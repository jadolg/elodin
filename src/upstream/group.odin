package upstream

import "core:mem"
import "core:sync"
import "core:time"
import "elodin:config"
import "elodin:logx"
import "elodin:pool"

/*
A set of upstreams plus the policy for choosing between them.

  Failover     ask each server in configured order until one answers
  Round_Robin  the same, but the starting position advances per query
  Race         ask every healthy server at once and take the first answer
*/
Group :: struct {
	servers:    []^Upstream,
	strategy:   config.Strategy,
	timeout:    time.Duration,
	attempts:   int,
	cursor:     u64,
	race_pool:  ^pool.Pool,
	allocator:  mem.Allocator,
}

make_group :: proc(
	cfg: config.Upstream_Config,
	race_pool: ^pool.Pool,
	allocator := context.allocator,
	// Whether plain upstreams are asked with a DNS cookie; see upstream/cookie.odin.
	cookies := false,
) -> (
	g: ^Group,
	err: Error,
) {
	g = new(Group, allocator)
	g.strategy = cfg.strategy
	g.timeout = cfg.timeout
	g.attempts = max(cfg.attempts, 1)
	g.race_pool = race_pool
	g.allocator = allocator

	servers := make([dynamic]^Upstream, 0, len(cfg.servers), allocator)
	for spec in cfg.servers {
		u, uerr := make_upstream(spec, cfg.max_idle, cfg.idle_timeout, allocator, cookies)
		if uerr != .None {
			logx.errorf("upstream %s: not usable (%v)", spec.name, uerr)
			continue
		}
		append(&servers, u)
	}
	if len(servers) == 0 {
		return nil, .Not_Resolved
	}
	g.servers = servers[:]
	return g, .None
}

destroy_group :: proc(g: ^Group) {
	if g == nil {
		return
	}
	for u in g.servers {
		destroy(u)
	}
	delete(g.servers, g.allocator)
	free(g, g.allocator)
}

/*
Resolve `query` through the group.

Returns the upstream response bytes, allocated from `allocator`, along with the
upstream that produced them for logging.
*/
resolve :: proc(
	g: ^Group,
	query: []u8,
	allocator := context.allocator,
) -> (
	response: []u8,
	winner: ^Upstream,
	err: Error,
) {
	switch g.strategy {
	case .Race:
		return resolve_race(g, query, allocator)
	case .Round_Robin:
		start := int(sync.atomic_add(&g.cursor, 1) % u64(len(g.servers)))
		return resolve_sequential(g, query, start, allocator)
	case .Failover:
		return resolve_sequential(g, query, 0, allocator)
	}
	return nil, nil, .IO_Error
}

@(private)
resolve_sequential :: proc(
	g: ^Group,
	query: []u8,
	start: int,
	allocator: mem.Allocator,
) -> (
	response: []u8,
	winner: ^Upstream,
	err: Error,
) {
	last_err := Error.Unhealthy

	for round in 0 ..< g.attempts {
		// The first pass skips upstreams in cooldown; a later pass takes them
		// anyway, so a total outage still gets one honest try per server.
		skip_unhealthy := round == 0
		for offset in 0 ..< len(g.servers) {
			u := g.servers[(start + offset) % len(g.servers)]
			if skip_unhealthy && !healthy(u) {
				continue
			}
			resp, xerr := exchange(u, query, g.timeout, allocator)
			if xerr == .None {
				return resp, u, .None
			}
			last_err = xerr
			logx.debugf("upstream %s failed: %v", u.spec.name, xerr)
		}
	}
	return nil, nil, last_err
}

/*
Racing state, shared between the caller and the workers it spawned.

Everything a worker touches is heap-allocated and reference counted. A worker
can outlive the caller — the caller gives up at the group timeout while a
worker sits in its own socket timeout — so nothing here may live in the
caller's per-request arena, including the query bytes and the response buffers.
The last reference to leave frees the block.
*/
@(private)
Race_State :: struct {
	mu:          sync.Mutex,
	sema:        sync.Sema,
	refs:        int,
	// Set once a winner is recorded; later arrivals discard their answers.
	done:        bool,
	outstanding: int,
	response:    []u8,
	winner:      ^Upstream,
	last_err:    Error,
	query:       []u8,
	timeout:     time.Duration,
	jobs:        []Race_Job,
}

@(private)
Race_Job :: struct {
	upstream: ^Upstream,
	state:    ^Race_State,
}

@(private)
race_state_release :: proc(st: ^Race_State) {
	sync.mutex_lock(&st.mu)
	st.refs -= 1
	should_free := st.refs == 0
	sync.mutex_unlock(&st.mu)
	if !should_free {
		return
	}
	if st.response != nil {
		delete(st.response)
	}
	delete(st.query)
	delete(st.jobs)
	free(st)
}

@(private)
race_worker :: proc(data: rawptr) {
	// A race-pool worker runs for the life of the process and `exchange` below
	// takes scratch space for every query it makes. Nothing else resets this
	// thread's arena, and the arena chains a new block rather than reusing the
	// old one, so without this it grows for as long as the server runs.
	defer free_all(context.temp_allocator)

	job := cast(^Race_Job)data
	st := job.state

	// Responses go on the heap: the caller's arena may already be gone.
	resp, err := exchange(job.upstream, st.query, st.timeout, context.allocator)

	sync.mutex_lock(&st.mu)
	won := false
	if err == .None && !st.done {
		st.done = true
		st.response = resp
		st.winner = job.upstream
		won = true
	} else if err != .None {
		st.last_err = err
	}
	st.outstanding -= 1
	last_one := st.outstanding == 0
	sync.mutex_unlock(&st.mu)

	if err == .None && !won {
		delete(resp)
	}
	if won || last_one {
		sync.sema_post(&st.sema)
	}
	race_state_release(st)
}

@(private)
resolve_race :: proc(
	g: ^Group,
	query: []u8,
	allocator: mem.Allocator,
) -> (
	response: []u8,
	winner: ^Upstream,
	err: Error,
) {
	candidates := make([dynamic]^Upstream, 0, len(g.servers), context.temp_allocator)
	for u in g.servers {
		if healthy(u) {
			append(&candidates, u)
		}
	}
	if len(candidates) == 0 {
		for u in g.servers {
			append(&candidates, u)
		}
	}
	if len(candidates) == 1 {
		resp, xerr := exchange(candidates[0], query, g.timeout, allocator)
		return resp, candidates[0], xerr
	}

	st := new(Race_State)
	st.refs = 1
	st.last_err = .Timeout
	st.timeout = g.timeout
	st.query = make([]u8, len(query))
	copy(st.query, query)
	st.jobs = make([]Race_Job, len(candidates))
	defer race_state_release(st)

	submitted := 0
	for u, i in candidates {
		st.jobs[i] = Race_Job {
			upstream = u,
			state    = st,
		}
		sync.mutex_lock(&st.mu)
		st.refs += 1
		st.outstanding += 1
		sync.mutex_unlock(&st.mu)

		if !pool.submit(g.race_pool, race_worker, &st.jobs[i]) {
			// The pool is shutting down; undo this leg's bookkeeping.
			sync.mutex_lock(&st.mu)
			st.refs -= 1
			st.outstanding -= 1
			sync.mutex_unlock(&st.mu)
			continue
		}
		submitted += 1
	}
	if submitted == 0 {
		return resolve_sequential(g, query, 0, allocator)
	}

	if !sync.sema_wait_with_timeout(&st.sema, g.timeout) {
		// Nobody answered in time. Workers still running will see `done` and
		// throw their answers away rather than writing into a dead frame.
		sync.mutex_lock(&st.mu)
		st.done = true
		sync.mutex_unlock(&st.mu)
		return nil, nil, .Timeout
	}

	sync.mutex_lock(&st.mu)
	defer sync.mutex_unlock(&st.mu)
	if st.response == nil {
		return nil, nil, st.last_err
	}
	// Hand the caller a copy in its own allocator; the shared buffer is freed
	// with the state once the last worker has let go of it.
	out := make([]u8, len(st.response), allocator)
	copy(out, st.response)
	return out, st.winner, .None
}

// Close idle connections that have been sitting around too long.
groom :: proc(g: ^Group) -> (closed: int) {
	for u in g.servers {
		closed += close_idle(u)
	}
	return
}
