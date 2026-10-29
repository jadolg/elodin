package server

import "core:sync"
import "core:time"
import "elodin:loop"

// Stamped at build time from the git tag; see ELODIN_VERSION in mise.toml. A
// build that bypasses mise reports "dev" rather than claiming a release number.
VERSION :: #config(ELODIN_VERSION, "dev")

/*
Bookkeeping for the fibers that serve connections, and for the listeners' own.

TCP, DoT and DoH connections are long-lived and mostly idle, so each gets a
fiber of its own on one of the server's loops: one that waits for its client
parks, and costs its stack and its buffers rather than a thread. The table is
what `server.max_connections` and its per-prefix share are counted against, and
what shutdown waits on. A connection takes its entry out itself as its fiber
returns.
*/
Conn_Manager :: struct {
	mu:           sync.Mutex,
	entries:      [dynamic]^Conn_Entry,
	limit:        int,
	/*
	The most of `limit` any one client prefix may hold, or 0 for no such cap.

	`limit` on its own is a budget with no share-out, and nothing else in this
	server bounds how long a client keeps what it was given: the rate limiter
	charges opening a connection and charges the queries asked over it, both of
	which are rates a client inside its budget goes on paying while holding every
	connection it opened. So without this one prefix may hold every slot and lock
	everybody else out.

	Occupancy against arrival, in other words - two bounds that need each other.
	A share alone does not bound arrivals: a flood that holds each connection for
	the length of a handshake never reaches a share of 256 out of 512, which is
	measured in `bench/results/2026-09-03-handshake-floods.md`. An arrival budget
	alone does not bound occupancy: a client that opens connections slowly and
	never closes them fills the table inside any rate.

	Kept per /24 and /64 rather than per address, because that is the granularity
	an attacker picks addresses within, and the granularity the limiter's budgets
	are already kept at. See `client_prefix`.
	*/
	prefix_limit: int,
	// Accept and read loops live here too, but must not eat into the limit the
	// operator set for client connections. The limit is `len(entries) -
	// permanent`, adjusted as either kind leaves.
	permanent:    int,
	/*
	Set by `conn_manager_shutdown`, under `mu`, before it waits on the table.

	The accept loops read `stop` before they wait in an accept, not after it
	returns, so a connection accepted as shutdown begins still asks for a
	fiber. Refused here, in the same critical section that would otherwise add
	it, because no check outside the lock can be made atomic with the spawn: a
	fiber started once the shutdown has found the table empty lands in one
	nothing waits on again, and outlives the `Stream_Context` that
	`destroy_listeners` frees.
	*/
	stopped:      bool,
}

/*
One connection or listener loop in the table. Allocated by `conn_spawn`, freed by
the fiber it describes as it leaves - or by `conn_spawn` itself, when the fiber
never started.
*/
@(private)
Conn_Entry :: struct {
	cm:        ^Conn_Manager,
	fn:        proc(data: rawptr),
	data:      rawptr,
	// For cancelling a listener loop at shutdown; zero off a loop.
	handle:    loop.Handle,
	permanent: bool,
	// Which client's share this fiber is occupying. Zero for the permanent
	// loops, which are nobody's client.
	prefix:    Client_Prefix,
	// Where it sits in `entries`, so leaving is a swap rather than a walk of the
	// table under the lock every loop's connections take to leave.
	index:     int,
}

conn_manager_init :: proc(cm: ^Conn_Manager, limit: int, prefix_limit: int) {
	cm.limit = max(limit, 1)
	cm.prefix_limit = max(prefix_limit, 0)
	cm.entries = make([dynamic]^Conn_Entry, 0, 16)
}

/*
Why a spawn did not happen.

`Stopped` is the manager having been shut down, which is no refusal an operator
can act on: the server is exiting, and the caller drops the connection without
counting or reporting it.

Three other things stop one, and they do not ask for the same response from an
operator. `Limit_Reached` is `server.max_connections` doing its job, and raising
it is the fix. `Prefix_Limit_Reached` is one client's share of that table being
full while the table itself is not, so raising `max_connections` would only hand
the same client more; `server.max_connections_per_prefix` is the figure that
decides it. `Spawn_Failed` is the OS refusing the memory for a fiber's stack -
an address-space or cgroup memory limit - and it can happen far below either
limit, where raising anything cannot help and the number in the log would send
somebody the wrong way.
*/
Spawn_Result :: enum u8 {
	Started,
	Limit_Reached,
	Prefix_Limit_Reached,
	Spawn_Failed,
	Stopped,
}

/*
Start `fn` on a fiber of `on`, unless a connection limit has been reached.

Anything but `.Started` means the caller should refuse the connection. `prefix`
is the client the connection belongs to, which is what its share of the table is
counted against; the zero value is a connection that is nobody's, and is not
counted against a share. Pass `counted = false` for the server's own listener
loops, which run for the process's lifetime and are not client connections.

A nil loop is the calling fiber's own, or a thread of its own off a loop - which
is the tests, driving the table from threads.
*/
conn_spawn :: proc(
	cm: ^Conn_Manager,
	data: rawptr,
	fn: proc(data: rawptr),
	prefix := Client_Prefix{},
	counted := true,
	on: ^loop.Loop = nil,
) -> Spawn_Result {
	sync.mutex_lock(&cm.mu)
	defer sync.mutex_unlock(&cm.mu)

	if cm.stopped {
		return .Stopped
	}
	if counted {
		if len(cm.entries) - cm.permanent >= cm.limit {
			return .Limit_Reached
		}
		/*
		The client's share, asked after the table's total.

		Both can be true at once - a full table whose last slot this prefix was
		not entitled to either - and the total is the one to report there. It is
		a fact about the server rather than about the client, and it is what
		would have to be raised before the next connection from anywhere could
		be served.
		*/
		if cm.prefix_limit > 0 && prefix.n != 0 && prefix_conns_locked(cm, prefix) >= cm.prefix_limit {
			return .Prefix_Limit_Reached
		}
	}
	e := new(Conn_Entry)
	e^ = Conn_Entry {
		cm        = cm,
		fn        = fn,
		data      = data,
		permanent = !counted,
		prefix    = prefix,
	}
	/*
	Listed before it can run, under the lock it takes to leave, so a fiber that
	finishes at once still finds itself here to remove.
	*/
	e.index = len(cm.entries)
	append(&cm.entries, e)
	if !counted {
		cm.permanent += 1
	}
	started: bool
	if on != nil {
		e.handle, started = loop.spawn(on, conn_entry_run, e)
	} else {
		started = loop.go(conn_entry_run, e)
	}
	if !started {
		conn_entry_remove_locked(cm, e)
		free(e)
		return .Spawn_Failed
	}
	return .Started
}

@(private)
conn_entry_run :: proc(data: rawptr) {
	e := (^Conn_Entry)(data)
	e.fn(e.data)
	cm := e.cm
	sync.mutex_lock(&cm.mu)
	conn_entry_remove_locked(cm, e)
	sync.mutex_unlock(&cm.mu)
	free(e)
}

@(private)
conn_entry_remove_locked :: proc(cm: ^Conn_Manager, e: ^Conn_Entry) {
	i := e.index
	assert(i < len(cm.entries) && cm.entries[i] == e, "a connection entry out of place in its table")
	last := cm.entries[len(cm.entries) - 1]
	cm.entries[i] = last
	last.index = i
	pop(&cm.entries)
	if e.permanent {
		cm.permanent -= 1
	}
}

/*
How many slots `prefix` is holding, counted off the table itself.

Walked rather than kept in a table beside the list, so that a count taken from
the connections cannot drift from the connections, which a counter incremented on
accept and decremented at the far end of a connection handler can. There is
nothing to release: a connection that ends gives up its share in the same step
that gives up its slot, and one that is refused never took either. The table is
`max_connections` long, so the walk is a comparison of nine bytes for each of at
most that many entries, once per accepted connection.
*/
@(private)
prefix_conns_locked :: proc(cm: ^Conn_Manager, prefix: Client_Prefix) -> int {
	n := 0
	for entry in cm.entries {
		if !entry.permanent && entry.prefix == prefix {
			n += 1
		}
	}
	return n
}

active_connections :: proc(cm: ^Conn_Manager) -> int {
	sync.mutex_lock(&cm.mu)
	defer sync.mutex_unlock(&cm.mu)
	return len(cm.entries) - cm.permanent
}

/*
Cancel the listener loops and wait for them to go, so their sockets can be
closed with nothing waiting on them: a descriptor closed under a waiting fiber
is a number the next socket may be given while the fiber still holds it.

Off a loop - the tests - there is nothing to cancel, and the loops are left to
notice `stop` within one `LISTENER_POLL`, which this waits for the same way.
*/
conn_manager_stop_permanent :: proc(cm: ^Conn_Manager) {
	sync.mutex_lock(&cm.mu)
	for entry in cm.entries {
		if entry.permanent {
			loop.cancel(entry.handle)
		}
	}
	sync.mutex_unlock(&cm.mu)
	for {
		sync.mutex_lock(&cm.mu)
		left := cm.permanent
		sync.mutex_unlock(&cm.mu)
		if left == 0 {
			return
		}
		time.sleep(SHUTDOWN_POLL)
	}
}

/*
Wait for every connection fiber to finish, and refuse any spawn after it.
Callers set `stop` and stop the listener loops first; a client connection ends
when its client closes it or at `server.client_timeout`.

The table shrinks as connections end, whichever order they finish in, so
`active_connections` counts down the connections still open - which is what
`stop_metrics` keeps the endpoint open to show.
*/
conn_manager_shutdown :: proc(cm: ^Conn_Manager) {
	sync.mutex_lock(&cm.mu)
	cm.stopped = true
	sync.mutex_unlock(&cm.mu)

	for {
		sync.mutex_lock(&cm.mu)
		if len(cm.entries) == 0 {
			delete(cm.entries)
			cm.entries = nil
			sync.mutex_unlock(&cm.mu)
			return
		}
		sync.mutex_unlock(&cm.mu)
		// ponytail: polled, so shutdown ends up to one interval after the last
		// connection does; a cond broadcast at the last exit if it matters.
		time.sleep(SHUTDOWN_POLL)
	}
}

@(private)
SHUTDOWN_POLL :: 10 * time.Millisecond
