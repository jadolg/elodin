package server

import "core:mem/virtual"
import "core:net"
import "core:reflect"
import "core:strings"
import "core:sync"
import "core:time"
import "elodin:brlock"
import "elodin:cache"
import "elodin:config"
import "elodin:dnssec"
import "elodin:logx"
import "elodin:loop"
import "elodin:upstream"

/*
Everything a request reads that a configuration reload can change, built from
one `config.Config` and read as one.

A request pins the generation that is current when it starts (`pin`) and reaches
all of this through `live` until it is done, so the upstreams it asks, the
policy it applies and the limits it is held to all come from the same
configuration however many reloads land while it runs. Reading `s.cfg` once
before a swap and once after would act on half of each: a rewrite found by index
in one table and read out of the other, say.

A `Server` built as a literal - which is every test - has no generations; it
holds one of these directly and `live` hands that back.
*/
Live :: struct {
	cfg:          ^config.Config,
	// The default upstream: everything that no route in `routes` claims, plus
	// every lookup the validator makes on its own account. See `routes.odin`.
	group:        ^upstream.Group,
	// The per-domain upstreams, in configuration order. Empty on a server that
	// forwards everything to one place.
	routes:       []Zone_Route,
	/*
	Which routed apexes the parent's group would not settle a `DS` for, and
	until when.

	Only the apex `DS` carve-out reads or writes it, and only to decide whether
	to spend a client's query on a parent that has just proved it cannot answer
	this question. `Apex_Memo` argues it in full; the zero value is no memory of
	anything, which is what a `Server` built as a literal wants.

	One per generation because the names in it are the routes' own strings,
	which live as long as the generation that owns the routes - this one, or a
	newer one they were handed to, which is released after it. A reload starts
	with no memory, which costs at most one cooldown's worth of queries to a
	parent that is still not settling.
	*/
	apex_memo:    Apex_Memo,
	// Nil when `cache.enabled` is off.
	answers:      ^cache.Cache,
	validator:    ^dnssec.Validator,
	/*
	The operator's own trust anchors, as parsed.

	Held here rather than left to the validator because the validator borrows
	them: with none configured it points at `dnssec.root_anchors`, which is
	static, so `destroy_validator` cannot free what it has and these would have
	nobody to release them. Empty when the built-in anchors are in use.
	*/
	anchors:      []dnssec.Trust_Anchor,
	// The zones of the operator's own trust anchors, root excluded, in canonical
	// form. An anchor here is a deliberate request to validate the zone it names,
	// which the locally-served bypass has to defer to; see `covered_by_local_anchor`.
	// The strings are the anchors' own; only the slice belongs to this field.
	anchor_zones: []string,
	cookies:      ^Cookie_Keeper,
	// Nil when rate limiting is off; `rate_check` takes that as "allow".
	limiter:      ^Rate_Limiter,
	/*
	The number the rules an answer is judged by before it is cached go by: which
	upstreams are asked, whether and against what it is validated, whether rebind
	protection reads it, and the lifetimes the cache gives it. It is part of every
	cache key (`cache.make_key`), so an answer stored under one number is never
	served under another.

	A reload that changes any of those moves it. Emptying the cache alone would
	not do: a request still running under the old rules stores its answer after
	the cache was emptied, and that answer - unvalidated, say, where the new
	configuration turned validation on - would then be served for its whole
	lifetime to clients the new rules were written for. Under the old number it
	is never found.
	*/
	policy:       u64,
}

/*
The parts of a `Live` a generation can own, which are the ones that have to be
released when nothing uses them any more.

A part whose section of the configuration a reload left alone is handed to the
new generation rather than rebuilt - the idle connections and client cookies of
the upstreams, the cached answers, the validator's zone keys, the cookie secret
every client holds a cookie under and the rate limiter's budgets all survive -
and with it the duty to release it.
*/
Part :: enum u8 {
	Upstreams,
	Validator,
	Cookies,
	Limiter,
	Answers,
}

Parts :: bit_set[Part]

Generation :: struct {
	using live: Live,
	// Where `cfg` points, for a generation a reload loaded.
	config:     config.Config,
	/*
	What `config`'s strings live in, for a generation a reload loaded.

	Nil for the first generation, whose configuration the caller loaded and keeps
	until the process ends. That one has to: the listeners, the metrics endpoint
	and the profile signer hold its strings for as long as they run, and none of
	them is rebuilt by a reload.
	*/
	arena:      ^virtual.Arena,
	/*
	Requests that pinned this generation and have not let go of it yet, counted
	on the stripe of the thread that pinned: one count on one line would be
	written by every loop on every request. Only the sum means anything; see
	`reap_generations`.
	*/
	refs:       [brlock.STRIPES]brlock.Count,
	owns:       Parts,
	// The next newer retired generation, once this one is retired.
	next:       ^Generation,
}

Generations :: struct {
	// Read-locked by `pin` while it takes a reference, write-locked by the swap.
	// Striped for the reason `refs` is.
	lock:    brlock.Lock,
	current: ^Generation,
	// The configuration the process started with, which is what every
	// restart-only key is held to.
	boot:    ^config.Config,
	// Swapped out and not yet released, oldest first; see `reap_generations`.
	retired: ^Generation,
}

// A loop thread per stripe, or two loops share one and contend on it.
#assert(brlock.STRIPES >= config.MAX_UDP_READERS)

@(private)
Pin :: struct {
	server: ^Server,
	gen:    ^Generation,
	depth:  int,
	// Which of `gen.refs` this pin counted on, which `unpin` takes back.
	stripe: int,
}

/*
The generation this fiber's request is running under.

Per request rather than passed along, because the request reaches its
configuration through some two hundred reads in a few dozen procedures that all
take the `Server` and nothing else; threading a second argument through every
one of them would be the same guarantee bought with a much larger change. What
makes it safe is that a request runs start to finish on one fiber, which keeps
its own copy of this across every wait (`register_pinned`): the work it hands to
another fiber - a racer, a refresh - is either given everything it needs up
front, or pins for itself when it starts.
*/
@(private, thread_local)
pinned: Pin

/*
Per fiber on a loop thread, where many requests take turns and each holds its
own generation across the waits in it: the pin is saved when the request's fiber
parks and put back when it runs. See `loop.register_local`.
*/
@(private, init)
register_pinned :: proc "contextless" () {
	context = {}
	loop.register_local(proc "contextless" () -> rawptr {return &pinned}, size_of(pinned))
}

/*
Take a reference to the current generation for the rest of this request.

Nests: an inner `pin` of the server already pinned by this request keeps the outer
one's generation, so a procedure can pin without knowing whether its caller did.
A server with no generations - one built as a literal - is pinned to nothing,
and `live` hands back its own `Live`.
*/
pin :: proc(s: ^Server) {
	if pinned.server == s {
		pinned.depth += 1
		return
	}
	assert(pinned.server == nil, "a request pins one server at a time")
	stripe := brlock.read_lock(&s.gens.lock)
	g := s.gens.current
	if g != nil {
		sync.atomic_add(&g.refs[stripe].n, 1)
	}
	brlock.read_unlock(&s.gens.lock, stripe)
	pinned = Pin{s, g, 1, stripe}
}

unpin :: proc(s: ^Server) {
	assert(pinned.server == s, "unpinning a server this request has not pinned")
	pinned.depth -= 1
	if pinned.depth > 0 {
		return
	}
	if pinned.gen != nil {
		sync.atomic_sub(&pinned.gen.refs[pinned.stripe].n, 1)
	}
	pinned = {}
}

// `pin` for the rest of the enclosing scope.
@(deferred_in = unpin)
pin_scope :: proc(s: ^Server) {
	pin(s)
}

/*
What this request reads its configuration and everything built from it through.

A server with generations must be pinned first. Reading one unpinned would race
a reload that frees what was read, which is why it stops the process rather
than guessing: every fiber that serves anything pins on the way in, and a path
that does not is a bug the test suites are there to find.
*/
live :: proc(s: ^Server) -> ^Live {
	if pinned.server == s && pinned.gen != nil {
		return &pinned.gen.live
	}
	assert(sync.atomic_load(&s.gens.current) == nil, "configuration read outside a pinned request")
	return &s.live
}

/*
The configuration the process started with, which is where every key a reload
cannot change is read: the listeners, the metrics endpoint, the loop count and
the connection table (see `keep_restart_only`). It never changes and lives as
long as the server, so it needs no pin and its strings can be kept.
*/
startup_config :: proc(s: ^Server) -> ^config.Config {
	if s.gens.boot != nil {
		return s.gens.boot
	}
	return live(s).cfg
}

/*
The configuration in effect, for the maintenance thread.

That thread is the only one that swaps or releases a generation, so the current
one cannot be released under it and it reads without pinning. Any other thread
pins.
*/
live_config :: proc(s: ^Server) -> ^config.Config {
	if g := sync.atomic_load(&s.gens.current); g != nil {
		return g.cfg
	}
	return live(s).cfg
}

/*
`server.client_timeout`, for a connection's fiber between requests.

Pinned for the one reading and let go at once: the wait it bounds is the
client's to stretch, and a connection holding a generation across it would hold
up the release of every one after it.
*/
client_timeout :: proc(s: ^Server) -> time.Duration {
	pin_scope(s)
	return live(s).cfg.server.client_timeout
}

// Whether a query on a connection is within its prefix's budget; see
// `stream_rate_check`. Pinned for the check alone, as `client_timeout` is.
stream_admits :: proc(s: ^Server, peer: net.Endpoint) -> bool {
	pin_scope(s)
	return stream_rate_check(live(s).limiter, peer, time.tick_now())
}

/*
Whether a connection's peer is still inside `server.allow_from`, asked before
each query on it. The accept loop checks the list once, and a reload that
narrows it has to cut off the connections already held as well: a client kept
on one would otherwise be answered for as long as it kept asking.

Logged at debug rather than through `report_refusal`, which releases the
calling fiber's scratch - one a connection's fiber is still reading its
request out of here.
*/
stream_source_allowed :: proc(s: ^Server, peer: net.Endpoint, proto: Protocol) -> bool {
	pin_scope(s)
	if config.source_allowed(live(s).cfg.server.allow_from, peer.address) {
		return true
	}
	sync.atomic_add(&s.stats.refused, 1)
	// Guarded, as `report_once` is: the address is formatted before `debugf`
	// could decline it, and how often this runs is the refused client's choice.
	if logx.enabled(.Debug) {
		logx.debugf(
			"%s: refusing a query from %s, which server.allow_from no longer admits",
			proto_name(proto),
			net.endpoint_to_string(peer, context.temp_allocator),
		)
	}
	return false
}

// Whether two values of one type differ anywhere, slices and strings included.
@(private)
differs :: proc(a, b: $T) -> bool {
	a, b := a, b
	return !reflect.equal(a, b, including_indirect_array_recursion = true)
}

cache_options :: proc(c: config.Cache_Config) -> cache.Options {
	return cache.Options {
		max_entries = c.max_entries,
		max_bytes = c.max_bytes,
		min_ttl = c.min_ttl,
		max_ttl = c.max_ttl,
		negative_ttl = c.negative_ttl,
		serve_stale = c.serve_stale,
		prefetch = c.prefetch,
		prefetch_min_ttl = c.prefetch_min_ttl,
	}
}

/*
What one pipelined upstream connection may carry under `cfg`.

A race's losers run on after their query has gone and its place in `max_pending`
has been taken by another, so where any group races, its racers - up to the
budget `build_live` sets, `max_pending` legs per member of the widest racing
group - may be asking one upstream beside the queries that are: a member slow to
answer is the one whose legs every race leaves behind.
*/
@(private)
connection_outstanding :: proc(cfg: ^config.Config) -> int {
	in_flight := cfg.server.max_pending * (1 + race_width(cfg.upstream))
	return upstream.pipeline_outstanding(in_flight, cfg.server.max_connections)
}

/*
The default group and one per `upstream.zones` entry.

A route whose servers are all unusable fails the whole build rather than being
dropped. The names it claims are the ones an operator added the route to keep
resolving, and a server that quietly carried on without it would send them to
the public upstream instead - which is both the leak the route was written to
stop and the answer least likely to be noticed, since the public resolver
replies rather than failing.
*/
@(private)
build_upstreams :: proc(s: ^Server, l: ^Live) -> bool {
	cfg := l.cfg
	outstanding := connection_outstanding(cfg)
	// The budget's figure is set by `build_live` once the whole generation is built.
	group, gerr := upstream.make_group(
		cfg.upstream,
		cookies = cfg.cookies.upstream,
		outstanding = outstanding,
		racers = &s.racers,
	)
	if gerr != .None {
		logx.errorf("no usable upstream servers")
		return false
	}
	routes := make([]Zone_Route, len(cfg.upstream.zones))
	for zone, i in cfg.upstream.zones {
		zg, zerr := upstream.make_group(
			zone.upstream,
			cookies = cfg.cookies.upstream,
			outstanding = outstanding,
			racers = &s.racers,
		)
		if zerr != .None {
			logx.errorf("upstream.zones[%d]: no usable servers for %s", i, zone.domains[0])
			// The routes built so far and the slice under them, which this
			// sub-slice starts at and so releases.
			l.group, l.routes = group, routes[:i]
			release_parts(l, {.Upstreams})
			return false
		}
		// Copied for the reason `upstream.make_upstream` copies its spec: the
		// routes can be handed to the next configuration, and the apex memory
		// keeps these strings for as long as they are in use.
		domains := make([]string, len(zone.domains))
		for d, j in zone.domains {
			domains[j] = strings.clone(d)
		}
		routes[i] = Zone_Route {
			domains = domains,
			group   = zg,
		}
		logx.infof("routing %s to its own upstream", strings.join(zone.domains, ", ", context.temp_allocator))
	}
	l.group = group
	l.routes = routes
	return true
}

@(private)
release_parts :: proc(l: ^Live, parts: Parts) {
	if .Upstreams in parts {
		for route in l.routes {
			upstream.destroy_group(route.group)
			for d in route.domains {
				delete(d)
			}
			delete(route.domains)
		}
		delete(l.routes)
		upstream.destroy_group(l.group)
		l.group, l.routes = nil, nil
	}
	if .Validator in parts {
		stop_validator(l)
	}
	if .Cookies in parts {
		stop_cookies(l)
	}
	if .Limiter in parts {
		stop_rate_limiter(l)
	}
	if .Answers in parts {
		cache.destroy(l.answers)
		l.answers = nil
	}
}

/*
Build what `l.cfg` describes into `l`, taking from `prev` every part whose
section of the configuration has not changed.

`built` is what this call made, and is the new generation's to release;
`carried` is what it took from `prev`, which is not, until the swap hands it
over. A part that cannot be
built fails the whole call, with everything it had built released and `prev`
untouched - a reload that half-applies is worse than one that does not happen.

What can fail comes first, so nothing shared is touched by a call that then
fails: the cache, taken over and resized rather than rebuilt, is resized by the
caller once the build has succeeded.
*/
build_live :: proc(s: ^Server, l: ^Live, prev: ^Live) -> (built, carried: Parts, ok: bool) {
	cfg := l.cfg
	defer if !ok {
		release_parts(l, built)
		built, carried = {}, {}
	}

	if prev == nil ||
	   differs(prev.cfg.upstream, cfg.upstream) ||
	   prev.cfg.cookies.upstream != cfg.cookies.upstream {
		// The hostnames too, before the new groups resolve theirs: an address
		// the old bootstrap servers gave is otherwise dialled for up to
		// `BOOTSTRAP_TTL` after a reload that replaced them.
		if prev != nil && upstreams_asked_changed(prev.cfg.upstream, cfg.upstream) {
			upstream.bootstrap_forget()
		}
		if !build_upstreams(s, l) {
			return
		}
		built += {.Upstreams}
	} else {
		l.group, l.routes = prev.group, prev.routes
		carried += {.Upstreams}
	}

	if cfg.dnssec.enabled {
		if prev == nil || prev.validator == nil || differs(prev.cfg.dnssec, cfg.dnssec) {
			if !start_validator(s, l) {
				return
			}
			built += {.Validator}
		} else {
			l.validator, l.anchors, l.anchor_zones = prev.validator, prev.anchors, prev.anchor_zones
			carried += {.Validator}
		}
	}

	if cfg.cookies.enabled {
		if prev == nil ||
		   prev.cookies == nil ||
		   prev.cfg.cookies.require != cfg.cookies.require ||
		   prev.cfg.cookies.secret != cfg.cookies.secret {
			// The same secret, configured or drawn at startup, is kept across a
			// reload that only changes `require`: every client holds a cookie
			// under it, and a new one would cost each of them a round trip.
			reuse :=
				prev.cookies if prev != nil && prev.cookies != nil && prev.cfg.cookies.secret == cfg.cookies.secret else nil
			if !start_cookies(l, reuse) {
				return
			}
			built += {.Cookies}
		} else {
			l.cookies = prev.cookies
			carried += {.Cookies}
		}
	}

	if cfg.server.rate_limit.enabled {
		/*
		Rebuilt when its figures change, and with it every prefix's budget: the
		buckets name their tier by an index into the figures, which a changed list
		of overrides renumbers. What that costs is one full bucket per prefix at
		the moment of the reload, an operator's act and not a client's. Left
		alone otherwise, so a reload of anything else hands nobody a fresh one.
		*/
		if prev == nil || prev.limiter == nil || differs(prev.cfg.server.rate_limit, cfg.server.rate_limit) {
			if !start_rate_limiter(l) {
				return
			}
			built += {.Limiter}
		} else {
			l.limiter = prev.limiter
			carried += {.Limiter}
			// Kept, but the lines describing it name the cookie rescue pool or
			// not, so they are said again when that changes.
			if prev.cfg.cookies.enabled != cfg.cookies.enabled {
				report_rate_limiter(l)
			}
		}
	}

	if cfg.cache.enabled {
		if prev == nil || prev.answers == nil {
			l.answers = cache.make_cache(cache_options(cfg.cache))
			built += {.Answers}
		} else {
			l.answers = prev.answers
			carried += {.Answers}
		}
	}

	if prev != nil {
		l.policy = prev.policy
		if policy_changed(prev.cfg, cfg) {
			l.policy += 1
		}
	}
	/*
	Every race leg is counted, while its query waits and after it has gone, so
	the figure is every query in flight racing the widest group at once: `max_pending`
	legs per member. That is what the descriptor estimate allows them
	(`Descriptor_Demand.racers`), and losers left behind by queries that have
	moved on take room a new race then does not get. One budget for every group,
	so routes do not each get another. Set here, where nothing can fail any more,
	so a reload refused above leaves it at the figure in effect.
	*/
	sync.atomic_store(&s.racers.limit, cfg.server.max_pending * max(race_width(cfg.upstream), 1))
	/*
	Groups kept from the last generation keep their connections, health and
	learned ceilings; what each connection may carry follows `max_pending`, set
	here for the same reason as the budget above.
	*/
	if .Upstreams in carried {
		outstanding := connection_outstanding(cfg)
		upstream.set_max_outstanding(l.group, outstanding)
		for r in l.routes {
			upstream.set_max_outstanding(r.group, outstanding)
		}
	}
	return built, carried, true
}

/*
Whether the rules an answer is judged by before it is stored have changed; see
`Live.policy`.

Which upstreams are asked - their addresses, how they are dialled and whether
their certificates are checked, the bootstrap that finds them, and the routes -
because an answer from one the file no longer names, or for a zone now routed
somewhere else, is not what the new configuration would have asked for. Not how
long they are waited on or in what order, which change nothing about an answer
once it has arrived. What a DNSSEC verdict turns on (`dnssec_verdicts_changed`),
because validation runs before the answer is stored and not when it is served;
`rebind`, for the same reason. And the lifetimes the cache stamps on an entry when it stores it.

Not the blocking rules, which the filter engine's own generation already covers
(see `rules_generation`), and not the rewrites, the reserved names or the
access list, which are all answered ahead of the cache. Not `dnssec` or `rebind`
keys edited while that feature is off before and after, which judged nothing
then and judge nothing now. Each flush is a cold cache for every client, so a
reload that only retunes a timeout does not pay for one.
*/
@(private)
policy_changed :: proc(prev, cfg: ^config.Config) -> bool {
	return(
		upstreams_asked_changed(prev.upstream, cfg.upstream) ||
		dnssec_verdicts_changed(prev.dnssec, cfg.dnssec) ||
		((prev.rebind.enabled || cfg.rebind.enabled) && differs(prev.rebind, cfg.rebind)) ||
		prev.cache.min_ttl != cfg.cache.min_ttl ||
		prev.cache.max_ttl != cfg.cache.max_ttl ||
		prev.cache.negative_ttl != cfg.cache.negative_ttl \
	)
}

/*
The keys a DNSSEC verdict turns on: whether there is one, the anchors it starts
from, and the NSEC3 iteration ceiling past which a zone is served insecure. Not
the chain-walk bounds or the zone-key cache size, which decide how much work
validation may do at once and how much it remembers, and nothing about what it
concludes. The validator is rebuilt for those too; only the answers stay.

Read off the type the other way round, as `rules_changed` is, so a key added to
the section later moves the policy until it is listed here as one that does
not. With validation off on both sides, nothing in the section reached an
answer.
*/
@(private)
dnssec_verdicts_changed :: proc(a, b: config.Dnssec_Config) -> bool {
	if !a.enabled && !b.enabled {
		return false
	}
	x := a
	x.max_chain_walks, x.max_connection_walks, x.max_cached_zones = b.max_chain_walks, b.max_connection_walks, b.max_cached_zones
	return differs(x, b)
}

@(private)
upstreams_asked_changed :: proc(a, b: config.Upstream_Config) -> bool {
	if servers_asked_changed(a.servers, b.servers) || differs(a.bootstrap, b.bootstrap) || len(a.zones) != len(b.zones) {
		return true
	}
	for zone, i in a.zones {
		other := b.zones[i]
		if differs(zone.domains, other.domains) ||
		   servers_asked_changed(zone.upstream.servers, other.upstream.servers) ||
		   differs(zone.upstream.bootstrap, other.upstream.bootstrap) {
			return true
		}
	}
	return false
}

// Everything but the name a server is logged and counted under, which changes
// nothing about the answers it gives.
@(private)
servers_asked_changed :: proc(a, b: []config.Upstream_Spec) -> bool {
	if len(a) != len(b) {
		return true
	}
	for x, i in a {
		x, y := x, b[i]
		x.name, x.named = "", false
		y.name, y.named = "", false
		if differs(x, y) {
			return true
		}
	}
	return false
}

/*
Put the first generation into effect, from the configuration the process was
started with. The caller keeps `cfg` for as long as the server runs.
*/
boot_generation :: proc(s: ^Server, cfg: ^config.Config) -> bool {
	g := new(Generation)
	g.cfg = cfg
	built, _, ok := build_live(s, &g.live, nil)
	if !ok {
		free(g)
		return false
	}
	g.owns = built
	s.gens.boot = cfg
	sync.atomic_store(&s.gens.current, g)
	return true
}

/*
Make `g` current and retire the generation it replaces.

`carried` is what `g` took from the one it replaces rather than building, and
the duty to release it goes with it. Nothing older can still be using any of it
once the one it replaces is released, because generations are released oldest
first (`reap_generations`).
*/
@(private)
swap_generation :: proc(s: ^Server, g: ^Generation, carried: Parts) {
	brlock.write_lock(&s.gens.lock)
	old := s.gens.current
	sync.atomic_store(&s.gens.current, g)
	brlock.write_unlock(&s.gens.lock)

	g.owns += old.owns & carried
	old.owns -= carried

	tail := &s.gens.retired
	for tail^ != nil {
		tail = &tail^.next
	}
	tail^ = old
}

/*
Release every retired generation nothing is using any more, oldest first.

Oldest first, and stopping at the first one still in use: a part is handed from
one generation to the next, so a newer generation can own something an older one
is still reading, and releasing it first would free that under the older one's
requests.

In use means a request still pinned to it, or a racer still asking one of
its upstreams - those outlive the request that started them. No new pin can
reach a retired generation, so a count that reads zero here stays zero: each
stripe only falls, and on the stripe it was raised on, so one read as zero is
still zero when the next is read.
*/
reap_generations :: proc(s: ^Server) -> (released: int) {
	for s.gens.retired != nil {
		g := s.gens.retired
		if brlock.total(g.refs[:]) > 0 || generation_racing(g) {
			break
		}
		s.gens.retired = g.next
		destroy_generation(g)
		released += 1
	}
	/*
	What is left is held by a request or a racer still running, which may
	go on for a while. The idle connections of the groups those generations own
	are closed now rather than then: no new request can reach a retired group,
	so they are only sockets held open to servers the file may no longer name.
	A connection in use is not idle and is left to finish.
	*/
	for g := s.gens.retired; g != nil; g = g.next {
		if .Upstreams not_in g.owns {
			continue
		}
		upstream.groom(g.group, all = true)
		for route in g.routes {
			upstream.groom(route.group, all = true)
		}
	}
	return
}

@(private)
generation_racing :: proc(g: ^Generation) -> bool {
	if .Upstreams not_in g.owns {
		return false
	}
	if upstream.busy(g.group) {
		return true
	}
	for route in g.routes {
		if upstream.busy(route.group) {
			return true
		}
	}
	return false
}

@(private)
destroy_generation :: proc(g: ^Generation) {
	release_parts(&g.live, g.owns)
	if g.arena != nil {
		virtual.arena_destroy(g.arena)
		free(g.arena)
	}
	free(g)
}

/*
Release every generation, current and retired, at shutdown.

Only once nothing can be using any of them: the listeners are stopped and both
pools drained.
*/
destroy_generations :: proc(s: ^Server) {
	for s.gens.retired != nil {
		g := s.gens.retired
		s.gens.retired = g.next
		destroy_generation(g)
	}
	if s.gens.current != nil {
		destroy_generation(s.gens.current)
		s.gens.current = nil
	}
}
