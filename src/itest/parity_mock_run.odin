package itest

import "core:fmt"
import "core:strings"
import "core:time"

/*
The mock mode, one scenario at a time.

Every scenario is a case of its own, so a run under `--parity-scenario all`
says which configuration a divergence came out of rather than only that one
did. See parity_scenario.odin for what the scenarios are and why.
*/

run_parity_mock :: proc(r: ^Runner, opts: Parity_Options) {
	scenarios := parity_scenarios_named(opts.scenario, false)
	if scenarios == nil {
		start_case(r, "parity scenario")
		fail(r, "no synthetic-upstream scenario is called %q", opts.scenario)
		end_case(r)
		return
	}
	for s in scenarios {
		run_parity_scenario(r, opts, s)
	}
}

// Everything one query of a scenario needs, gathered so the steps below take
// one argument rather than eight.
@(private = "file")
Parity_Mock_Run :: struct {
	r:      ^Runner,
	srv:    ^Server,
	ups:    ^Parity_Upstreams,
	s:      Parity_Scenario,
	opts:   Parity_Options,
	stats:  ^Parity_Stats,
	// What the upstream answered each question with, for the answers the
	// cache serves without asking it again. Only filled with the cache on.
	cached: map[string]Parity_Cached,
	// How many references each upstream was, for the checks a strategy makes.
	served: []int,
}

@(private = "file")
run_parity_scenario :: proc(r: ^Runner, opts: Parity_Options, s: Parity_Scenario) {
	// Heap, not the arena: `start_case` keeps the pointer and `fail` reads it
	// back on every divergence, by which time the loop below has reset the temp
	// allocator many times over. Freed after `end_case`, which defers run in
	// reverse order.
	title := fmt.aprintf("parity: %s - %s (seed %d)", s.name, s.levers, opts.seed)
	defer delete(title)
	tls := r.cert_file != ""
	if parity_needs_tls(s) && !tls {
		skip_case(r, title, "no certificate for the tls upstream")
		return
	}
	start_case(r, title)
	defer end_case(r)

	udp_port := next_port(r)
	dot_port := next_port(r)
	doh_port := next_port(r)

	ups, ups_ok := parity_upstreams_start(r, s)
	defer parity_upstreams_stop(&ups)
	if !ups_ok {
		return
	}

	cfg := parity_scenario_config(r, s, udp_port, dot_port, doh_port, tls, Parity_Endpoints{ports = ups.ports[:]})
	srv, ok := start_server(
		r,
		Server_Options {
			config = cfg,
			udp_port = udp_port,
			tcp_port = udp_port,
			dot_port = tls ? dot_port : 0,
			doh_port = tls ? doh_port : 0,
		},
	)
	if !ok {
		return
	}
	defer stop_server(&srv)

	transports := parity_transports(tls)
	defer delete(transports)
	g := pg_make(opts.seed, s.blocking ? PARITY_BLOCKING_POOL : PARITY_POOL, transports[:])
	stats := parity_stats_make()
	defer parity_stats_destroy(&stats)

	run := Parity_Mock_Run {
		r      = r,
		srv    = &srv,
		ups    = &ups,
		s      = s,
		opts   = opts,
		stats  = &stats,
		cached = make(map[string]Parity_Cached),
		served = make([]int, len(s.kinds)),
	}
	defer parity_cache_destroy(&run.cached)
	defer delete(run.served)

	for i in 0 ..< opts.runs {
		parity_one_mock(&run, &g, i)
		// The generator allocates a query and the comparator a page of strings
		// per iteration; without this a long run grows without bound.
		free_all(context.temp_allocator)
	}

	parity_strategy_check(&run)
	parity_report(r, opts, stats)
}

/*
The transports a run's generator picks from.

The generator holds this for the whole run, so it cannot come from the temp
allocator: the loop resets that arena after every query, and a slice into it
reads reclaimed memory from the second query on. What that looked like was
every query going out over UDP while the run reported itself as covering four
transports.
*/
parity_transports :: proc(tls: bool) -> [dynamic]Parity_Transport {
	transports := make([dynamic]Parity_Transport, 0, len(Parity_Transport), context.allocator)
	append(&transports, Parity_Transport.UDP, Parity_Transport.TCP)
	if tls {
		append(&transports, Parity_Transport.DoT, Parity_Transport.DoH, Parity_Transport.DoH_GET, Parity_Transport.DoH2)
	}
	return transports
}

@(private = "file")
parity_one_mock :: proc(run: ^Parity_Mock_Run, g: ^Parity_Gen, index: int) {
	q := pg_query(g)
	if run.s.cookies == .Required && q.transport == .UDP && !q.local && parity_sent_cookie(q) != nil {
		shown, ok := parity_cookie_handshake(run, q)
		if !ok {
			return
		}
		q = shown
	}
	parity_settle(run, q, index)
	/*
	Asked again with the cache on, which is what makes a cached answer part of
	the run rather than an accident of which names the generator repeats. The
	second ask is served from the entry the first one filled, or forwarded
	again where there is none - a ttl of zero, say - and either way it is
	judged: against the reply that filled the entry, or against its own.
	*/
	if run.s.cache {
		parity_settle(run, q, index)
	}
}

/*
Ask one query and judge the answer.

Four outcomes, and the configuration decides which a query is due: blocked by
name (the upstream must not have been asked), answered from the cache (held
against the reply that filled the entry), blocked by what the upstream said (a
CNAME into a blocked name), or forwarded and held to parity like any other.
*/
@(private = "file")
parity_settle :: proc(run: ^Parity_Mock_Run, q: Parity_Query, index: int) {
	stats := run.stats
	stats.sent += 1
	stats.transports[q.transport] += 1
	parity_upstreams_reset(run.ups)

	answer, answered := parity_ask_elodin(run.srv, q)
	if !answered {
		// Not every query has an answer coming: this server drops a message it
		// cannot make a response out of rather than replying to it.
		stats.unanswered += 1
		return
	}
	reference, from, asked := parity_upstreams_reference(run.ups, q)

	/*
	Blocked by name, unless the question is one the server refuses before it
	reads a block list at all. RFC 6891 section 6.1.3 has an unknown EDNS
	version answered BADVERS whatever it asked, and a class this server does
	not serve is refused for the class; neither is a lookup of the name. A
	query without RD is not in that set: the block lists sit above the RD gate,
	so a blocked name is blocked however it was asked.
	*/
	refused_first := q.local && (q.version != 0 || q.qclass != 1)
	if run.s.blocking && !refused_first && parity_blocked_name(q.name) {
		parity_check_blocked(run.r, q, answer, asked, false, stats)
		return
	}

	age := u32(0)
	if asked {
		parity_check_route(run, q, from)
		run.served[from] += 1
		if run.s.cache {
			parity_cache_store(&run.cached, q, reference)
		}
	} else {
		entry, found := run.cached[parity_cache_key(q)]
		if !run.s.cache || q.local || !found {
			// Nothing reached the upstream, so the server answered out of its
			// own mouth. Correct for some questions and a finding for others.
			stats.local += 1
			parity_check_local(run.r, q, answer, run.opts, stats)
			return
		}
		reference = entry.reply
		age = u32(time.duration_seconds(time.since(entry.at))) + 1
	}

	/*
	An allow rule on the question clears the whole answer, the one exemption
	that reaches past a name (see src/server/cnamecheck.odin on why no other
	allow rule does): a CNAME from an allowed name into a blocked one is
	served.
	*/
	if run.s.blocking && !parity_name_under(q.name, PARITY_ALLOWED) && parity_cloaked(reference) {
		parity_check_blocked(run.r, q, answer, true, true, stats)
		return
	}

	policy := Parity_Policy {
		mode              = .Mock,
		dnssec_validation = false,
		ttl_exact         = true,
		transport         = q.transport,
		client_udp_limit  = parity_client_limit(q, parity_max_udp(run.s)),
		client_cookies    = run.s.cookies != .Off,
		cache             = run.s.cache,
		cache_age         = age,
	}
	parity_judge(run.r, q, reference, answer, policy, run.opts, stats, index)
}

// The client cookie a query carried, or nil.
parity_sent_cookie :: proc(q: Parity_Query) -> []u8 {
	for o in q.options {
		if o.code == 10 && len(o.data) >= 8 {
			return o.data
		}
	}
	return nil
}

/*
The exchange `cookies.require` puts in front of a UDP query that carries a
cookie, and the query that comes after it.

RFC 7873 section 5.2.3: a query whose cookie does not show a server cookie this
server issued is answered BADCOOKIE, with a cookie to come back with and nothing
else - no answer, and no upstream asked, since the whole point is that an
unverified source costs this server nothing. The generator only ever sends a
fresh client cookie, so every such query takes this path first.

What comes back is the query again carrying the cookie it was handed, which is
what a real client does next, and that one is judged for parity like any other.
Any other outcome is a failure: an upstream asked, an answer given anyway, or a
cookie that does not carry the client's own half.
*/
@(private = "file")
parity_cookie_handshake :: proc(run: ^Parity_Mock_Run, q: Parity_Query) -> (shown: Parity_Query, ok: bool) {
	stats := run.stats
	parity_upstreams_reset(run.ups)
	answer, answered := parity_ask_elodin(run.srv, q)
	if !answered {
		stats.sent += 1
		stats.unanswered += 1
		return q, false
	}
	_, _, asked := parity_upstreams_reference(run.ups, q)
	sent := parity_sent_cookie(q)
	m := pw_parse(answer, context.temp_allocator)
	got, has := pw_find_option(m, 10)

	problem := ""
	switch {
	case !m.ok:
		problem = fmt.tprintf("the answer does not parse: %s", m.err)
	case m.id != q.id:
		problem = fmt.tprintf("the answer came back with id %d, not %d", m.id, q.id)
	case asked:
		problem = "the upstream was asked before the client had shown a server cookie"
	case m.rcode != 23:
		problem = fmt.tprintf("rcode %s, not badcookie", pc_rcode_text(m.rcode, context.temp_allocator))
	case len(m.answer) != 0:
		problem = fmt.tprintf("a badcookie carrying %d answer records", len(m.answer))
	case !has || len(got) < 16 || len(got) > 40:
		problem = "a badcookie without a well-formed cookie to come back with"
	case string(got[:8]) != string(sent[:8]):
		problem = "a badcookie whose cookie does not start with the client's own eight bytes"
	}
	if problem != "" {
		stats.sent += 1
		stats.failures += 1
		fail(run.r, "%s: %s\n    answer: %s", q.desc, problem, parity_hex(answer))
		return q, false
	}

	shown = q
	options := make([]Pw_Option, len(q.options), context.temp_allocator)
	copy(options, q.options)
	for &o in options {
		if o.code == 10 {
			o.data = got
		}
	}
	shown.options = options
	shown.wire = pg_encode(shown, context.temp_allocator)
	shown.desc = strings.concatenate({q.desc, " after badcookie"}, context.temp_allocator)
	return shown, true
}

/*
Whether a zone route sent this query where it says.

The routed zone goes to the last upstream and nowhere else, and every other name
goes to the others. A reply from the wrong one is a route not taken - or one
taken for a name it does not cover - and the answer would still pass parity,
the zone being the same zone, which is why it is checked apart.
*/
@(private = "file")
parity_check_route :: proc(run: ^Parity_Mock_Run, q: Parity_Query, from: int) {
	if run.s.route == "" {
		return
	}
	/*
	Less one question: the DS at the route's own apex, which lives in the
	parent zone and is asked of the default upstreams so the chain of trust
	has the parent's answer (src/server/routes.odin, the apex carve-out).
	*/
	apex := q.qtype == 43 && pw_names_equal_fold(q.name, pm_name(run.s.route, context.temp_allocator))
	routed := parity_name_under(q.name, run.s.route) && !apex
	last := len(run.s.kinds) - 1
	if routed != (from == last) {
		run.stats.failures += 1
		fail(
			run.r,
			"%s was answered by upstream %d; %s is routed to upstream %d alone",
			q.desc,
			from,
			run.s.route,
			last,
		)
	}
}

/*
Whether the strategy spread the queries the way it says it does.

Round robin moves its starting point on every query, so across a run every
upstream is asked. One that never was is a rotation that is not rotating, and
parity would never notice: the answers would all be right, from one server.
*/
@(private = "file")
parity_strategy_check :: proc(run: ^Parity_Mock_Run) {
	if run.s.strategy != "round_robin" || run.opts.runs < 30 {
		return
	}
	for n, i in run.served {
		if n == 0 {
			fail(run.r, "round robin never asked upstream %d of %d", i, len(run.served))
		}
	}
}
