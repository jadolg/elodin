package itest

import "core:fmt"
import "core:net"
import "core:strconv"
import "core:strings"

/*
Driving one parity query and reporting on a run of them.

Kept apart from `cases_parity.odin`, which is about how a run is set up; this is
about what happens to each query inside one.
*/

// How many failing queries a run prints in full before it starts only counting
// them. A run that has gone wrong has usually gone wrong in one way, and the
// tenth copy of it teaches nothing while burying the summary.
PARITY_MAX_REPORTED :: 10

@(private)
parity_ask_elodin :: proc(srv: ^Server, q: Parity_Query) -> (answer: []u8, ok: bool) {
	switch q.transport {
	case .UDP:
		res := query_udp(srv.udp_port, q.wire, context.temp_allocator)
		return res.wire, res.ok
	case .TCP:
		res := query_tcp(srv.udp_port, q.wire, context.temp_allocator)
		return res.wire, res.ok
	case .DoT:
		res := query_dot(srv.dot_port, q.wire, context.temp_allocator)
		return res.wire, res.ok
	case .DoH:
		res := doh_post(srv.doh_port, "/dns-query", q.wire, context.temp_allocator)
		if !res.ok || res.status != 200 || len(res.body) < 12 {
			return nil, false
		}
		return res.body, true
	}
	return nil, false
}

/*
The live mode's reference answer: one query straight to a resolver somewhere
else, over TCP if the datagram would not hold the reply.

The retry is the point. A truncated reply is not an answer, it is an instruction
to come back over TCP, and a client that stopped there would be comparing
elodin's full answer against an empty stub and calling every record in it
invented. elodin makes that retry on the client's behalf, so the reference has to
make it too or the two are not being asked the same thing.
*/
@(private)
parity_ask_reference :: proc(host: string, port: int, query: []u8) -> (answer: []u8, ok: bool) {
	answer, ok = parity_ask_udp(host, port, query)
	if !ok {
		return nil, false
	}
	m := pw_parse(answer, context.temp_allocator)
	if !m.ok || !m.tc {
		return answer, true
	}
	return parity_ask_tcp(host, port, query)
}

// One query over TCP to a resolver somewhere else. Its own rather than
// `query_tcp`, which only ever dials loopback.
@(private)
parity_ask_tcp :: proc(host: string, port: int, query: []u8) -> (answer: []u8, ok: bool) {
	address := net.parse_address(host)
	if address == nil {
		return nil, false
	}
	socket, err := net.dial_tcp_from_endpoint(net.Endpoint{address = address, port = port})
	if err != nil {
		return nil, false
	}
	defer net.close(socket)
	_ = net.set_option(socket, .Receive_Timeout, CLIENT_TIMEOUT)
	_ = net.set_option(socket, .Send_Timeout, CLIENT_TIMEOUT)

	framed := make([]u8, 2 + len(query), context.temp_allocator)
	framed[0] = u8(len(query) >> 8)
	framed[1] = u8(len(query))
	copy(framed[2:], query)
	if _, serr := net.send_tcp(socket, framed); serr != nil {
		return nil, false
	}

	header: [2]u8
	if !parity_read_full(socket, header[:]) {
		return nil, false
	}
	length := int(header[0]) << 8 | int(header[1])
	if length < 12 || length > 65535 {
		return nil, false
	}
	out := make([]u8, length, context.temp_allocator)
	if !parity_read_full(socket, out) {
		return nil, false
	}
	return out, true
}

@(private = "file")
parity_read_full :: proc(socket: net.TCP_Socket, buf: []u8) -> bool {
	got := 0
	for got < len(buf) {
		n, err := net.recv_tcp(socket, buf[got:])
		if err != nil || n <= 0 {
			return false
		}
		got += n
	}
	return true
}

// One query straight to a resolver somewhere else, over UDP only.
@(private = "file")
parity_ask_udp :: proc(host: string, port: int, query: []u8) -> (answer: []u8, ok: bool) {
	address := net.parse_address(host)
	if address == nil {
		return nil, false
	}
	family: net.Address_Family = .IP4
	if _, is_v6 := address.(net.IP6_Address); is_v6 {
		family = .IP6
	}
	socket, err := net.make_unbound_udp_socket(family)
	if err != nil {
		return nil, false
	}
	defer net.close(socket)
	_ = net.set_option(socket, .Receive_Timeout, CLIENT_TIMEOUT)
	_ = net.set_option(socket, .Send_Timeout, CLIENT_TIMEOUT)

	endpoint := net.Endpoint {
		address = address,
		port    = port,
	}
	if _, serr := net.send_udp(socket, query, endpoint); serr != nil {
		return nil, false
	}

	buf := make([]u8, 65535, context.temp_allocator)
	for {
		n, _, rerr := net.recv_udp(socket, buf)
		if rerr != nil || n < 12 {
			return nil, false
		}
		// A datagram carrying somebody else's transaction id is not this
		// query's answer, whoever sent it.
		if u16(buf[0]) << 8 | u16(buf[1]) != peek_id_of(query) {
			continue
		}
		out := make([]u8, n, context.temp_allocator)
		copy(out, buf[:n])
		return out, true
	}
}

@(private = "file")
peek_id_of :: proc(msg: []u8) -> u16 {
	if len(msg) < 2 {
		return 0
	}
	return u16(msg[0]) << 8 | u16(msg[1])
}

/*
The largest answer this client can be sent in one datagram.

The smaller of what the client advertised and what the server will put in a
datagram at all - `response_limit` in src/server/resolver.odin, which floors the
advertised size at `server.max_udp_response`. Both halves matter: a client
asking for 65535 does not get 65535, because a datagram that large fragments and
a fragmented DNS answer is a reassembly problem somebody else has to have.

Only meaningful over UDP; every other transport carries a length prefix and has
no such ceiling.
*/
@(private)
parity_client_limit :: proc(q: Parity_Query) -> int {
	if q.transport != .UDP {
		return 65535
	}
	if !q.edns {
		return 512
	}
	return min(max(int(q.udp_size), 512), PARITY_MAX_UDP_RESPONSE)
}

/*
Judge one comparison and fold it into the run's tally.

The mock mode's whole path: compare once, count what was allowed, report what
was not. The live mode splits the same steps up because it asks twice - see
`parity_live_attempt`.
*/
@(private)
parity_judge :: proc(
	r: ^Runner,
	q: Parity_Query,
	reference: []u8,
	answer: []u8,
	policy: Parity_Policy,
	opts: Parity_Options,
	stats: ^Parity_Stats,
	index: int,
) {
	c := parity_compare(q, reference, answer, policy)
	stats.compared += 1
	if c.identical {
		stats.identical += 1
	}
	parity_tally(opts, stats, c, true)
	if parity_failed(c.diffs[:]) {
		parity_report_diffs(r, q, c, opts, stats, index)
	}
}

/*
Count the differences that were allowed, by reason.

Counted rather than discarded, and that is the reviewable part of a run. A
reason that stops being hit is an allowance nobody needs any more; one that
starts being hit far more often than it was is behaviour that changed underneath
it. Neither is visible if an allowed difference is simply dropped on the floor.
*/
@(private)
parity_tally :: proc(
	opts: Parity_Options,
	stats: ^Parity_Stats,
	c: Parity_Compare,
	count_it: bool,
) {
	for d in c.diffs {
		if d.reason == "" {
			continue
		}
		if opts.explain {
			fmt.printfln("    allowed: %s (%s -> %s): %s", d.what, d.upstream, d.elodin, d.reason)
		}
		if !count_it {
			continue
		}
		// The key is cloned into the run's own allocator: the reason lives in
		// the per-query arena, which is reset before the summary is printed.
		if _, seen := stats.allowances[d.reason]; !seen {
			stats.allowances[strings.clone(d.reason, context.allocator)] = 0
		}
		stats.allowances[d.reason] += 1
	}
}

/*
Print one diverging query in full.

Everything needed to reproduce it goes in the line: the seed and the index
regenerate the exact query, and the three hex blobs are the query, what the
upstream said and what elodin said, so the difference can be picked apart
without re-running anything at all.
*/
@(private)
parity_report_diffs :: proc(
	r: ^Runner,
	q: Parity_Query,
	c: Parity_Compare,
	opts: Parity_Options,
	stats: ^Parity_Stats,
	index: int,
) {
	stats.failures += 1
	if stats.failures > PARITY_MAX_REPORTED {
		return
	}

	sb := strings.builder_make(context.temp_allocator)
	fmt.sbprintf(&sb, "\n  query %d: %s\n", index, q.desc)
	fmt.sbprintf(&sb, "    reproduce: --parity-seed %d --parity-runs %d\n", opts.seed, index + 1)
	for d in c.diffs {
		if d.reason != "" {
			continue
		}
		fmt.sbprintf(&sb, "    %s: upstream %s, elodin %s\n", d.what, d.upstream, d.elodin)
	}
	fmt.sbprintf(&sb, "    query:    %s\n", parity_hex(q.wire))
	fmt.sbprintf(&sb, "    upstream: %s\n", parity_hex(c.reference))
	fmt.sbprintf(&sb, "    elodin:   %s", parity_hex(c.answer))
	fail(r, "%s", strings.to_string(sb))
}

/*
The questions this server settles for itself.

There is no upstream answer to hold these against, so they are checked against
the specification instead. Only the two the generator produces on purpose are
here; anything else reaching this path is a query that should have been
forwarded and was not, which is why the count is reported.
*/
@(private)
parity_check_local :: proc(
	r: ^Runner,
	q: Parity_Query,
	answer: []u8,
	opts: Parity_Options,
	stats: ^Parity_Stats,
) {
	m := pw_parse(answer, context.temp_allocator)
	if !m.ok {
		stats.failures += 1
		fail(r, "locally answered %s does not parse: %s", q.desc, m.err)
		return
	}
	if m.id != q.id {
		stats.failures += 1
		fail(r, "locally answered %s came back with id %d, not %d", q.desc, m.id, q.id)
		return
	}
	if q.version == 0 {
		return
	}
	// RFC 6891 section 6.1.3: an unimplemented EDNS version is answered with
	// BADVERS, an OPT advertising the highest version this server does
	// implement, and nothing in the answer section.
	if m.rcode != 16 {
		stats.failures += 1
		fail(r, "%s asked with edns version %d and got rcode %d, not badvers", q.desc, q.version, m.rcode)
		return
	}
	if m.opt.version != 0 {
		stats.failures += 1
		fail(r, "%s got a badvers carrying edns version %d, not 0", q.desc, m.opt.version)
		return
	}
	if len(m.answer) != 0 {
		stats.failures += 1
		fail(r, "%s got a badvers carrying %d answer records", q.desc, len(m.answer))
	}
}

parity_report :: proc(r: ^Runner, opts: Parity_Options, stats: Parity_Stats) {
	if stats.failures > PARITY_MAX_REPORTED {
		fail(
			r,
			"%d more queries diverged, not printed",
			stats.failures - PARITY_MAX_REPORTED,
		)
	}

	// A run that compared almost nothing is not a run that passed. The floor is
	// deliberately low - the live mode legitimately skips unstable names, and
	// some generated questions are answered locally - but a mode that compared
	// a handful out of thousands has broken rather than agreed.
	if stats.sent > 0 && stats.compared * 4 < stats.sent {
		fail(
			r,
			"only %d of %d queries were compared; the rest were skipped, unanswered or answered locally",
			stats.compared,
			stats.sent,
		)
	}

	if !opts.verbose && !opts.explain {
		return
	}
	fmt.printfln("\n  parity summary (seed %d)", opts.seed)
	fmt.printfln("    sent          %d", stats.sent)
	fmt.printfln("    compared      %d", stats.compared)
	fmt.printfln("    byte-for-byte %d", stats.identical)
	fmt.printfln("    answered here %d", stats.local)
	fmt.printfln("    unanswered    %d", stats.unanswered)
	fmt.printfln("    skipped       %d", stats.skipped)
	fmt.printfln("    diverged      %d", stats.failures)
	if len(stats.allowances) > 0 {
		fmt.println("    differences allowed, and why:")
		for reason, count in stats.allowances {
			fmt.printfln("      %6d  %s", count, reason)
		}
	}
}

@(private)
parity_hex :: proc(b: []u8) -> string {
	sb := strings.builder_make(context.temp_allocator)
	for x in b {
		fmt.sbprintf(&sb, "%02x", x)
	}
	return strings.to_string(sb)
}

parity_split_host_port :: proc(s: string) -> (host: string, port: int, ok: bool) {
	// Rightmost colon, so a bare IPv6 address is still readable as one.
	i := strings.last_index_byte(s, ':')
	if i < 0 {
		return s, 53, true
	}
	port, ok = strconv.parse_int(s[i + 1:])
	if !ok {
		return "", 0, false
	}
	host = strings.trim_suffix(strings.trim_prefix(s[:i], "["), "]")
	return host, port, true
}
