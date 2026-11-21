package itest

import "core:fmt"
import "elodin:cache"
import "elodin:dns"

@(private = "file")
MIXED_QNAME :: "mixed.rrset-ttl.test."

@(private = "file")
HIGHBIT_QNAME :: "highbit.rrset-ttl.test."

// A TTL with the top bit set: 2^31 + 16.
@(private = "file")
HIGHBIT_TTL :: u32(0x8000_0010)

// An A RRset whose two records arrive at TTLs 3600 and 10.
@(private = "file")
mixed_ttl_answer :: proc(allocator := context.allocator) -> []u8 {
	return a_answer(MIXED_QNAME, []u32{3600, 10}, allocator)
}

@(private = "file")
a_answer :: proc(qname: string, ttls: []u32, allocator := context.allocator) -> []u8 {
	answer := make([]dns.Record, len(ttls), context.temp_allocator)
	for ttl, i in ttls {
		answer[i] = {name = qname, type = .A, class = .IN, ttl = ttl, data = dns.Rdata_A{addr = {192, 0, 2, 34 + u8(i)}}}
	}
	m := dns.Message {
		question = []dns.Question{{name = qname, type = .A, class = .IN}},
		answer   = answer,
	}
	m.flags.qr = true
	m.flags.rd = true
	m.flags.ra = true
	wire, _, err := dns.encode_message(m, allocator)
	if err != .None {
		return nil
	}
	return wire
}

/*
RFC 2181 section 5.2: "In no case may a server send an RRSet with TTLs not all
equal"; one that arrives so is passed on, and cached, at its lowest TTL. The
forwarded copy and the copy the cache serves later are both held to it.
*/
run_rrset_ttl_cases :: proc(r: ^Runner) {
	GROUP :: "rrset ttl"
	payload := mixed_ttl_answer()
	defer delete(payload)
	if payload == nil {
		skip_case(r, GROUP, "cannot build the mixed-TTL answer")
		return
	}
	upstream_port := next_port(r)
	mock := mock_make("rrset-ttl", upstream_port)
	mock_reply(mock, MIXED_QNAME, u16(dns.Type.A), payload)
	if !mock_start_or_skip(r, mock, GROUP) {
		return
	}
	defer mock_stop(mock)
	udp_port := next_port(r)
	srv, ok := start_server(r, Server_Options{config = base_config(udp_port, upstream_at(upstream_port), cache = "{ enabled: true }"), udp_port = udp_port})
	if !ok {
		return
	}
	defer stop_server(&srv)

	start_case(r, "rrset ttl: an RRset that arrives with two TTLs leaves with its lowest, forwarded and cached")
	{
		for what, i in ([]string{"forwarded", "cached"}) {
			res := query_udp(udp_port, build_query(MIXED_QNAME, u16(dns.Type.A), id = u16(0x6940 + i)))
			if !check(r, res.ok, "%s: no response", what) {
				continue
			}
			msg, decoded := decode_reply(r, res.wire)
			if !decoded || !check(r, len(msg.answer) == 2, "%s: %d answers, want both", what, len(msg.answer)) {
				continue
			}
			check(r, msg.answer[0].ttl == msg.answer[1].ttl, "%s: TTLs %d and %d in one RRset", what, msg.answer[0].ttl, msg.answer[1].ttl)
			check(r, msg.answer[0].ttl <= 10, "%s: TTL %d, past the lowest of the set", what, msg.answer[0].ttl)
		}
		check_eq_int(r, mock_total(mock), 1, fmt.tprintf("upstream queries for %s", MIXED_QNAME))
	}
	end_case(r)
}

/*
RFC 8767 section 4: a TTL with the top bit set is positive and capped, not read
as zero. With the cache on it is forwarded and cached at `cache.max_ttl`, so the
second query is a hit; with the cache off it is forwarded at `dns.TTL_CAP`.
*/
run_highbit_ttl_cases :: proc(r: ^Runner) {
	GROUP :: "highbit ttl"
	payload := a_answer(HIGHBIT_QNAME, []u32{HIGHBIT_TTL})
	defer delete(payload)
	if payload == nil {
		skip_case(r, GROUP, "cannot build the high-bit answer")
		return
	}
	upstream_port := next_port(r)
	mock := mock_make("highbit-ttl", upstream_port)
	mock_reply(mock, HIGHBIT_QNAME, u16(dns.Type.A), payload)
	if !mock_start_or_skip(r, mock, GROUP) {
		return
	}
	defer mock_stop(mock)

	Setup :: struct {
		cache:   string,
		ceiling: u32,
		fetches: int,
	}
	setups := []Setup {
		{cache = "{ enabled: true }", ceiling = cache.DEFAULT_MAX_TTL, fetches = 1},
		{cache = "{ enabled: false }", ceiling = dns.TTL_CAP, fetches = 2},
	}
	for setup in setups {
		udp_port := next_port(r)
		srv, ok := start_server(r, Server_Options{config = base_config(udp_port, upstream_at(upstream_port), cache = setup.cache), udp_port = udp_port})
		if !ok {
			return
		}
		before := mock_total(mock)
		start_case(r, fmt.tprintf("highbit ttl: a TTL with the top bit set is capped at %d, not zeroed, cache %s", setup.ceiling, setup.cache))
		for i in 0 ..< 2 {
			res := query_udp(udp_port, build_query(HIGHBIT_QNAME, u16(dns.Type.A), id = u16(0x6950 + i)))
			if !check(r, res.ok, "query %d: no response", i) {
				continue
			}
			msg, decoded := decode_reply(r, res.wire)
			if !decoded || !check(r, len(msg.answer) == 1, "query %d: %d answers, want 1", i, len(msg.answer)) {
				continue
			}
			ttl := msg.answer[0].ttl
			// A cache hit counts down from the ceiling by the seconds it was held.
			check(r, ttl <= setup.ceiling && ttl + 5 >= setup.ceiling, "query %d: TTL %d, want %d", i, ttl, setup.ceiling)
		}
		check_eq_int(r, mock_total(mock) - before, setup.fetches, fmt.tprintf("upstream queries for %s", HIGHBIT_QNAME))
		end_case(r)
		stop_server(&srv)
	}
}
