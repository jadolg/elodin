package server

import "core:fmt"
import "core:mem"
import "core:strings"
import "core:testing"
import "elodin:config"
import "elodin:dns"

// `opt` 0 sends no OPT record, 1 one with DO set, 2 one without and another size.
@(private = "file")
block_query :: proc(name: string, qtype: dns.Type, opt: int, rd, cd: bool) -> dns.Message {
	m: dns.Message
	m.id = 0xbeef
	m.flags.rd, m.flags.cd = rd, cd
	m.question = make([]dns.Question, 1, context.temp_allocator)
	m.question[0] = {name = name, type = qtype, class = .IN}
	if opt > 0 {
		m.additional = make([]dns.Record, 1, context.temp_allocator)
		m.additional[0] = dns.make_opt(1232 if opt == 1 else 1400, opt == 1)
	}
	return m
}

/*
`block_wire` writes the encoder's bytes, compared with the encoder itself over
every response mode, a type each mode answers differently, both settings of
`typed_only`, without an OPT record and with two that differ in size and DO,
and names that move the SOA's owner pointer: one label, mixed case, an escaped
dot in the first label, the longest name there is. Each answer is written at a
`limit` of its own length and left to the encoder one byte below it.
*/
@(test)
test_block_wire_is_the_encoders_bytes :: proc(t: ^testing.T) {
	cfg := config.default_config()
	s := Server{cfg = &cfg}
	cfg.blocking.custom_ipv4 = {10, 0, 0, 1}
	cfg.blocking.custom_ipv6 = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	cfg.blocking.block_ttl = 123

	longest := strings.concatenate(
		{strings.repeat("a", 63, context.temp_allocator), ".", strings.repeat("b", 63, context.temp_allocator), ".",
		 strings.repeat("c", 63, context.temp_allocator), ".", strings.repeat("d", 61, context.temp_allocator), "."},
		context.temp_allocator,
	)
	names := []string{"blocked.bench.test.", "Ads.Example.COM.", "com.", "a\\.b.example.", longest}
	types := []dns.Type{.A, .AAAA, .MX, .HTTPS}
	modes := []config.Block_Response{.NX_Domain, .No_Data, .Refused, .Zero_IP, .Custom_IP}
	for mode in modes {
		cfg.blocking.response = mode
		for name in names {
			for qtype in types {
				for typed_only in ([2]bool{false, true}) {
					for opt in 0 ..< 3 {
						q := block_query(name, qtype, opt, rd = opt != 1, cd = opt == 1)
						fast, ok := block_wire(&s, q, q.question[0], context.temp_allocator, dns.MAX_UDP_SIZE, typed_only)
						want := encode_block_response(&s, q, q.question[0], context.temp_allocator, dns.MAX_UDP_SIZE, typed_only)
						what := fmt.tprintf("%v %s %v typed_only=%v opt=%d", mode, name, qtype, typed_only, opt)
						if testing.expectf(t, ok, "%s: left to the encoder", what) {
							testing.expectf(t, string(fast) == string(want), "%s:\n got % x\nwant % x", what, fast, want)
							_, fits := block_wire(&s, q, q.question[0], context.temp_allocator, len(fast), typed_only)
							_, over := block_wire(&s, q, q.question[0], context.temp_allocator, len(fast) - 1, typed_only)
							testing.expectf(t, fits && !over, "%s: limit %d fits=%v over=%v", what, len(fast), fits, over)
						}
					}
				}
			}
		}
	}
	free_all(context.temp_allocator)
}

/*
Where the encoder would write other bytes, or might: the SOA's own names
compressed against a question that ends in them, the root, and an answer past
`limit`, which the encoder truncates. `build_block_response` still answers each.
*/
@(test)
test_block_wire_leaves_the_rest_to_the_encoder :: proc(t: ^testing.T) {
	cfg := config.default_config()
	s := Server{cfg = &cfg}
	cfg.blocking.response = .NX_Domain

	cases := []struct {
		name:  string,
		limit: int,
	}{
		{"x.invalid.", dns.MAX_UDP_SIZE},
		{"x.LocalHost.", dns.MAX_UDP_SIZE},
		{"hostmaster.INVALID.", dns.MAX_UDP_SIZE},
		{".", dns.MAX_UDP_SIZE},
		{"blocked.bench.test.", 40},
	}
	for c in cases {
		q := block_query(c.name, .A, 1, true, false)
		_, ok := block_wire(&s, q, q.question[0], context.temp_allocator, c.limit, false)
		testing.expectf(t, !ok, "%s at %d: written directly", c.name, c.limit)
		out := build_block_response(&s, q, q.question[0], context.temp_allocator, c.limit)
		want := encode_block_response(&s, q, q.question[0], context.temp_allocator, c.limit, false)
		testing.expectf(t, len(out) > 0 && string(out) == string(want), "%s at %d: not the encoder's answer", c.name, c.limit)
	}
	free_all(context.temp_allocator)
}

/*
`build_block_response` takes the direct path: one allocation, the answer, where
the encoder makes several. A call site that went back to the encoder would answer
the same bytes and give back the throughput `block_wire` is for.
*/
@(test)
test_block_response_is_one_allocation :: proc(t: ^testing.T) {
	cfg := config.default_config()
	s := Server{cfg = &cfg}
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	q := block_query("blocked.bench.test.", .A, 1, true, false)

	out := build_block_response(&s, q, q.question[0], mem.tracking_allocator(&track), dns.MAX_UDP_SIZE)
	testing.expectf(t, len(out) > 0, "no block answer")
	testing.expectf(t, track.total_allocation_count == 1, "a block answer took %d allocations, want 1", track.total_allocation_count)
	delete(out, mem.tracking_allocator(&track))
	free_all(context.temp_allocator)
}
