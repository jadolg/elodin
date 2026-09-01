package dns

import "core:mem"
import "core:testing"

/*
A message whose OPT record is not the last one in the additional section, which
is what sends `rewrite_edns_option` down its decode-and-re-encode path.
*/
@(private = "file")
opt_not_last :: proc(options: []EDNS_Option, allocator := context.temp_allocator) -> []u8 {
	questions := make([]Question, 1, allocator)
	questions[0] = Question {
		name  = "example.com.",
		type  = .A,
		class = .IN,
	}

	opt := make_opt(1232, false)
	if options != nil {
		opt.data = Rdata_OPT{options = options}
	}

	trailing := Record {
		name  = "ns.example.com.",
		type  = .A,
		class = .IN,
		ttl   = 60,
		data  = Rdata_A{addr = {192, 0, 2, 1}},
	}

	additional := make([]Record, 2, allocator)
	additional[0] = opt
	additional[1] = trailing

	m := Message {
		id         = 0x1234,
		question   = questions,
		additional = additional,
	}
	wire, _, err := encode_message(m, allocator)
	if err != .None {
		return nil
	}
	return wire
}

/*
`remove_edns_option` must not hold anything of the caller's allocator beyond the
buffer it returns.

Every caller on the client-facing side passes a per-request arena, where a
scratch allocation left behind costs nothing. The race strategy does not: a race
worker can outlive the caller's arena, so `exchange` and everything under it is
given the process heap instead - and there nothing ever reclaims what this
procedure keeps.
*/
@(test)
test_remove_edns_option_frees_its_scratch :: proc(t: ^testing.T) {
	wire := opt_not_last([]EDNS_Option{{code = u16(EDNS_Option_Code.Cookie), data = []u8{1, 2, 3, 4, 5, 6, 7, 8}}})
	testing.expect(t, wire != nil, "could not build the query")

	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	heap := mem.tracking_allocator(&track)

	out, ok := remove_edns_option(wire, .Cookie, heap)
	testing.expect(t, ok, "remove_edns_option failed")
	testing.expect(t, raw_data(out) != raw_data(wire), "expected the rebuild path, not the in-place one")

	_, still_there := option_code_present(out, .Cookie)
	testing.expect(t, !still_there, "the cookie survived the removal")

	// The caller owns exactly one thing: the buffer it was handed.
	delete(out, heap)

	testing.expectf(
		t,
		len(track.allocation_map) == 0,
		"remove_edns_option left %d allocation(s) (%d bytes) behind in the caller's allocator",
		len(track.allocation_map),
		track.current_memory_allocated,
	)

	free_all(context.temp_allocator)
}

@(private = "file")
option_code_present :: proc(wire: []u8, code: EDNS_Option_Code) -> (data: []u8, found: bool) {
	m, err := decode_message(wire, context.temp_allocator)
	if err != .None {
		return nil, false
	}
	return find_edns_option(m, code)
}
