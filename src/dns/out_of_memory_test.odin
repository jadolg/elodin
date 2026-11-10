package dns

import "core:bytes"
import "core:mem"
import "core:testing"

/*
An allocator that runs dry fails the build it was asked for, and never traps.

The server builds every answer in a per-request arena, and that arena can stop
growing: the process is out of memory, an `RLIMIT_AS` is hit, or
`vm.max_map_count` is reached. One query then fails on its own; it must not
take the process down with a bounds-check trap, which the release build keeps.

Each entry point is run against an arena of every size from nothing up to what
it needs, so a check missing at any allocation along the way traps here. A
build that reports success has to be the one an unlimited allocator makes.
*/

@(private = "file")
OOM_COOKIE := [8]u8{1, 2, 3, 4, 5, 6, 7, 8}

// Long enough that the writer's buffer grows partway through the message.
@(private = "file")
OOM_LONG_TXT := [3]string {
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012345",
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012345",
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012345",
}

/*
Twenty owner names the writer has not seen, so its compression map grows past
the room `writer_init` gives it, and each of them twice, so one it failed to
record shows in the bytes.
*/
@(private = "file")
OOM_GLUE := [40]Record {
	{name = "h0.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 10}}},
	{name = "h1.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 11}}},
	{name = "h2.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 12}}},
	{name = "h3.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 13}}},
	{name = "h4.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 14}}},
	{name = "h5.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 15}}},
	{name = "h6.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 16}}},
	{name = "h7.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 17}}},
	{name = "h8.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 18}}},
	{name = "h9.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 19}}},
	{name = "h10.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 20}}},
	{name = "h11.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 21}}},
	{name = "h12.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 22}}},
	{name = "h13.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 23}}},
	{name = "h14.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 24}}},
	{name = "h15.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 25}}},
	{name = "h16.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 26}}},
	{name = "h17.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 27}}},
	{name = "h18.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 28}}},
	{name = "h19.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 29}}},
	{name = "h0.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 30}}},
	{name = "h1.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 31}}},
	{name = "h2.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 32}}},
	{name = "h3.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 33}}},
	{name = "h4.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 34}}},
	{name = "h5.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 35}}},
	{name = "h6.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 36}}},
	{name = "h7.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 37}}},
	{name = "h8.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 38}}},
	{name = "h9.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 39}}},
	{name = "h10.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 40}}},
	{name = "h11.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 41}}},
	{name = "h12.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 42}}},
	{name = "h13.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 43}}},
	{name = "h14.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 44}}},
	{name = "h15.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 45}}},
	{name = "h16.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 46}}},
	{name = "h17.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 47}}},
	{name = "h18.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 48}}},
	{name = "h19.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 49}}},
}

@(private = "file")
OOM_ADDITIONAL := [2]Record {
	{name = "mail.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 2}}},
	{
		name = ".",
		type = .OPT,
		class = Class(1232),
		ttl = 0x8000,
		data = Rdata_OPT{options = []EDNS_Option{{code = u16(EDNS_Option_Code.Cookie), data = OOM_COOKIE[:]}}},
	},
}

// Every RDATA shape the writer has a case for that carries a name or a length.
@(private = "file")
OOM_MESSAGE := Message {
	id = 0x4242,
	flags = {rd = true, qr = true},
	question = []Question{{name = "Example.COM.", type = .A, class = .IN}},
	answer = []Record {
		{name = "example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 1}}},
		{name = "example.com.", type = .TXT, class = .IN, ttl = 300, data = Rdata_TXT{strings = []string{"hello", "world"}}},
		{name = "long.example.com.", type = .TXT, class = .IN, ttl = 300, data = Rdata_TXT{strings = OOM_LONG_TXT[:]}},
		// Twenty labels, past the offsets `writer_init` reserves room for.
		{name = "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 3}}},
		{name = "example.com.", type = .MX, class = .IN, ttl = 300, data = Rdata_MX{preference = 10, exchange = "mail.example.com."}},
		{name = "example.com.", type = Type(65280), class = .IN, ttl = 300, data = Rdata_Raw{data = OOM_COOKIE[:]}},
	},
	authority = []Record {
		{
			name = "example.com.",
			type = .SOA,
			class = .IN,
			ttl = 300,
			data = Rdata_SOA{ns = "ns.example.com.", mbox = "hostmaster.example.com.", serial = 1, minimum = 60},
		},
	},
	additional = OOM_ADDITIONAL[:],
}

// The same message with the glue behind its answer, for the sweeps the map's
// growth matters to.
@(private = "file")
oom_message_with_glue :: proc() -> Message {
	m := OOM_MESSAGE
	m.authority = OOM_GLUE[:]
	return m
}

@(private = "file")
oom_message :: proc() -> Message {
	return OOM_MESSAGE
}

// The largest arena any sweep below needs; past it every build succeeds.
@(private = "file")
OOM_SWEEP_MAX :: 16384

/*
An allocator that refuses `fail_for` requests from its `fail_at`th on and
grants every other one from `arena`.

An arena that runs dry refuses everything after the first refusal too, so a
check missing at one allocation is covered by whichever check comes next. This
refuses a short run and then lets the next succeed, which is what finds it.
*/
@(private = "file")
Fail_Nth :: struct {
	arena:    mem.Arena,
	seen:     int,
	fail_at:  int,
	fail_for: int,
}

@(private = "file")
fail_nth_proc :: proc(
	data: rawptr,
	mode: mem.Allocator_Mode,
	size, alignment: int,
	old_memory: rawptr,
	old_size: int,
	loc := #caller_location,
) -> (
	[]byte,
	mem.Allocator_Error,
) {
	f := cast(^Fail_Nth)data
	#partial switch mode {
	case .Alloc, .Alloc_Non_Zeroed, .Resize, .Resize_Non_Zeroed:
		f.seen += 1
		if f.seen >= f.fail_at && f.seen < f.fail_at + f.fail_for {
			return nil, .Out_Of_Memory
		}
	}
	return mem.arena_allocator_proc(&f.arena, mode, size, alignment, old_memory, old_size, loc)
}

/*
Run `build` in an arena of every size up to `OOM_SWEEP_MAX`, with the same arena
as `context.temp_allocator` for the scratch the rebuilds take, and hand back
whether every successful build matched `want`.
*/
@(private = "file")
oom_sweep :: proc(t: ^testing.T, what: string, want: []u8, build: proc(allocator: mem.Allocator) -> ([]u8, bool)) {
	backing := make([]u8, OOM_SWEEP_MAX)
	defer delete(backing)
	failed_once := false
	for size in 0 ..= OOM_SWEEP_MAX {
		arena: mem.Arena
		mem.arena_init(&arena, backing[:size])
		limited := mem.arena_allocator(&arena)
		out: []u8
		ok: bool
		{
			context.temp_allocator = limited
			out, ok = build(limited)
		}
		if !ok {
			failed_once = true
			continue
		}
		if !testing.expectf(t, bytes.equal(out, want), "%s: a %d-byte arena built %v, wanted %v", what, size, out, want) {
			return
		}
	}
	testing.expectf(t, failed_once, "%s: no arena was small enough to fail, so the sweep proved nothing", what)

	// Then each run of allocations refused on its own, until a build asks for
	// fewer.
	for run in ([]int{1, 2, 3, 8}) do for n := 1; ; n += 1 {
		f := Fail_Nth{fail_at = n, fail_for = run}
		mem.arena_init(&f.arena, backing)
		one := mem.Allocator{procedure = fail_nth_proc, data = &f}
		out: []u8
		ok: bool
		{
			context.temp_allocator = one
			out, ok = build(one)
		}
		if f.seen < n {
			break
		}
		if ok && !testing.expectf(t, bytes.equal(out, want), "%s: refusing %d from allocation %d built %v, wanted %v", what, run, n, out, want) {
			return
		}
	}
}

@(test)
test_encode_with_no_memory_reports_it :: proc(t: ^testing.T) {
	m := Message{id = 7, question = []Question{{name = "example.com.", type = .A, class = .IN}}}
	out, _, err := encode_message(m, mem.nil_allocator())
	testing.expect_value(t, err, Encode_Error.Out_Of_Memory)
	testing.expect_value(t, len(out), 0)

	// The header alone, with no record after it to notice.
	bare, _, bare_err := encode_message(Message{id = 7}, mem.nil_allocator())
	testing.expect_value(t, bare_err, Encode_Error.Out_Of_Memory)
	testing.expect_value(t, len(bare), 0)
}

@(test)
test_encode_at_every_budget :: proc(t: ^testing.T) {
	@(static) want: []u8
	w, _, err := encode_message(oom_message(), context.allocator)
	if !testing.expect_value(t, err, Encode_Error.None) {
		return
	}
	defer delete(w)
	want = w
	oom_sweep(t, "encode", want, proc(a: mem.Allocator) -> ([]u8, bool) {
		out, _, err := encode_message(oom_message(), a)
		if err != .None {
			assert(err == .Out_Of_Memory, "an encode that ran dry reported something else")
			return nil, false
		}
		return out, true
	})
	@(static) glued: []u8
	g, _, gerr := encode_message(oom_message_with_glue(), context.allocator)
	if !testing.expect_value(t, gerr, Encode_Error.None) {
		return
	}
	defer delete(g)
	glued = g
	oom_sweep(t, "encode glue", glued, proc(a: mem.Allocator) -> ([]u8, bool) {
		out, _, err := encode_message(oom_message_with_glue(), a)
		if err != .None {
			assert(err == .Out_Of_Memory, "an encode that ran dry reported something else")
			return nil, false
		}
		return out, true
	})

	// Cut short, the walk back and the re-added OPT record write after a resize.
	@(static) cut: []u8
	c, _, cerr := encode_message(oom_message(), context.allocator, max_size = 100)
	if !testing.expect_value(t, cerr, Encode_Error.None) {
		return
	}
	defer delete(c)
	cut = c
	oom_sweep(t, "encode truncated", cut, proc(a: mem.Allocator) -> ([]u8, bool) {
		out, _, err := encode_message(oom_message(), a, max_size = 100)
		if err != .None {
			assert(err == .Out_Of_Memory, "a truncating encode that ran dry reported something else")
			return nil, false
		}
		return out, true
	})
}

/*
A decode that runs dry says so, rather than trapping on a section it could not
allocate or handing back a record whose RDATA came out empty.
*/
@(test)
test_decode_at_every_budget :: proc(t: ^testing.T) {
	@(static) wire: []u8
	w, _, err := encode_message(oom_message(), context.allocator)
	if !testing.expect_value(t, err, Encode_Error.None) {
		return
	}
	defer delete(w)
	wire = w
	oom_sweep(t, "decode", wire, proc(a: mem.Allocator) -> ([]u8, bool) {
		m, err := decode_message(wire, a)
		if err != .None {
			assert(err == .Out_Of_Memory, "a decode that ran dry reported something else")
			return nil, false
		}
		// Compared as bytes, encoded on the heap: what came out is what went in.
		again, _, eerr := encode_message(m, context.allocator)
		assert(eerr == .None)
		defer delete(again)
		return wire if bytes.equal(again, wire) else nil, true
	})
}

@(test)
test_name_fold_with_no_memory :: proc(t: ^testing.T) {
	folded, err := name_fold("Example.COM.", mem.nil_allocator())
	testing.expect_value(t, err, mem.Allocator_Error.Out_Of_Memory)
	testing.expect_value(t, folded, "")
}

/*
The answers built for a query that is being refused or sent to TCP: the
SERVFAIL a request that ran out of arena is answered with is one of these.
*/
@(test)
test_error_responses_at_every_budget :: proc(t: ^testing.T) {
	@(static) query: []u8
	q := Message {
		id         = 0x1234,
		flags      = {rd = true},
		question   = []Question{{name = "example.com.", type = .A, class = .IN}},
		additional = []Record{make_opt(1232, false)},
	}
	w, _, err := encode_message(q, context.allocator)
	if !testing.expect_value(t, err, Encode_Error.None) {
		return
	}
	defer delete(w)
	query = w

	decoded, derr := decode_message(query, context.temp_allocator)
	if !testing.expect_value(t, derr, Decode_Error.None) {
		return
	}
	// The wanted answers are built on the heap's temp arena, which outlives the
	// sweeps: `error_response` leaves its message's OPT record in the allocator.
	defer free_all(context.temp_allocator)
	want_err, _ := error_response(query, decoded, .Serv_Fail, context.temp_allocator)
	oom_sweep(t, "error_response", want_err, proc(a: mem.Allocator) -> ([]u8, bool) {
		msg, derr := decode_message(query, a)
		if derr != .None {
			return nil, false
		}
		return error_response(query, msg, .Serv_Fail, a)
	})

	// The header-only fallback, for a query that did not decode.
	want_hdr, _ := error_response(query, {}, .Form_Err, context.temp_allocator)
	oom_sweep(t, "error_response fallback", want_hdr, proc(a: mem.Allocator) -> ([]u8, bool) {
		return error_response(query, {}, .Form_Err, a)
	})

	want_tc, _ := truncated_response(query, context.temp_allocator)
	oom_sweep(t, "truncated_response", want_tc, proc(a: mem.Allocator) -> ([]u8, bool) {
		return truncated_response(query, a)
	})
}

@(test)
test_make_response_with_no_memory :: proc(t: ^testing.T) {
	query := Message {
		id         = 9,
		question   = []Question{{name = "example.com.", type = .A, class = .IN}},
		additional = []Record{make_opt(1232, false)},
	}
	resp, err := make_response(query, .Bad_Vers, mem.nil_allocator())
	testing.expect_value(t, err, mem.Allocator_Error.Out_Of_Memory)
	testing.expect_value(t, resp.id, 9)

	// Without its OPT record BADVERS would go out as NOERROR (RFC 6891 section
	// 6.1.3), so a caller that encodes it anyway, with all the memory it wants,
	// is refused.
	out, _, eerr := encode_message(resp, context.allocator)
	testing.expect_value(t, eerr, Encode_Error.Out_Of_Memory)
	testing.expect_value(t, len(out), 0)
}

// `m` encoded on the heap, for a fixture: a failure is the test's own.
@(private = "file")
oom_wire :: proc(m: Message, every_opt := false) -> []u8 {
	out: []u8
	err: Encode_Error
	if every_opt {
		out, _, err = encode_with_every_opt(m, context.allocator)
	} else {
		out, _, err = encode_message(m, context.allocator)
	}
	if err != .None {
		panic("the fixture does not encode")
	}
	return out
}

/*
Every rewrite of an encoded message's EDNS record, on both its fast path (the
OPT record last, cut in place) and its slow one (decode and encode again).
*/
@(test)
test_edns_rewrites_at_every_budget :: proc(t: ^testing.T) {
	@(static) last, inner, bare, two_opts: []u8
	m := oom_message()
	last = oom_wire(m)
	defer delete(last)

	// The OPT record ahead of a glue record, which only a rebuild can edit.
	swapped := m
	swapped.additional = []Record{m.additional[1], m.additional[0]}
	inner = oom_wire(swapped)
	defer delete(inner)

	no_opt := m
	no_opt.additional = m.additional[:1]
	bare = oom_wire(no_opt)
	defer delete(bare)

	// Two OPT records, which only the rebuild keeps both of for
	// `peek_opt_unreadable` to refuse.
	doubled := m
	doubled.additional = []Record{m.additional[1], m.additional[0], m.additional[1]}
	two_opts = oom_wire(doubled, every_opt = true)
	defer delete(two_opts)

	@(static) value := [2]u8{0, 18}
	Case :: struct {
		what:  string,
		build: proc(a: mem.Allocator) -> ([]u8, bool),
	}
	cases := [?]Case {
		{"set_edns_option last", proc(a: mem.Allocator) -> ([]u8, bool) {return set_edns_option(last, .Ext_Error, value[:], a)}},
		{"set_edns_option inner", proc(a: mem.Allocator) -> ([]u8, bool) {return set_edns_option(inner, .Ext_Error, value[:], a)}},
		{"set_edns_option two", proc(a: mem.Allocator) -> ([]u8, bool) {return set_edns_option(two_opts, .Ext_Error, value[:], a)}},
		{"ensure_edns_option bare", proc(a: mem.Allocator) -> ([]u8, bool) {return ensure_edns_option(bare, .Ext_Error, value[:], 1232, a)}},
		{"ensure_opt bare", proc(a: mem.Allocator) -> ([]u8, bool) {return ensure_opt(bare, 1232, a)}},
		{"ensure_opt_compressed bare", proc(a: mem.Allocator) -> ([]u8, bool) {return ensure_opt_compressed(bare, 1232, a)}},
		{"remove_opt last", proc(a: mem.Allocator) -> ([]u8, bool) {return remove_opt(last, a)}},
		{"remove_opt inner", proc(a: mem.Allocator) -> ([]u8, bool) {return remove_opt(inner, a)}},
		{"remove_edns_option last", proc(a: mem.Allocator) -> ([]u8, bool) {return remove_edns_option(last, .Cookie, a)}},
		{"remove_edns_option inner", proc(a: mem.Allocator) -> ([]u8, bool) {return remove_edns_option(inner, .Cookie, a)}},
		{"strip_edns_options last", proc(a: mem.Allocator) -> ([]u8, bool) {return strip_edns_options(last, a)}},
		{"strip_edns_options inner", proc(a: mem.Allocator) -> ([]u8, bool) {return strip_edns_options(inner, a)}},
	}
	for c in cases {
		want, ok := c.build(context.allocator)
		if !testing.expectf(t, ok, "%s: failed with all the memory it wanted", c.what) {
			continue
		}
		oom_sweep(t, c.what, want, c.build)
		delete(want)
		free_all(context.temp_allocator)
	}
}
