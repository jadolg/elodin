package server

import "core:mem"
import "core:testing"
import "core:time"
import "elodin:config"
import "elodin:dns"
import "elodin:dnssec"

/*
Issue #620: an answer built in a request arena that cannot grow fails on its
own, and never traps. The arena runs dry when the process is out of memory, an
`RLIMIT_AS` is hit, or `vm.max_map_count` is reached; one query must not take
the server down with it.
*/

@(private = "file")
oom_server :: proc(cfg: ^config.Config) -> Server {
	cfg^ = config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	cfg.blocking.enabled = false
	return Server{cfg = cfg}
}

@(private = "file")
oom_query :: proc(t: ^testing.T) -> (wire: []u8, msg: dns.Message, ok: bool) {
	msg = dns.Message {
		id         = 0x620,
		flags      = {rd = true},
		question   = []dns.Question{{name = "Example.COM.", type = .A, class = .IN}},
		additional = []dns.Record{dns.make_opt(1232, false)},
	}
	err: dns.Encode_Error
	wire, _, err = dns.encode_message(msg, context.temp_allocator)
	if !testing.expect_value(t, err, dns.Encode_Error.None) {
		return
	}
	// Read back, so the message outlives the literals above.
	derr: dns.Decode_Error
	msg, derr = dns.decode_message(wire, context.temp_allocator)
	return wire, msg, testing.expect_value(t, derr, dns.Decode_Error.None)
}

/*
`shape_forwarded`'s failure branch: the outgoing query could not be built. A
detached refresh reports `unanswered` and counts nothing, as `judge_reply`'s
does; a client's query is counted failed. Neither traps on the SERVFAIL it
then cannot build either.
*/
@(test)
test_a_forward_that_cannot_be_built_fails_on_its_own :: proc(t: ^testing.T) {
	cfg: config.Config
	s := oom_server(&cfg)
	wire, msg, ok := oom_query(t)
	if !ok {
		return
	}
	defer free_all(context.temp_allocator)
	spent: int

	for refresh in ([]bool{true, false}) {
		before := s.stats.failed
		st := Query_State {
			s         = &s,
			query     = wire,
			msg       = msg,
			q         = msg.question[0],
			proto     = .UDP,
			client    = "127.0.0.1:5555",
			limit     = 512,
			started   = time.tick_now(),
			spent     = &spent,
			allocator = mem.nil_allocator(),
			refresh   = refresh,
		}
		testing.expect(t, shape_forwarded(&st), "a query with nothing to forward was handed on")
		testing.expect_value(t, st.outcome, Outcome.Failed)
		testing.expectf(t, !st.ok, "refresh=%v: an answer was reported built with no memory to build it", refresh)
		testing.expect_value(t, len(st.forwarded), 0)
		if refresh {
			testing.expect(t, st.unanswered, "a detached refresh that built nothing did not say so")
			testing.expect_value(t, s.stats.failed, before)
		} else {
			testing.expect(t, !st.unanswered, "a client's query was reported as a refresh's")
			testing.expect_value(t, s.stats.failed, before + 1)
		}
	}
}

/*
A query this server had no memory to read is not malformed. FORMERR would say
it was (RFC 1035 section 4.1.1) and send a stub back without EDNS (RFC 6891
section 7); what it gets is SERVFAIL, where there is room to build one, and
nothing where there is not.
*/
@(test)
test_a_query_read_without_memory_is_not_a_format_error :: proc(t: ^testing.T) {
	cfg: config.Config
	s := oom_server(&cfg)
	wire, _, ok := oom_query(t)
	if !ok {
		return
	}
	defer free_all(context.temp_allocator)

	backing := make([]u8, 4096)
	defer delete(backing)
	servfails := 0
	for size in 0 ..< len(backing) {
		// Only arenas the query itself does not fit in: past that, the request
		// is read and goes on to be answered, which is not this test's business.
		probe: mem.Arena
		mem.arena_init(&probe, backing[:size])
		if _, derr := dns.decode_message(wire, mem.arena_allocator(&probe)); derr == .None {
			break
		}
		arena: mem.Arena
		mem.arena_init(&arena, backing[:size])
		out, _, built := handle_query(&s, wire, .UDP, "127.0.0.1:5555", mem.arena_allocator(&arena))
		if !built {
			continue
		}
		rcode := dns.peek_rcode(out)
		if !testing.expectf(t, rcode == .Serv_Fail, "a %d-byte arena answered %v", size, rcode) {
			return
		}
		servfails += 1
	}
	testing.expect(t, servfails > 0, "no arena was large enough to answer SERVFAIL, so the rcode went untested")
}

// The answers this server builds for itself, each with nothing to build from.
@(test)
test_local_answers_with_no_memory :: proc(t: ^testing.T) {
	cfg: config.Config
	s := oom_server(&cfg)
	_, msg, ok := oom_query(t)
	if !ok {
		return
	}
	defer free_all(context.temp_allocator)
	none := mem.nil_allocator()

	testing.expect_value(t, len(synth_soa_for_zone("example.com.", 60, none)), 0)

	chaos_q := dns.Question{name = "version.bind.", type = .TXT, class = .CH}
	chaos, handled := answer_chaos(&s, msg, chaos_q, none, 512)
	testing.expect(t, !handled, "a CHAOS answer was reported built with no memory to build it")
	testing.expect_value(t, len(chaos), 0)

	_, failed_built := dnssec_failure_response(msg, dnssec.Result{status = .Bogus}, none, 512)
	testing.expect(t, !failed_built, "a DNSSEC failure was reported built with no memory to build it")

	query_wire, _, _ := dns.encode_message(msg, context.temp_allocator)
	_, refusal_built := upstream_refusal(query_wire, msg, "test", 512, none)
	testing.expect(t, !refusal_built, "a refusal was reported built with no memory to build it")

	// The extended error is advice; the OPT record it would go in is left as it was.
	resp := dns.make_response(msg, .Serv_Fail, context.temp_allocator)
	attach_extended_error(&resp, 22, "why", none)
	testing.expect_value(t, len(resp.additional), 1)
	_, has_options := resp.additional[0].data.(dns.Rdata_OPT)
	testing.expect(t, !has_options, "an extended error was attached with no memory to attach it")
}

// A TCP or DoT answer that cannot be framed is not sent, rather than trapping.
@(test)
test_a_stream_answer_with_no_memory_to_frame_it :: proc(t: ^testing.T) {
	answer := []u8{1, 2, 3}
	_, built := stream_frame(answer, mem.nil_allocator())
	testing.expect(t, !built, "an answer was framed with no memory to frame it")

	framed, framed_built := stream_frame(answer, context.temp_allocator)
	defer free_all(context.temp_allocator)
	testing.expect(t, framed_built, "an answer was not framed with all the memory it wanted")
	testing.expect_value(t, len(framed), 5)
	if len(framed) == 5 {
		testing.expect_value(t, framed[1], 3)
		testing.expect_value(t, framed[4], 3)
	}
}

/*
With only the OPT record refused, and room for everything after it: an answer
built without the record would state SERVFAIL with none of the client's EDNS,
so it is not built - or, for a refusal, built whole by `error_response`.
*/
@(test)
test_local_answers_with_their_opt_record_refused :: proc(t: ^testing.T) {
	_, msg, ok := oom_query(t)
	if !ok {
		return
	}
	defer free_all(context.temp_allocator)
	query_wire, _, _ := dns.encode_message(msg, context.temp_allocator)
	failed := false
	first := mem.Allocator{procedure = fail_first_proc, data = &failed}
	_, first_built := dnssec_failure_response(msg, dnssec.Result{status = .Bogus}, first, 512)
	testing.expect(t, failed, "the allocator was never asked for anything")
	testing.expect(t, !first_built, "a DNSSEC failure was built without the client's OPT record")

	// A refusal falls back to `error_response`, which builds it whole.
	failed = false
	refusal, refusal_first_built := upstream_refusal(query_wire, msg, "test", 512, first)
	testing.expect(t, failed, "the allocator was never asked for anything")
	if testing.expect(t, refusal_first_built, "a refusal was not built once there was memory for it") {
		testing.expect_value(t, dns.peek_rcode(refusal), dns.Rcode.Serv_Fail)
		read, rerr := dns.decode_message(refusal, context.temp_allocator)
		testing.expect_value(t, rerr, dns.Decode_Error.None)
		testing.expect(t, dns.edns_present(read), "a refusal was built without the client's OPT record")
	}
}

// Fails the first request it is given and hands the rest to the heap.
@(private = "file")
fail_first_proc :: proc(
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
	failed := cast(^bool)data
	if (mode == .Alloc || mode == .Alloc_Non_Zeroed) && !failed^ {
		failed^ = true
		return nil, .Out_Of_Memory
	}
	return context.temp_allocator.procedure(context.temp_allocator.data, mode, size, alignment, old_memory, old_size, loc)
}

/*
The question goes upstream folded, and a fold that could not be allocated is a
query not built - not one for the empty name, which the encoder would write as
the root.
*/
@(test)
test_an_upstream_query_whose_name_cannot_be_folded_is_not_built :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	failed := false
	first := mem.Allocator{procedure = fail_first_proc, data = &failed}
	q := dns.Question{name = "Example.COM.", type = .A, class = .IN}
	wire, built := upstream_query(q, false, false, first)
	testing.expect(t, failed, "the allocator was never asked for anything")
	testing.expectf(t, !built, "a query was built without its name: %v", wire)
}

// Fails the `fail_at`th request it is given and hands every other to the
// temp arena.
@(private = "file")
Fail_Nth :: struct {
	seen:    int,
	fail_at: int,
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
		if f.seen == f.fail_at {
			return nil, .Out_Of_Memory
		}
	}
	return context.temp_allocator.procedure(context.temp_allocator.data, mode, size, alignment, old_memory, old_size, loc)
}

/*
A DDR answer keeps the client's OPT record whichever of its allocations is
refused: the designated resolvers' addresses are the optional part (RFC 9462
section 4), and an answer that went out without the record would lose the
client's EDNS without a word.
*/
@(test)
test_a_ddr_answer_keeps_its_opt_record_whatever_runs_dry :: proc(t: ^testing.T) {
	cfg: config.Config
	s := oom_server(&cfg)
	// One designation, so the addresses are concatenated behind the OPT record.
	cfg.ddr.name = "dns.example."
	s.ddr.dot = true
	defer free_all(context.temp_allocator)
	query := dns.Message {
		id         = 0x620,
		question   = []dns.Question{{name = DDR_QNAME, type = .SVCB, class = .IN}},
		additional = []dns.Record{dns.make_opt(1232, false)},
	}
	q := query.question[0]
	built_once := false
	for n := 1; ; n += 1 {
		f := Fail_Nth{fail_at = n}
		one := mem.Allocator{procedure = fail_nth_proc, data = &f}
		out := build_resolver_arpa_response(&s, query, q, one, 1232)
		if f.seen < n {
			break
		}
		if len(out) == 0 {
			continue
		}
		built_once = true
		read, err := dns.decode_message(out, context.temp_allocator)
		if !testing.expect_value(t, err, dns.Decode_Error.None) {
			return
		}
		if !testing.expectf(t, dns.edns_present(read), "refusing allocation %d sent the answer without its OPT record", n) {
			return
		}
	}
	testing.expect(t, built_once, "no refusal left room for an answer, so the record went untested")
}
