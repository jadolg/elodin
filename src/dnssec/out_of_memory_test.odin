package dnssec

import "core:mem"
import "core:testing"
import "core:time"
import "elodin:dns"
import "elodin:loop"

/*
Issue #636: a validation whose memory runs dry is undecided, not judged on what
was left. A refused allocation that drops a DS, a key or a signature from a set
leaves a smaller set to judge, and judged it reads as a forgery - or as an
unsigned delegation, which serves a forgery as insecure. Neither is a statement
about the zone.
*/

// Fails `fail_for` requests from its `fail_at`th on and hands every other to
// `backing`. src/dns/out_of_memory_test.odin and src/server/out_of_memory_test.odin
// keep their own copies: test files cannot be shared across packages.
@(private = "file")
Fail_Nth :: struct {
	backing:  mem.Allocator,
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
	return f.backing.procedure(f.backing.data, mode, size, alignment, old_memory, old_size, loc)
}

/*
The captured chain, read out of the heap and copied into the allocator the
validator hands the lookup, as the server's lookup copies its reply into the
request's arena. A copy that cannot be had is a lookup that failed, as it is
there; `scenario_query` would read the hex into that allocator and panic.
*/
@(private = "file")
copying_query :: proc(_: rawptr, name: string, type: dns.Type, allocator: mem.Allocator, _: ^time.Tick) -> (out: []u8, ok: bool) {
	wire, found := fixture_answer(FIXTURES, name, type, context.allocator)
	if !found {
		return nil, false
	}
	defer delete(wire)
	out = dns.alloc_slice([]u8, len(wire), allocator) or_return
	copy(out, wire)
	return out, true
}

@(private = "file")
Oom_Case :: struct {
	key:   string,
	qname: string,
	qtype: dns.Type,
	want:  Status,
}

// An answer and a denial of each kind the captured chains hold: RSA, ECDSA and
// Ed25519 signatures, NSEC, and an NSEC3 opt-out span that settles insecure.
@(private = "file")
OOM_CASES := []Oom_Case {
	{key = "example_a", qname = "www.example.com.", qtype = .A, want = .Secure},
	{key = "ed25519_a", qname = "ed25519.nl.", qtype = .A, want = .Secure},
	{key = "nxdomain_root", qname = "zzzz-does-not-exist-xq7.", qtype = .A, want = .Secure},
	{key = "nodata_cloudflare", qname = "nosuchname-xq7.cloudflare.com.", qtype = .A, want = .Secure},
	{key = "nxdomain_com", qname = "zzzz-does-not-exist-xq7.com.", qtype = .A, want = .Insecure},
}

/*
Every allocation of the validation refused in turn, alone and in runs: a
validation refused any is `Indeterminate` naming this server's reading, and one
refused none reaches the verdict the captured chain holds. The validator is
asked again with its memory back, so a step settled while it was dry cannot
have been cached.
*/
@(test)
test_a_validation_that_runs_dry_is_undecided :: proc(t: ^testing.T) {
	for c in OOM_CASES {
		// On the heap: each round frees the temp arena it would otherwise sit in.
		wire := unhex(fixture(c.key).wire, context.allocator)
		defer delete(wire)
		refused := 0
		for run in ([]int{1, 2, 3}) do for n := 1; ; n += 1 {
			v := make_validator(copying_query, nil, Options{})
			defer destroy_validator(v)
			f := Fail_Nth{backing = context.temp_allocator, fail_at = n, fail_for = run}
			result: Result
			{
				failing := mem.Allocator{procedure = fail_nth_proc, data = &f}
				context.temp_allocator = failing
				result = validate(v, c.qname, c.qtype, wire, fixture_now(), failing)
			}
			if f.seen < n {
				testing.expectf(t, result.status == c.want, "%s: %v (%s) with nothing refused", c.key, result.status, result.reason)
				free_all(context.temp_allocator)
				break
			}
			refused += 1
			if !testing.expectf(
				t,
				result.status == .Indeterminate && result.reason == READING_OVER_BUDGET,
				"%s, allocation %d refused (run of %d): %v (%s)",
				c.key,
				n,
				run,
				result.status,
				result.reason,
			) {
				return
			}
			again := validate(v, c.qname, c.qtype, wire, fixture_now())
			if !testing.expectf(
				t,
				again.status == c.want,
				"%s, allocation %d refused (run of %d) left the validator answering %v (%s)",
				c.key,
				n,
				run,
				again.status,
				again.reason,
			) {
				return
			}
			free_all(context.temp_allocator)
		}
		testing.expectf(t, refused > 0, "%s: the validation allocated nothing to refuse", c.key)
	}
}

// `key`'s captured reply with the first signature of its answer section - or of
// its authority section, for a denial - sent twice, so the prune keeps a
// signature past the one that verified.
@(private = "file")
signed_twice :: proc(t: ^testing.T, key: string) -> (wire: []u8, ok: bool) {
	msg, derr := dns.decode_message(scenario_fixture(FIXTURES, key), context.temp_allocator)
	if !testing.expect_value(t, derr, dns.Decode_Error.None) {
		return nil, false
	}
	section := &msg.answer if len(msg.answer) > 0 else &msg.authority
	records := make([dynamic]dns.Record, 0, len(section) + 1, context.temp_allocator)
	append(&records, ..section^)
	for rec in section {
		if rec.type == .RRSIG {
			append(&records, rec)
			break
		}
	}
	if !testing.expectf(t, len(records) == len(section) + 1, "%s holds no signature to send twice", key) {
		return nil, false
	}
	section^ = records[:]
	encoded, _, enc := dns.encode_message(msg, context.allocator)
	if !testing.expect_value(t, enc, dns.Encode_Error.None) {
		return nil, false
	}
	return encoded, true
}

/*
The AD prune refused any allocation is no prune: false, so the caller serves the
answer without AD, rather than a section an allocation dropped a signature or a
record from, under AD.
*/
@(test)
test_a_prune_that_runs_dry_is_not_a_prune :: proc(t: ^testing.T) {
	for c in OOM_CASES do for twice in ([]bool{false, true}) {
		if c.want != .Secure {
			continue
		}
		v := scenario_validator(&FIXTURES)
		defer destroy_validator(v)
		wire: []u8
		if twice {
			built: bool
			if wire, built = signed_twice(t, c.key); !built {
				return
			}
		} else {
			wire = unhex(fixture(c.key).wire, context.allocator)
		}
		defer delete(wire)
		result := validate(v, c.qname, c.qtype, wire, fixture_now())
		if !testing.expectf(t, result.status == .Secure, "%s: %v (%s)", c.key, result.status, result.reason) {
			return
		}
		_, pruned := strip_unauthenticated(wire, result)
		if !testing.expectf(t, pruned, "%s: the prune failed with nothing refused", c.key) {
			return
		}
		refused := 0
		for run in ([]int{1, 2, 3}) do for n := 1; ; n += 1 {
			f := Fail_Nth{backing = context.temp_allocator, fail_at = n, fail_for = run}
			ok: bool
			{
				failing := mem.Allocator{procedure = fail_nth_proc, data = &f}
				context.temp_allocator = failing
				_, ok = strip_unauthenticated(wire, result, failing)
			}
			if f.seen < n {
				testing.expectf(t, ok, "%s: the prune failed with nothing refused", c.key)
				break
			}
			refused += 1
			testing.expectf(t, !ok, "%s, allocation %d refused (run of %d) still pruned", c.key, n, run)
		}
		testing.expectf(t, refused > 0, "%s: the prune allocated nothing to refuse", c.key)
		free_all(context.temp_allocator)
	}
}

// A signer that cannot be read for want of memory is this server's failure,
// not a bad name in the record.
@(test)
test_a_signer_read_without_memory_is_not_a_bad_name :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	msg, derr := dns.decode_message(scenario_fixture(FIXTURES, "example_a"), context.temp_allocator)
	if !testing.expect_value(t, derr, dns.Decode_Error.None) {
		return
	}
	for rec in msg.answer {
		if rec.type != .RRSIG {
			continue
		}
		rdata, is_raw := raw_rdata(rec)
		if !testing.expect(t, is_raw, "the captured RRSIG is not raw RDATA") {
			return
		}
		sig, perr := parse_rrsig(rdata, context.temp_allocator)
		testing.expect_value(t, perr, Parse_Error.None)
		testing.expect(t, sig.signer != "", "the captured RRSIG names no signer")
		_, dry_err := parse_rrsig(rdata, mem.nil_allocator())
		testing.expect_value(t, dry_err, Parse_Error.Out_Of_Memory)
		return
	}
	testing.expect(t, false, "the captured answer holds no RRSIG")
}

/*
A zone's keys the heap refused a copy of are not cached short of a key, which
would refuse every signature that key makes for the life of the entry: either
every usable key is held, or the zone is not cached.
*/
@(test)
test_a_key_set_the_heap_refuses_is_not_cached_short :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	msg, derr := dns.decode_message(scenario_fixture(FIXTURES, "com_dnskey"), context.temp_allocator)
	if !testing.expect_value(t, derr, dns.Decode_Error.None) {
		return
	}
	keys := make([dynamic]Dnskey, context.temp_allocator)
	for rec in msg.answer {
		rdata, is_raw := raw_rdata(rec)
		if rec.type != .DNSKEY || !is_raw {
			continue
		}
		key, perr := parse_dnskey(rdata)
		if !testing.expect_value(t, perr, Parse_Error.None) {
			return
		}
		if _, aerr := append(&keys, key); !testing.expect_value(t, aerr, nil) {
			return
		}
	}
	usable := 0
	for key in keys {
		usable += 1 if key_usable(key) else 0
	}
	if !testing.expectf(t, usable > 1, "the fixture holds %d usable keys, want more than one to drop", usable) {
		return
	}

	// Into an empty cache, and over the zone's own entry, which a refresh
	// replaces.
	refused := 0
	for refresh in ([]bool{false, true}) do for run in ([]int{1, 2, 3}) do for n := 1; ; n += 1 {
		v := make_validator(counting_query, nil, Options{})
		defer destroy_validator(v)
		if refresh {
			cache_put(v, nil, "com.", .Secure, keys[:], MAX_ZONE_TTL, loop.moment_now())
		}
		heap := v.allocator
		f := Fail_Nth{backing = heap, fail_at = n, fail_for = run}
		v.allocator = mem.Allocator{procedure = fail_nth_proc, data = &f}
		cache_put(v, nil, "com.", .Secure, keys[:], MAX_ZONE_TTL, loop.moment_now())
		v.allocator = heap
		entry, found := v.zones["com."]
		if f.seen < n {
			testing.expect(t, found, "the zone was not cached with nothing refused")
			testing.expect_value(t, len(entry.keys) if found else 0, usable)
			break
		}
		refused += 1
		for zone in v.zones {
			testing.expectf(t, zone == "com.", "allocation %d refused (run of %d, refresh %v) cached a zone named %q", n, run, refresh, zone)
		}
		testing.expectf(
			t,
			!found && !refresh || found && len(entry.keys) == usable,
			"allocation %d refused (run of %d, refresh %v): cached %v, %d of %d keys",
			n,
			run,
			refresh,
			found,
			len(entry.keys) if found else 0,
			usable,
		)
	}
	testing.expect(t, refused > 0, "the cache took no copy to refuse")
}

/*
Nothing a question settles once it has run dry is remembered, a zone or a name
that is no cut: the step may have judged a set short of a record. The same calls
for a question with its memory are remembered.
*/
@(test)
test_a_question_that_ran_dry_settles_nothing :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	now := loop.moment_now()
	for dry in ([]bool{false, true}) {
		v := make_validator(counting_query, nil, Options{})
		defer destroy_validator(v)
		budget := query_budget(v)
		ran := dry
		budget.dry = &ran
		cache_put(v, &budget, "example.com.", .Insecure, nil, MAX_ZONE_TTL, now)
		non_cut_remember(v, &budget, "www.example.com.", MIN_ZONE_TTL, now)
		_, zone_found, _ := cache_get(v, "example.com.", now, context.temp_allocator)
		_, _, name_found := cache_get(v, "www.example.com.", now, context.temp_allocator)
		testing.expectf(t, zone_found == !dry, "ran dry %v: the zone cached %v", dry, zone_found)
		testing.expectf(t, name_found == !dry, "ran dry %v: the name remembered %v", dry, name_found)
	}
}

// What `scratch_seeing_query` saw: lookups, and how many ran with a temp
// allocator other than `want`.
@(private = "file")
Scratch_Seen :: struct {
	want:    rawptr,
	calls:   int,
	others:  int,
}

@(private = "file")
scratch_seeing_query :: proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator, _: ^time.Tick) -> ([]u8, bool) {
	seen := (^Scratch_Seen)(ctx)
	seen.calls += 1
	if context.temp_allocator.data != seen.want {
		seen.others += 1
	}
	return fixture_answer(FIXTURES, name, type, allocator)
}

/*
A lookup runs with the temp allocator the question came with, not the watch
`validate` puts over it: what the lookup starts can outlive the validation, a
race's legs on threads of their own, and the watch lives in `validate`'s frame.
*/
@(test)
test_a_lookup_runs_on_the_questions_own_scratch :: proc(t: ^testing.T) {
	seen := Scratch_Seen {
		want = context.temp_allocator.data,
	}
	v := make_validator(scratch_seeing_query, &seen, Options{})
	defer destroy_validator(v)
	defer free_all(context.temp_allocator)
	result := validate(v, "www.example.com.", .A, scenario_fixture(FIXTURES, "example_a"), fixture_now())
	testing.expect_value(t, result.status, Status.Secure)
	testing.expect(t, seen.calls > 0, "the walk asked nobody")
	testing.expect_value(t, seen.others, 0)
}
