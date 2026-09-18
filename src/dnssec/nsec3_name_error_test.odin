package dnssec

import "core:mem"
import "core:testing"
import "core:time"
import "elodin:dns"

/*
What a name error proven with NSEC3 costs, and what happens when it cannot be
paid for.

`MAX_NSEC3_ROUNDS_PER_QUERY` bounds the hashing one question may spend, and the
answer a proof gets when it runs out has to be `Indeterminate` - this server did
not finish reading the records - and never `Bogus`, which says forgery, carries
the client's address into the log and hands the client extended error 6.

No other NSEC3 fixture in this package reaches that proof. A DS denial is
settled by the walk on the way down: under opt-out the name comes back an
unsigned delegation, and without it the step answers from a record on the name
itself. `n3test.` is asked about a name two labels below its apex, so the
answer's own proof has to find the closest encloser, see the next closer name
covered and see the wildcard covered - the shape that does the hashing.

Generated - `testdata/gen/sign_fixtures.py`, scenario `nsec3_name_error`.
Ed25519 throughout, zero iterations and a two-byte salt, root replaced by a
trust anchor of the generator's own making. What is measured here is how many
hashes the proof asks for, not how dear one of them is.
*/

@(private = "file")
N3_ANCHOR :: ". IN DS 34178 15 2 5D09A200847C8691AE3E6BC2E077CB7975EA43F330D53C220AF2C6F08FA0A448"

@(private = "file")
N3_FIXTURES := []Fixture{
	{
		key   = "n3_root_dnskey",
		name  = ".",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "1234858000010002000000000000300001000030000100000e1000240101030fbe2e40b9584be9eb80d709d8f4470eaa" +
			"ba4036cf474f6398a01faaa60ce8bf0b00002e000100000e10005300300f0000000e107d3b18206a4788208582002481" +
			"889066f7663c8f98048529ce749d210c4d9293900d51e1196b634f5d2deaa37ab7cfb63ec2fab3c8ac518e5a55fa6f92" +
			"ae143e4869e316efb0bd1abd9e00",
	},
	{
		key   = "n3_ds",
		name  = "n3test.",
		type  = .DS,
		rcode = 0,
		wire  = "123485800001000200000000066e337465737400002b0001066e337465737400002b000100000e100024ce660f024c94" +
			"dbc5faf609c5970d70b7d1bd324f1f4fe52d8237a3c1bef0c40114acfb26066e337465737400002e000100000e100053" +
			"002b0f0100000e107d3b18206a478820858200774fc6ccc5ae4783d31fa22e2c1dbd90755a4814f2713d427d3d88af27" +
			"67ea5b8e76ecaa898edfbddfaa5179a5a12b47ef9dda2eb0816b1eeb744fc8c26c6902",
	},
	{
		key   = "n3_dnskey",
		name  = "n3test.",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "123485800001000200000000066e33746573740000300001066e3374657374000030000100000e1000240101030f89c0" +
			"39bfc7f5b52c84a4eb9d40824fe94e9dd974fe0e92a73583f73d70283354066e337465737400002e000100000e10005a" +
			"00300f0100000e107d3b18206a478820ce66066e3374657374007c28ce3b23fe670d63df1872bbc9d09d91f8e5552e7d" +
			"e32ff595ace66df8739a15334ab87c71a26752138320a646265a65b21ad376fbcd99f7ac1b2bd1ca2b0c",
	},
	{
		key   = "n3_nx",
		name  = "nx.deep.n3test.",
		type  = .A,
		rcode = 3,
		wire  = "123485830001000000040000026e780464656570066e33746573740000010001203361727067376435636475346a656d" +
			"66697073633234756d6e626c6b726d7376066e3374657374000032000100000e10002501000000020e0f14b14ca13361" +
			"9f7df6f0dab64e642d85a4aef279ea000762000000000290203361727067376435636475346a656d6669707363323475" +
			"6d6e626c6b726d7376066e337465737400002e000100000e10005a00320f0200000e107d3b18206a478820ce66066e33" +
			"7465737400c01bbeae1b7aca1f677dff655442ce7171ff3d171c9be0add6767f6160099e93ad36ec2ad47194961ee1d2" +
			"18296ca089e1da3784e629dedb151686d2c317d30a206d353661326372316a747576647336716d703736386263356b69" +
			"6e6634756661066e3374657374000032000100000e10002401000000020e0f141ab7981da5637c49bacf9678c113d6ba" +
			"eb4ddb9f0006400000000002206d353661326372316a747576647336716d703736386263356b696e6634756661066e33" +
			"7465737400002e000100000e10005a00320f0200000e107d3b18206a478820ce66066e33746573740084f5029f3ceff0" +
			"e1306363e6b4a1ddb9844e618d80c120ebdc0292c98790e95cb435134a664efa06662164ad5ec49f69ef0b68ab40caa8" +
			"753a3cd156f9bf6909",
	},
	{
		key   = "n3_deep_ds",
		name  = "deep.n3test.",
		type  = .DS,
		rcode = 3,
		wire  = "1234858300010000000400000464656570066e337465737400002b0001203361727067376435636475346a656d666970" +
			"73633234756d6e626c6b726d7376066e3374657374000032000100000e10002501000000020e0f14b14ca133619f7df6" +
			"f0dab64e642d85a4aef279ea000762000000000290203361727067376435636475346a656d66697073633234756d6e62" +
			"6c6b726d7376066e337465737400002e000100000e10005a00320f0200000e107d3b18206a478820ce66066e33746573" +
			"7400c01bbeae1b7aca1f677dff655442ce7171ff3d171c9be0add6767f6160099e93ad36ec2ad47194961ee1d218296c" +
			"a089e1da3784e629dedb151686d2c317d30a206d353661326372316a747576647336716d703736386263356b696e6634" +
			"756661066e3374657374000032000100000e10002401000000020e0f141ab7981da5637c49bacf9678c113d6baeb4ddb" +
			"9f0006400000000002206d353661326372316a747576647336716d703736386263356b696e6634756661066e33746573" +
			"7400002e000100000e10005a00320f0200000e107d3b18206a478820ce66066e33746573740084f5029f3ceff0e13063" +
			"63e6b4a1ddb9844e618d80c120ebdc0292c98790e95cb435134a664efa06662164ad5ec49f69ef0b68ab40caa8753a3c" +
			"d156f9bf6909",
	},
}

@(private = "file")
n3_query :: proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator) -> (wire: []u8, ok: bool) {
	for f in N3_FIXTURES {
		if f.type == type && dns.name_equal_fold(f.name, name) {
			return decode_hex(f.wire, allocator)
		}
	}
	return nil, false
}

@(private = "file")
n3_validator :: proc() -> ^Validator {
	anchor, ok := parse_trust_anchor(N3_ANCHOR, context.temp_allocator)
	if !ok {
		return nil
	}
	anchors := make([]Trust_Anchor, 1, context.temp_allocator)
	anchors[0] = anchor
	return make_validator(n3_query, nil, Options{anchors = anchors})
}

@(private = "file")
n3_reply :: proc() -> []u8 {
	for f in N3_FIXTURES {
		if f.key == "n3_nx" {
			out, _ := decode_hex(f.wire, context.temp_allocator)
			return out
		}
	}
	return nil
}

@(private = "file")
N3_QNAME :: "nx.deep.n3test."

@(test)
test_an_nsec3_name_error_validates_and_says_what_it_hashed :: proc(t: ^testing.T) {
	// The control, and the measurement the test below is built on: if this
	// stops proving, everything after it is measuring the wrong thing.
	v := n3_validator()
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	msg, err := dns.decode_message(n3_reply(), context.temp_allocator)
	testing.expect(t, err == .None, "the fixture should decode")

	budget := Budget{}
	result := validate_denial(v, &budget, msg, N3_QNAME, .A, .IN, u32(FIXTURE_TIME), time.unix(FIXTURE_TIME, 0), context.temp_allocator)
	testing.expectf(t, result.status == .Secure, "the name error should be proven, got %v (%q)", result.status, result.reason)
	testing.expect(t, budget.nsec3.rounds > 0, "a proof that hashed nothing is not exercising this")
	testing.expectf(
		t,
		budget.nsec3.rounds < MAX_NSEC3_ROUNDS_PER_QUERY / 8,
		"an honest name error cost %d of %d rounds, which leaves no room for a deeper one",
		budget.nsec3.rounds,
		MAX_NSEC3_ROUNDS_PER_QUERY,
	)
	free_all(context.temp_allocator)
}

@(test)
test_an_nsec3_name_error_that_runs_out_of_hashing_is_indeterminate :: proc(t: ^testing.T) {
	/*
	One round short of what the whole question costs, so the last hash it needs
	is the one refused - and the last hash belongs to the answer's own proof,
	which runs after the walk. Measured rather than written down, because a
	number here would rot the first time the fixture or the proof changed.
	*/
	measure_v := n3_validator()
	testing.expect(t, measure_v != nil, "the anchor should parse")
	defer destroy_validator(measure_v)

	msg, err := dns.decode_message(n3_reply(), context.temp_allocator)
	testing.expect(t, err == .None, "the fixture should decode")

	whole := Budget{}
	validate_denial(measure_v, &whole, msg, N3_QNAME, .A, .IN, u32(FIXTURE_TIME), time.unix(FIXTURE_TIME, 0), context.temp_allocator)

	// A validator of its own, because what the first call learned about the
	// zone is cached and the second would read the answer rather than work it
	// out.
	v := n3_validator()
	defer destroy_validator(v)
	short := Budget {
		nsec3 = {rounds = MAX_NSEC3_ROUNDS_PER_QUERY - whole.nsec3.rounds + 1},
	}
	result := validate_denial(v, &short, msg, N3_QNAME, .A, .IN, u32(FIXTURE_TIME), time.unix(FIXTURE_TIME, 0), context.temp_allocator)
	testing.expect_value(t, result.status, Status.Indeterminate)
	// Named apart from the signature budget: an operator reading this has to be
	// able to tell which allowance ran out.
	testing.expect_value(t, result.reason, "nsec3 hashing budget spent")
	free_all(context.temp_allocator)
}

/*
A ceiling the allowance cannot pay for is held down, not obeyed.

`dnssec.max_nsec3_iterations` is an operator's number and
`MAX_NSEC3_ROUNDS_PER_QUERY` is this package's, and above
`MAX_NSEC3_ITERATIONS_LIMIT` the second is what answers: the zones a higher
ceiling admits are the ones whose proofs the allowance cannot pay for, so the
setting reads as laxer and acts as SERVFAIL for names that were being served.

Held here, where the arithmetic is, rather than refused wherever the option came
from. A configuration carrying a larger number was legal before this bound
existed, and refusing it would mean a resolver that does not come up after an
upgrade - a worse answer than either of the ones this is choosing between.
*/
@(test)
test_an_iteration_ceiling_past_the_allowance_is_held_down :: proc(t: ^testing.T) {
	v := make_validator(n3_query, nil, Options{max_nsec3_iterations = MAX_NSEC3_ITERATIONS_LIMIT + 1})
	defer destroy_validator(v)
	testing.expect_value(t, v.max_nsec3_iterations, MAX_NSEC3_ITERATIONS_LIMIT)

	under := make_validator(n3_query, nil, Options{max_nsec3_iterations = 10})
	defer destroy_validator(under)
	testing.expect_value(t, under.max_nsec3_iterations, 10)

	// Unset still means the shipped default, which is what `make_validator`
	// has always done with a zero here.
	unset := make_validator(n3_query, nil, Options{})
	defer destroy_validator(unset)
	testing.expect_value(t, unset.max_nsec3_iterations, DEFAULT_MAX_NSEC3_ITERATIONS)
	free_all(context.temp_allocator)
}
