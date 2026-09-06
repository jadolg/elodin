package dnssec

import "core:mem"
import "core:sync"
import "core:testing"
import "core:time"
import "elodin:dns"

/*
The algorithm a zone publishes, the algorithm the library will run, and what
happens where the two disagree.

Every other chain in this package is real traffic, captured from a public
resolver, and none of it can pose this question: a real zone is signed with one
algorithm at a time, and the one host that would refuse it - a Fedora or RHEL
build, whose OpenSSL declines SHA-1 signatures outright - is not the host these
tests run on. So the chain below is made rather than captured. A synthetic root
anchors two synthetic zones:

  - `migrating.`, one zone-signing key per algorithm, RSA/SHA-1 (5) beside
    ECDSA P-256 (13), which is what a zone rolling from one to the other
    publishes for as long as the roll takes. Its DS names 13.
  - `legacy.`, signed only with RSA/SHA-1, DS and all. The zone that has not
    rolled yet.

and the refusal is made too: `refuse_rsasha1` sets the bit `probe_algorithms`
would have set on a host whose libcrypto turns algorithm 5 down, which is the
only way to ask this question from an Ubuntu CI runner. The signatures are
genuine - generated outside this implementation, over the canonical form this
package builds - and the tests that run before the refusal is applied are what
say so.

What the pair is for, together: a refusal is a decision about an algorithm
taken before a single signature byte is read, so a forged RRSIG earns one as
readily as the zone's own. Treating a refused signature as though the RRset it
covers were unsigned therefore hands an attacker the second algorithm as a
downgrade - strip the ECDSA signature, alter the records, leave the RSA/SHA-1
one standing, and what reaches the client is unvalidated rather than refused.
That is RFC 6840 section 5.11 inverted. Settling it at the delegation instead,
per section 5.2, is what keeps `legacy.` resolving while `migrating.` stops
being strippable, and both halves are asserted here.
*/

@(private = "file")
CHAIN_TTL :: 3600

// The synthetic root's key-signing key, which the trust anchor below names.
@(private = "file")
ROOT_KEY_TAG :: 45990

@(private = "file")
ANCHOR_DIGEST :: "da6c6ec34a279d18f3b660e0c59ff6e5ba31f652cb7d22ef041bc2d092305daf"

@(private = "file")
ROOT_KSK ::
	"0101030d26732d708c88c10658e933acba97b2aeb02802f68dfeaeade25a24f6c0de04a7a8ceb5e18d544d9cd58aea74" +
	"d3ae12dc1a53e52ac8aecf47fba2108a4c2c87ae"

@(private = "file")
ROOT_DNSKEY_SIG ::
	"00300d0000000e106b36ec806955b900b3a600ee3114e83059419fbbdadcc534e962d53cf47e32e55e96886a541d5f20" +
	"e094c2bc0be9cfd72daba10a67666e2b917d9274fb929e7dbf5f7cd4558deea027d6ce"

@(private = "file")
MIGRATING_DS :: "817a0d0287d9b14bd385e52b823dc6f651f6190469e5c5a06ba619ae8791d1827f086514"

@(private = "file")
MIGRATING_DS_SIG ::
	"002b0d0100000e106b36ec806955b900b3a6004ef7594075a8d8ea000b78c27f45adb34035458ef47cb083f72e677419" +
	"1fd859ee7a1b00c92dcec36cb4a1f9f852d27b796df54f20f9a4c42540325b96fcca22"

@(private = "file")
MIGRATING_KSK ::
	"0101030d49c0614ad48e4778eb788455737b893ac126a4da2ceba37e95a04a3209640701f1e2df9c1dbca107d8c553fc" +
	"a6b5131f19f934275cb3712c2e48bd8abc62e822"

@(private = "file")
MIGRATING_ZSK ::
	"0100030503010001abbf27f685cd3bb80662f09b639379716220d619cee4d5cc3665b8fe22ec01cade75e06379e349e8" +
	"75f2e21c9f4f945883f40ddaad99a3a26b16a3f1f1dca4b4dfa13cd155f7e00593f6ae932f62466af7375f07f2503508" +
	"7ded092a2bcf76c76783dd1fe9cb25658854022ad56fd2270378d05b1d2a9f80f7fa85d09a3096976758aef6d413f39a" +
	"11a0a5a683a14a887c5e23bc2dd556d7df9d95f57aecfb060b2575f02c375fe5b1e02cc75ccf2c1cb5eef5ae24be946e" +
	"8163a17f0f6d3958bed81aeea8a262100abcb0ddefdfee6686d9b37f83d7fb8b820fdacad88f6e14a26902fb90c8fd5c" +
	"0091b6ed641bd65985114f871a23d2e7b2cb4b3060f9ec6d"

@(private = "file")
MIGRATING_DNSKEY_SIG ::
	"00300d0100000e106b36ec806955b900817a096d6967726174696e67006ea0b58e6dcbaf18fdcd95cc232c712aecbe3c" +
	"8867d71743be0bff25821a43be8ca6d69a1c833bf43b2c5d912cb05844e97d0db5c31618c954133c940fea3e38"

@(private = "file")
MIGRATING_A_SIG_13 ::
	"00010d0100000e106b36ec806955b900817a096d6967726174696e670067e8e1d901d8046bd0c2be8d86bf1d1323f974" +
	"0428d887dd4b3ddcec84958c7641df952d5f460fd29ea0c7e8ceb78a32123e09e972fc2abc47a74ad6e34baa53"

@(private = "file")
MIGRATING_A_SIG_5 ::
	"0001050100000e106b36ec806955b9003667096d6967726174696e6700965050d4172179ff3fabd796d20d05e809c690" +
	"5c25fbaafd2d6c2bb2447e9157ee32965780ccfbc26f7efa74d744bbe079b7490f206654cbee38d3c89b10ac8663c683" +
	"a37728b71eb407dea91a02ff3781a0f7a054ee2882c5e5fa616d421910af76805974c48c0cbb20a6dbb905aa6efbcd71" +
	"ba1ab93b9617c04cb73bc50b1c79bd988e3a826d599576f9c84a6a8f361ccc7890e5d525bf5a3126f05b8569ca4a9edd" +
	"4f88f488ab7880c7f063793972a94ae879314d500129bb62f4fdd5cafbe4f1086159e615f7ef12b43910caec1e03812b" +
	"ec354d580a8fcdbcd54adc1c333b9fb2067deb02c17abe19fb6d0f9d78889a1611ba801af89a18453c33586000"

@(private = "file")
LEGACY_DS :: "20b60502d83d7ee68aefeae083e51a2e71d992107751d373b3dd71611f65debce0e789d5"

@(private = "file")
LEGACY_DS_SIG ::
	"002b0d0100000e106b36ec806955b900b3a600de976289164086a851a52f197c0ed1fae320ffade5c1f5f46a71ae5978" +
	"373ebd8a3387e972a8811fe29cb7da97ec6e6a13a826a045513dbc355a62f3e5ee90cf"

@(private = "file")
LEGACY_KSK ::
	"01010305030100018f8e45c3fcd84f5e7d307ea1a0288930ccf8ff80a67351a82520a003d2ca172be3c87147b04dbe19" +
	"86a56f79003a0bc0d5c4159ecc78c1f79afa3aa524894514d64d3749ba50f8a1b5b40f39914ea81bb5afc9303c931700" +
	"f25663a62fe23aae095fdc3149461bc4e6a994261ab1955c1e33b468ec546ef11e4824f1811c3922381d2dc5bcd77fc3" +
	"e20f1e5f9a450669bb0ed814e252eb0523e9506024a94658f297a4ebb9e0d06ade97475d4413988b046afae28eb5a499" +
	"556be0062fe39ce7af3185252f32140289fb4b8e60eb1cd0f463e52e4d76b408a1521359d5e48426196f4bb2bfe5a6fc" +
	"692464f4d12c52bd1ba5f8d911d4bc104b61804eba173687"

@(private = "file")
LEGACY_DNSKEY_SIG ::
	"0030050100000e106b36ec806955b90020b6066c6567616379006464139f579e7c0dbb7fb3a2f827e9b14c22bab42623" +
	"b417f85f9fa7cd2ba93f57394b830ba2de8c3bbce5bfd4f67f288f6af48facc8d127dc42b0814141e44cd4072122668c" +
	"2e78bf969a1969b3cde98ff13984ead21d94ab71ce4254c7f1d07aeea8069ca23c073cc383a383ffd4fff9cb767103ab" +
	"04f15a9f7bcaa330d7dd8f29dc8c758a4a3dd642599968dc9af54124ca6304bb328f23927c6be0519fc2475f1ddf15e3" +
	"0880969b5a369a1df4902fbd6940a1e20d2de4ce3be4f77da3477eb5db219ff36f7116990d28051d3512bafa85ce1dae" +
	"06511ace7a26c22a5c9068b87c5ccfe2f201122c67ea2d9c6d5f1ceeb711ed7e910a08bd961c6c4a3923"

@(private = "file")
LEGACY_A_SIG ::
	"0001050100000e106b36ec806955b90020b6066c6567616379002ca38dcae44b2641cf7fcd3e21c4a80dfbf3df4f0c2f" +
	"9bbbc1d7427f6f06e64c6aaf1f8cd3400b42c6490a0ed22b556de428c39f7c719edfd232c765103aa27508966b77fb72" +
	"afa26872b452415e9360c1241859d29d709e0dce714563ee09d394b3942ff1dafd528918a530e3454af0fc61bb7cf5bd" +
	"3a4d302abed8390a80c7fd0c33dffdb99e0a87c154dab66bfc2115be4d6b9f35db6fcf2f5c22cb9f85620a2cbccdb9d8" +
	"20ada59a1c760c74a447b125d3ac725b4b86c9e0bf35115d75ada54e7fe800d82dc16cacde9db4221dd628dfa9f4139f" +
	"c25b8aefc9473ef69e0f851c7694b7c187e5af071e47aac1d9a087a3e4fa0b14bd1636b0d2e5600308bf"

// ---------------------------------------------------------------------------
// Serving the chain
// ---------------------------------------------------------------------------

@(private = "file")
raw_record :: proc(name: string, type: dns.Type, rdata_hex: string, allocator: mem.Allocator) -> dns.Record {
	rdata, ok := decode_hex(rdata_hex, allocator)
	if !ok {
		panic("a fixture record is not hex")
	}
	return dns.Record{name = name, type = type, class = .IN, ttl = CHAIN_TTL, data = dns.Rdata_Raw{data = rdata}}
}

@(private = "file")
message :: proc(qname: string, qtype: dns.Type, answer: []dns.Record, allocator: mem.Allocator) -> []u8 {
	question := make([]dns.Question, 1, allocator)
	question[0] = dns.Question {
		name  = qname,
		type  = qtype,
		class = .IN,
	}
	msg := dns.Message {
		id       = 0x2660,
		question = question,
		answer   = answer,
	}
	msg.flags.qr = true
	msg.flags.rd = true
	msg.flags.ra = true
	out, _, err := dns.encode_message(msg, allocator, dns.MAX_MESSAGE)
	if err != .None {
		panic("a fixture response did not encode")
	}
	return out
}

// The DS and DNSKEY lookups the walk makes, and nothing else: a name this chain
// does not describe is a lookup the test did not mean to provoke, so it fails
// rather than answering.
@(private = "file")
chain_query :: proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator) -> (wire: []u8, ok: bool) {
	records := make([dynamic]dns.Record, 0, 3, allocator)
	switch {
	case type == .DNSKEY && dns.name_equal_fold(name, "."):
		append(&records, raw_record(".", .DNSKEY, ROOT_KSK, allocator))
		append(&records, raw_record(".", .RRSIG, ROOT_DNSKEY_SIG, allocator))
	case type == .DS && dns.name_equal_fold(name, "migrating."):
		append(&records, raw_record("migrating.", .DS, MIGRATING_DS, allocator))
		append(&records, raw_record("migrating.", .RRSIG, MIGRATING_DS_SIG, allocator))
	case type == .DNSKEY && dns.name_equal_fold(name, "migrating."):
		append(&records, raw_record("migrating.", .DNSKEY, MIGRATING_KSK, allocator))
		append(&records, raw_record("migrating.", .DNSKEY, MIGRATING_ZSK, allocator))
		append(&records, raw_record("migrating.", .RRSIG, MIGRATING_DNSKEY_SIG, allocator))
	case type == .DS && dns.name_equal_fold(name, "legacy."):
		append(&records, raw_record("legacy.", .DS, LEGACY_DS, allocator))
		append(&records, raw_record("legacy.", .RRSIG, LEGACY_DS_SIG, allocator))
	case type == .DNSKEY && dns.name_equal_fold(name, "legacy."):
		append(&records, raw_record("legacy.", .DNSKEY, LEGACY_KSK, allocator))
		append(&records, raw_record("legacy.", .RRSIG, LEGACY_DNSKEY_SIG, allocator))
	case:
		return nil, false
	}
	return message(name, type, records[:], allocator), true
}

// One A record at a zone apex, with whichever of its signatures the caller left
// on it. `addr` is what the attacker gets to choose.
@(private = "file")
apex_answer :: proc(zone: string, addr: [4]u8, sigs: []string, allocator: mem.Allocator) -> []u8 {
	records := make([dynamic]dns.Record, 0, 1 + len(sigs), allocator)
	append(
		&records,
		dns.Record{name = zone, type = .A, class = .IN, ttl = CHAIN_TTL, data = dns.Rdata_A{addr = addr}},
	)
	for sig in sigs {
		append(&records, raw_record(zone, .RRSIG, sig, allocator))
	}
	return message(zone, .A, records[:], allocator)
}

@(private = "file")
chain_validator :: proc(allocator: mem.Allocator) -> ^Validator {
	digest, ok := decode_hex(ANCHOR_DIGEST, allocator)
	if !ok {
		panic("the trust anchor is not hex")
	}
	anchors := make([]Trust_Anchor, 1, allocator)
	anchors[0] = Trust_Anchor {
		zone = ".",
		ds = Ds {
			key_tag = ROOT_KEY_TAG,
			algorithm = ALG_ECDSAP256SHA256,
			digest_type = DIGEST_SHA256,
			digest = digest,
		},
	}
	return make_validator(chain_query, nil, Options{anchors = anchors})
}

// ---------------------------------------------------------------------------
// Standing in for a host whose crypto policy refuses an algorithm
// ---------------------------------------------------------------------------

/*
The policy table is one table for the whole package, and the test runner runs
tests on four threads. Everything that writes it holds this, so that a test
asking what a refusing host does cannot be read by a test asking what this host
does.
*/
@(private = "file")
policy_lock: sync.Mutex

// Take the table, and answer whether this build's libcrypto runs RSA/SHA-1 at
// all - on a host that already refuses it there is nothing to restore, and the
// checks that need it running have nothing to say.
@(private = "file")
hold_policy :: proc() -> (runs_rsasha1: bool) {
	sync.mutex_lock(&policy_lock)
	probe_algorithms()
	return algorithm_supported(ALG_RSASHA1)
}

@(private = "file")
release_policy :: proc(runs_rsasha1: bool) {
	if runs_rsasha1 {
		sync.atomic_and(&refused_algorithms, ~algorithm_bit(ALG_RSASHA1))
	}
	sync.mutex_unlock(&policy_lock)
}

// Exactly what `run_probe` does on a host whose OpenSSL declines SHA-1
// signatures, and the only part of that host this test needs.
@(private = "file")
refuse_rsasha1 :: proc() {
	sync.atomic_or(&refused_algorithms, algorithm_bit(ALG_RSASHA1))
}

// ---------------------------------------------------------------------------
// The probe
// ---------------------------------------------------------------------------

/*
Every vector in `ALGORITHM_PROBES` is one the library gives a verdict on.

The probe reads a failure as the library declining the algorithm, so a vector
that had gone stale - a typo, a key and a signature that never belonged
together - would be indistinguishable from a crypto policy, and would quietly
take the algorithm out of `algorithm_supported` on every host. `Bad` is what
that looks like, and it is the one answer no probe vector may produce.

`verify_now` rather than `verify_signature`: the question is what the library
does, and `verify_signature` would answer from the table this is checking.
*/
@(test)
test_no_probe_vector_can_be_rejected_as_a_forgery :: proc(t: ^testing.T) {
	data, data_ok := decode_hex(PROBE_DATA, context.temp_allocator)
	testing.expect(t, data_ok, "the probe's own message is not hex")

	for probe in ALGORITHM_PROBES {
		key, key_ok := decode_hex(probe.key, context.temp_allocator)
		signature, sig_ok := decode_hex(probe.signature, context.temp_allocator)
		if !testing.expectf(t, key_ok && sig_ok, "%s: the probe vector is not hex", probe.name) {
			continue
		}
		result := verify_now(probe.algorithm, key, signature, data, context.temp_allocator)
		testing.expectf(
			t,
			result == .Ok || result == .Refused,
			"%s (algorithm %d): the probe vector came back %v. `Bad` means the vector is wrong rather than the library unwilling, and a wrong vector drops the algorithm on every host",
			probe.name,
			probe.algorithm,
			result,
		)
	}
	free_all(context.temp_allocator)
}

/*
What the table reports is what the library did, algorithm by algorithm.

This is the whole point of probing: `algorithm_supported` used to answer for
what this codebase implements, which on a host whose OpenSSL refuses SHA-1 is
not the same list. Both directions are asserted, because both are load-bearing
- an algorithm reported supported that the library will not run leaves the
RFC 6840 section 5.11 downgrade open, and one reported unsupported that it
would run degrades a zone to insecure for no reason.
*/
@(test)
test_the_table_reports_what_the_library_answered :: proc(t: ^testing.T) {
	sync.mutex_lock(&policy_lock)
	defer sync.mutex_unlock(&policy_lock)
	probe_algorithms()

	data, _ := decode_hex(PROBE_DATA, context.temp_allocator)
	for probe in ALGORITHM_PROBES {
		key, _ := decode_hex(probe.key, context.temp_allocator)
		signature, _ := decode_hex(probe.signature, context.temp_allocator)
		ran := verify_now(probe.algorithm, key, signature, data, context.temp_allocator) == .Ok
		testing.expectf(
			t,
			algorithm_supported(probe.algorithm) == ran,
			"%s (algorithm %d): the library %s it, the table says %v",
			probe.name,
			probe.algorithm,
			"verified" if ran else "would not verify",
			algorithm_supported(probe.algorithm),
		)
	}

	for probe in DIGEST_PROBES {
		out: [64]u8
		want, _ := decode_hex(probe.want, context.temp_allocator)
		size := digest_size(probe.digest_type)
		computed := digest(probe.digest_type, nil, out[:size])
		matched := computed && mem.compare(out[:size], want) == 0
		testing.expectf(
			t,
			digest_supported(probe.digest_type) == matched,
			"%s (digest type %d): the library %s it, the table says %v",
			probe.name,
			probe.digest_type,
			"computed" if matched else "would not compute",
			digest_supported(probe.digest_type),
		)
	}
	free_all(context.temp_allocator)
}

// An algorithm nobody implements is not an algorithm anybody refused, and the
// difference decides whether a zone is unresolvable or merely unvalidated.
@(test)
test_an_unimplemented_algorithm_is_not_a_refused_one :: proc(t: ^testing.T) {
	probe_algorithms()
	for algorithm in ([]u8{0, 1, 2, 3, 4, 6, 9, 11, 12, 17, 99, 253, 254, 255}) {
		testing.expectf(t, algorithm_bit(algorithm) == 0, "algorithm %d is not implemented", algorithm)
		testing.expectf(t, !algorithm_supported(algorithm), "and the table should agree about %d", algorithm)
	}
	testing.expect(t, !digest_supported(3), "GOST is not a digest this build computes")
	testing.expect(t, !digest_supported(0), "nor is the reserved zero")
}

// ---------------------------------------------------------------------------
// The downgrade
// ---------------------------------------------------------------------------

/*
A signature the library refuses cannot make the RRset it covers unsigned data.

The forgery here is the cheapest one there is. The attacker alters the address,
drops the ECDSA signature - the one this build can check - and leaves the
zone's own RSA/SHA-1 signature exactly as it was published: key tag, algorithm
and validity window all genuine, so `signature_worth_trying` spends a
verification on it, and the signature bytes it no longer matches are never
looked at, because the refusal is decided before them.

Before the probe existed this came back `Insecure`, which is an answer the
resolver forwards to the client with nothing but the AD bit cleared. The zone
had said, by publishing two algorithms, that it wanted the surviving one
believed; treating what is left as unsigned believes the attacker instead.
*/
@(test)
test_a_refused_signature_does_not_downgrade_an_altered_rrset :: proc(t: ^testing.T) {
	now := time.unix(FIXTURE_TIME, 0)
	published := []string{MIGRATING_A_SIG_13, MIGRATING_A_SIG_5}
	rsa_only := []string{MIGRATING_A_SIG_5}
	genuine := [4]u8{192, 0, 2, 1}
	altered := [4]u8{198, 51, 100, 1}

	runs_rsasha1 := hold_policy()
	defer release_policy(runs_rsasha1)

	/*
	First, with nothing refused: the fixture is a real dual-signed zone and the
	RSA/SHA-1 signature really does carry the set on its own. Without this the
	test below could pass against a signature that was never valid in the first
	place, which would prove nothing about refusals.
	*/
	if runs_rsasha1 {
		v := chain_validator(context.temp_allocator)
		defer destroy_validator(v)
		both := validate(v, "migrating.", .A, apex_answer("migrating.", genuine, published, context.temp_allocator), now)
		testing.expectf(t, both.status == .Secure, "the zone as published did not validate: %v, %s", both.status, both.reason)
		alone := validate(v, "migrating.", .A, apex_answer("migrating.", genuine, rsa_only, context.temp_allocator), now)
		testing.expectf(
			t,
			alone.status == .Secure,
			"the RSA/SHA-1 signature does not carry the set on its own: %v, %s",
			alone.status,
			alone.reason,
		)
	}

	refuse_rsasha1()
	v := chain_validator(context.temp_allocator)
	defer destroy_validator(v)

	// The zone still validates. Its DS names ECDSA, so refusing algorithm 5
	// costs a mid-migration zone nothing at all.
	untouched := validate(v, "migrating.", .A, apex_answer("migrating.", genuine, published, context.temp_allocator), now)
	testing.expectf(
		t,
		untouched.status == .Secure,
		"refusing one of a zone's two algorithms broke the zone: %v, %s",
		untouched.status,
		untouched.reason,
	)

	stripped := validate(v, "migrating.", .A, apex_answer("migrating.", altered, rsa_only, context.temp_allocator), now)
	testing.expectf(
		t,
		stripped.status == .Bogus,
		"an altered RRset left with only a refused signature came back %v (%s): the client is being handed a forgery as unvalidated data",
		stripped.status,
		stripped.reason,
	)
	testing.expect_value(t, stripped.reason, "no signature this build can verify")
	free_all(context.temp_allocator)
}

/*
A zone signed only with a refused algorithm keeps resolving.

The other half, and the reason the refusal was ever kept apart from an
unimplemented algorithm: a zone that has done nothing wrong must not become
unresolvable on one distribution and fine on every other. RFC 6840 section 5.2
puts that decision at the DS, and putting it there is what lets the RRset
inside a secure zone be judged strictly - so this test and the one above hold
each other in place.

`legacy.` publishes a single RSA/SHA-1 key and a DS that names it. With the
algorithm refused there is no usable DS, the delegation is insecure, and the
answer is unvalidated data rather than a SERVFAIL.
*/
@(test)
test_a_zone_signed_only_with_a_refused_algorithm_stays_insecure :: proc(t: ^testing.T) {
	now := time.unix(FIXTURE_TIME, 0)
	sigs := []string{LEGACY_A_SIG}
	addr := [4]u8{192, 0, 2, 2}

	runs_rsasha1 := hold_policy()
	defer release_policy(runs_rsasha1)

	// Signed, and provably so, before the refusal is what explains the verdict.
	if runs_rsasha1 {
		v := chain_validator(context.temp_allocator)
		defer destroy_validator(v)
		got := validate(v, "legacy.", .A, apex_answer("legacy.", addr, sigs, context.temp_allocator), now)
		testing.expectf(t, got.status == .Secure, "the legacy zone did not validate: %v, %s", got.status, got.reason)
	}

	refuse_rsasha1()
	v := chain_validator(context.temp_allocator)
	defer destroy_validator(v)

	got := validate(v, "legacy.", .A, apex_answer("legacy.", addr, sigs, context.temp_allocator), now)
	testing.expectf(
		t,
		got.status == .Insecure,
		"a zone whose only algorithm this host refuses came back %v (%s) rather than insecure: it resolves everywhere but here",
		got.status,
		got.reason,
	)
	testing.expect_value(t, got.reason, "unsigned zone")
	free_all(context.temp_allocator)
}

/*
And it is the delegation that settles it, not the zone underneath.

The verdict above would look the same if the walk had gone down into `legacy.`,
fetched its DNSKEY set, tried the RSA/SHA-1 signature over it, been refused and
called the zone insecure on the way back out - `fetch_keys` reads a refusal that
way too. The difference is where the decision is made, and the difference is
the point: RFC 6840 section 5.2 puts it at the DS, and a delegation whose every
DS names something this build cannot check is insecure before any of the zone's
own records are read.

The meter is what says which of the two happened. Two verifications reach this
answer - the root's signature over its DNSKEY set, and the root's signature
over the DS set - and a third would mean the DS was walked past and the zone
below it asked, which is `algorithm_supported` no longer answering for what the
library will run.
*/
@(test)
test_a_refused_algorithm_is_settled_at_the_delegation :: proc(t: ^testing.T) {
	runs_rsasha1 := hold_policy()
	defer release_policy(runs_rsasha1)
	refuse_rsasha1()

	v := chain_validator(context.temp_allocator)
	defer destroy_validator(v)

	budget := Budget{}
	status, _, established := zone_trust(v, &budget, "legacy.", time.unix(FIXTURE_TIME, 0), context.temp_allocator)
	testing.expectf(t, status == .Insecure, "the delegation to legacy. came back %v", status)
	testing.expect_value(t, established, "legacy.")
	testing.expectf(
		t,
		budget.verifications == 2,
		"reaching an insecure delegation cost %d verifications rather than 2: the DS was walked past and the zone below it asked",
		budget.verifications,
	)
	free_all(context.temp_allocator)
}
