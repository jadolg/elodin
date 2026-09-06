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

  - `migrating.`, one key per algorithm, RSA/SHA-1 (5) beside ECDSA P-256
    (13), each signing the whole zone, and a DS at the parent for each - what
    a zone rolling from one algorithm to the other publishes for as long as
    the roll takes.
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
ROOT_KEY_TAG :: 14607

@(private = "file")
ANCHOR_DIGEST :: "21d7cb2915a6abc7f491ade9ee3ab47258188e726ca1267ef6d68804e22ac010"

@(private = "file")
ROOT_KSK ::
	"0101030dfea371e31ce9bb1378d73366d08db40af5c7ea0db52c3c437f3f3560fe661f4218ee72c56f76d8c36f6f96ca" +
	"a5f22a9b733dd1f96fa94ed82358917136d97e06"

@(private = "file")
ROOT_DNSKEY_SIG ::
	"00300d0000000e106b36ec806955b900390f00daf8ca2ab9eca80e0e68ddbbca0ac0f9904f966d923533c73589aa1d03" +
	"0b857da3eaf806b64ca551a512e3c0eeb92395d5263fc6626044ac67d9e93bcc88443b"

@(private = "file")
MIGRATING_DS_ECDSA :: "30490d02e8cbcb98298e25d9b2aedd34848206933b6ba59a106073e38871bbec999f49ea"

@(private = "file")
MIGRATING_DS_RSA :: "97570502d1e0b6200359432c1f241669602d22ee954cc4abbce14bb4cee0d4eaf880afd3"

@(private = "file")
MIGRATING_DS_SIG ::
	"002b0d0100000e106b36ec806955b900390f00af41cdf64a92de8c160c7203daa1961d48371fdaa5a683c2643fab38b7" +
	"66b8688c8bbb458ad1d30273be8c4d999c5bf6575023e46cc8da143f3fc00833596a31"

@(private = "file")
MIGRATING_ECDSA_KEY ::
	"0101030d462041543b8789bd532ef5227106291251d7244a045a5f28d0f2684a12d7c9331928f870752989773d9473e0" +
	"b31c7411cdd8ee3358917a1f838c5f124a88696a"

@(private = "file")
MIGRATING_RSA_KEY ::
	"0101030503010001b9e8913962cb55549f225841c94b7298c1c5de60781f2e232d9f50a2dff3a3b55b2b8b7be293890c" +
	"4cf375c1cb69e9c42a1d84f8ee0233ad79b5515ad0e0b3aa09ab01ed5e2656e5afdccf57b85cbe5229251dd78d60a697" +
	"91f66ca58abf2aa7256330211f99a9d591a05633936b2043dea92d0651323b7bbda79bf965a8577a6acc085e8ad3a497" +
	"3e6de7f974bfc2813aa2233fdd793ff61dfe008ddc0bf48eece06def05e6e89803135488ed1af13e6432058886c4d06b" +
	"6b912fb730c1d488b510528bfc64164a7378f6eb436b2b90f7058e18be0a3281c4da1368bf70bde55164a7df0281e1e9" +
	"45d548eb4eb7818ab977d531921e1e277815dcb94951b3a7"

@(private = "file")
MIGRATING_DNSKEY_SIG_13 ::
	"00300d0100000e106b36ec806955b9003049096d6967726174696e6700d943291313a0fdf4296396e0d128ed72716d2d" +
	"00e7ac167252f20c82b9d086dc76df7df2107699c9603e2f4a5d9292e9871adda4fd2740a6d0e7b6fcd8bde0d4"

@(private = "file")
MIGRATING_DNSKEY_SIG_5 ::
	"0030050100000e106b36ec806955b9009757096d6967726174696e670012a875e19218aaf8652b89709fc8d73ff3ca61" +
	"66c96e2293d09284065b5746390bde1a27eb0bbf7a97a64b2a3c54fb5425607e67d055523ce597eea09c699fd87653e0" +
	"3dc44183efcf6dc86e2a5c9836b82138ad06bc52d390b7c40c71428e1b681fbe55196291d3224bb335f09894fc425b64" +
	"d748d94bc03b09877e947054ce657dfb2ec3570fa7fa32cd0b592d35238ef5069a96ed8e8bd6a2164fdcf4a7b7daf858" +
	"6845e15bf9b1e928158fafaaf0141bfa8ad696bdf3ff7d77939e642cbbaf33653530cf2883f683f3909a906742f657a7" +
	"bcf3403b0ecb3aa2685635d6cc0d182ac7453c8f5f0075e2a1713b5a4f165891c0c8403946e989e231b02c46b7"

@(private = "file")
MIGRATING_A_SIG_13 ::
	"00010d0100000e106b36ec806955b9003049096d6967726174696e6700859ca5fcb207b84a69d5bc556b720b8dd4a3cf" +
	"a1d7aa9f6c7616aa2223d212b5db3ddfd6bbfd4a3b74d94b6f16e330037fcacaa64f135d186fccd21b8f5d6d4d"

@(private = "file")
MIGRATING_A_SIG_5 ::
	"0001050100000e106b36ec806955b9009757096d6967726174696e67003c22b0b70c0d19b4c01354cf352c24bf128769" +
	"4d9bd1591fe6a9204111b5c43023fc4529547395c1809d73f219b8292a58ac1d327c6ff40a7c4d666598b93c5a1ab186" +
	"07f014e036aecf45c467e0352cbb95d84ebaee34cb51fa40634083f6242b4c92bc36e646662e7491ddc8329fe0bf9418" +
	"0c4828471e305de725523fddf68dade3511e2dc0f338a437f9abc3f2a6ef52c036e72b9e23700f47fcc2d6af3ce2b364" +
	"4092df794b46a23756a3e009b1469c4042abd52ce09d4bd463aeb852b0474f167f3ede4181c16adba9712cd219cbf777" +
	"adb2c06d0236a3c5ae70961edf41e7096a30f41aaeb9e21e506cebe5e1263ac723e01c1f673546ad5de8ee7f3f"

@(private = "file")
LEGACY_DS :: "1ba4050299d38370c3cf98b78b525e24460953ced89259c25edc7b42f93bf8f086812e0c"

@(private = "file")
LEGACY_DS_SIG ::
	"002b0d0100000e106b36ec806955b900390f00cea420877262414866958fba827106cbda5e2d32f6c20ce5367d634f56" +
	"d72cf99ac51f8bf5488633e5bc8141c5a1a4461e33517b29bfa2a51d4872b70bb472a0"

@(private = "file")
LEGACY_KEY ::
	"0101030503010001da49299e117fbd0af3d4c177224d1741c15f9ce6f42950486bceba4b23af45ad3ccf73e0fe7e9219" +
	"8f1c84f325eb9b00314ec8a06d81bc043141518460e56386e599aca3c918d0aef8531cae83dc1e34f25c41df15d220a2" +
	"26f103b4b456e13126a32efe0ee6f320a7cfe87382285860199fb41f29da726a0b250487da983e71818fd7b4d217a6a7" +
	"c5139761146d02e85c6f867fd64fe5e2804de5050a3691f271e78def956a6907443220a9b75afe725a29d6eab32b7aec" +
	"6d293b7c689292073449d5ec6a41df5f5de512e3c66ed323e4e06f0bdf8d7d3a10165a4776784e12fdd7bc034706e5d7" +
	"4a8e6101fb3996dbf804986ad150e9dd432fc5200b097a21"

@(private = "file")
LEGACY_DNSKEY_SIG ::
	"0030050100000e106b36ec806955b9001ba4066c65676163790049bcea4308367289522b2e85dfccd24e65b57b0c3ffb" +
	"5f19a2f0695e5d78a7993fc57699b2ff05bffe042b02edd074681b058d99d218069d88c6fa31ebc316995ff62477ca4b" +
	"6f97be25afed58c6046a5374f9a84baad5fa1c6f23c68be96428634410408d3f7e0b1740d5e2c5e9aec871cdaa5926ed" +
	"0a76adaa835598451223e5a691074b74a11815d550ea1ef76ad1a657cee4a793ca83c33d231856285d3e72442963c6e8" +
	"6c89d802955813e133a6d85f1b081a935b4f934609df782d6d2ce7301f0a6af891ea807096ddb5bd0dba53c765cad009" +
	"cbef91352e4ddd0265d02a899b81f822e72527da7d6ca24474bf26bcf1e7397d26e10ec7971e2618d577"

@(private = "file")
LEGACY_A_SIG ::
	"0001050100000e106b36ec806955b9001ba4066c65676163790094f170fe98782d8a473fc6bc7c97d1410ad3b97a9e88" +
	"87b7de5ab7edcb7f8a048a8af4009466ef574dbbcb59522e3f8d815c50306ec743f4c1414a041808fe1f6c3f725f3bdf" +
	"911678fe45e38d7e413b50128e521795453ad43374aad166a2fa93d1d627fbf1ed445b98e6bc97ce21cc45376349b126" +
	"25449ff2f75668bc77d8a979ae379fd65e9fa1219d685d250769ad3d03ef8c16ad7453d1f3df7b95343cf9abab945831" +
	"5e0bc821d42ffac552ce352c149d48efbcbec356fd433c2b94793b2b7de475d16423be652be306a5c5f58d2623406f04" +
	"4e17d65fdff3b44c7b2ce89009a6b67b7279b9423d8c1bd764a1ba255480fc98982af487977e6ee60a5b"

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

/*
What an attacker on the path to the upstream gets to do to a lookup, which for
this file is one thing: take the signatures off the DNSKEY set of `migrating.`.

That is the cheapest tampering there is - no forgery, nothing to get right -
and the zone it is aimed at is one whose DS set names two algorithms. What must
come back is Bogus: the parent attests a key with an algorithm this build can
check, so a DNSKEY set that will not verify against it is a broken zone and not
an unsigned one.
*/
@(private = "file")
Tamper :: struct {
	strip_migrating_dnskey_signatures: bool,
}

// The DS and DNSKEY lookups the walk makes, and nothing else: a name this chain
// does not describe is a lookup the test did not mean to provoke, so it fails
// rather than answering.
@(private = "file")
chain_query :: proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator) -> (wire: []u8, ok: bool) {
	tamper := Tamper{}
	if ctx != nil {
		tamper = (^Tamper)(ctx)^
	}
	records := make([dynamic]dns.Record, 0, 3, allocator)
	switch {
	case type == .DNSKEY && dns.name_equal_fold(name, "."):
		append(&records, raw_record(".", .DNSKEY, ROOT_KSK, allocator))
		append(&records, raw_record(".", .RRSIG, ROOT_DNSKEY_SIG, allocator))
	case type == .DS && dns.name_equal_fold(name, "migrating."):
		append(&records, raw_record("migrating.", .DS, MIGRATING_DS_ECDSA, allocator))
		append(&records, raw_record("migrating.", .DS, MIGRATING_DS_RSA, allocator))
		append(&records, raw_record("migrating.", .RRSIG, MIGRATING_DS_SIG, allocator))
	case type == .DNSKEY && dns.name_equal_fold(name, "migrating."):
		append(&records, raw_record("migrating.", .DNSKEY, MIGRATING_ECDSA_KEY, allocator))
		append(&records, raw_record("migrating.", .DNSKEY, MIGRATING_RSA_KEY, allocator))
		if !tamper.strip_migrating_dnskey_signatures {
			append(&records, raw_record("migrating.", .RRSIG, MIGRATING_DNSKEY_SIG_13, allocator))
			append(&records, raw_record("migrating.", .RRSIG, MIGRATING_DNSKEY_SIG_5, allocator))
		}
	case type == .DS && dns.name_equal_fold(name, "legacy."):
		append(&records, raw_record("legacy.", .DS, LEGACY_DS, allocator))
		append(&records, raw_record("legacy.", .RRSIG, LEGACY_DS_SIG, allocator))
	case type == .DNSKEY && dns.name_equal_fold(name, "legacy."):
		append(&records, raw_record("legacy.", .DNSKEY, LEGACY_KEY, allocator))
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
chain_validator :: proc(allocator: mem.Allocator, tamper: ^Tamper = nil) -> ^Validator {
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
	return make_validator(chain_query, tamper, Options{anchors = anchors})
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

/*
A DS set that names a refused algorithm beside a checkable one is not an
insecure delegation.

RFC 6840 section 5.2 makes a delegation insecure when the resolver supports
*none* of the algorithms in the DS RRset. `fetch_keys` was reading it as "some
DS named something we cannot check", which is a different set of zones - and a
much larger one once an algorithm can leave `algorithm_supported` at start-up.

`migrating.` is delegated with two DS records, one per algorithm. Take the
signatures off its DNSKEY set - the cheapest tampering on the path to an
upstream, and nothing an attacker has to get right - and the answer is a zone
whose keys are not the keys the parent attests. That is bogus. Reported
insecure it is worse than a failure: `zone_step` caches it for the DS TTL, so
one tampered DNSKEY response takes the whole zone out of validation for as long
as the cache holds it.
*/
@(test)
test_one_refused_ds_does_not_make_a_mixed_delegation_insecure :: proc(t: ^testing.T) {
	runs_rsasha1 := hold_policy()
	defer release_policy(runs_rsasha1)
	refuse_rsasha1()

	tamper := Tamper {
		strip_migrating_dnskey_signatures = true,
	}
	v := chain_validator(context.temp_allocator, &tamper)
	defer destroy_validator(v)

	budget := Budget{}
	status, _, _ := zone_trust(v, &budget, "migrating.", time.unix(FIXTURE_TIME, 0), context.temp_allocator)
	testing.expectf(
		t,
		status == .Bogus,
		"a zone whose DNSKEY set no longer verifies came back %v: the parent attests an ECDSA key, and only the RSA/SHA-1 DS beside it is unusable here",
		status,
	)
	free_all(context.temp_allocator)
}
