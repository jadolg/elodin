package dnssec

import "core:mem"
import "core:sync"
import "elodin:logx"

/*
Which algorithms and digests this build can actually check something with.

Two separate things decide that, and DNSSEC needs them answered as one. The
first is what `crypto.odin` implements, which is fixed when the binary is
built. The second is what the libcrypto it was linked against will consent to
run: Fedora and RHEL ship an OpenSSL whose crypto policy refuses SHA-1
signatures outright, so `EVP_DigestVerifyInit` declines algorithms 5 and 7 on
those hosts and returns `.Refused` before a signature byte is read.

Answering the two separately is what made the second one dangerous. An
algorithm we never implemented settles the question at the delegation, where
RFC 6840 section 5.2 puts it: no DS names anything we can check, so the child
is an insecure delegation and everything under it is unvalidated data that
nobody claims otherwise about. An algorithm the *library* declined used to be
noticed much later, inside a zone the chain had already established as secure,
and treated as unsigned there - which is RFC 6840 section 5.11 inverted. A zone
mid-migration publishes an RRSIG per algorithm, so an attacker had only to
strip the one this build can verify, alter the records, and leave the
algorithm-5 signature standing: the refusal is a policy decision made before
the bytes are looked at, so a forgery earned it exactly as a genuine signature
would, and the altered RRset reached the client as merely unvalidated instead
of refused. The whole point of the second algorithm, inverted.

So the two are one answer here, and it is reached by asking rather than by
assuming: `probe_algorithms` verifies one known-good signature per algorithm
against the linked library at start-up and drops whatever it will not run.
What is left is what `algorithm_supported` reports, which is what the DS
usability checks in `zone_step` and `fetch_keys` read - so a refused algorithm
now goes insecure at the delegation, in front of the zone, and no RRset inside
an established zone is ever left resting on a signature this build cannot
check. A zone publishing only a refused algorithm keeps resolving exactly as it
did before; a zone publishing one beside a supported one stops being
strippable.

The digest half of the table answers for DS digests and for those only.
NSEC3's iterated hash is SHA-1 by definition (RFC 5155) and `nsec3.odin` calls
`digest` for it directly: there is no second algorithm to fall back on and no
verdict to reach, so a library that could not compute SHA-1 at all would leave
every NSEC3 denial unprovable whatever this table said. Nothing has been seen
to do that - crypto policies restrict what a signature may be made with, not
what may be hashed - and the probe is here so that the DS path does not have to
assume it.

What this does not cover is a policy that turns an algorithm down for something
about a particular key rather than for the algorithm itself. The concrete one
is a minimum RSA modulus - OpenSSL's FIPS provider has such a floor - against a
zone whose key is smaller than it: the probe verifies its 2048-bit vector,
reports RSA runnable, and the zone's own key is then declined at
`EVP_DigestVerifyInit`. Inside a zone the chain has established, that comes
back Bogus rather than insecure. It is the safe direction of the two and the
only one available: a refusal arriving at an RRset inside a secure zone cannot
be told apart from a stripped signature, which is why section 5.11 asks for
Bogus there.

A second, smaller RSA vector would not move that case to the delegation where
it belongs. This table holds one bit per algorithm and knows nothing of key
sizes, so requiring both vectors to verify would refuse RSA outright on such a
host - taking every 2048-bit zone with it to spare the 1024-bit ones. Answering
it properly means asking about the key in hand rather than about the algorithm,
at the DS, which is a larger change than a vector.
*/

/*
Bits set for algorithms and digests the probe found the library would not run.

Read from every validating worker and written once, so both go through
`sync.atomic_load`. Zero until `probe_algorithms` has run, which means an
unprobed build reports exactly the table it implements - the behaviour this
package had before the probe existed.
*/
@(private)
refused_algorithms: u32

@(private)
refused_digests: u32

// Non-zero for the algorithms `verify_signature` implements, one bit each.
@(private)
algorithm_bit :: proc "contextless" (algorithm: u8) -> u32 {
	switch algorithm {
	case ALG_RSASHA1:
		return 1 << 0
	case ALG_RSASHA1_NSEC3:
		return 1 << 1
	case ALG_RSASHA256:
		return 1 << 2
	case ALG_RSASHA512:
		return 1 << 3
	case ALG_ECDSAP256SHA256:
		return 1 << 4
	case ALG_ECDSAP384SHA384:
		return 1 << 5
	case ALG_ED25519:
		return 1 << 6
	case ALG_ED448:
		return 1 << 7
	}
	return 0
}

// The same for the DS digests, which `digest` computes.
@(private)
digest_bit :: proc "contextless" (digest_type: u8) -> u32 {
	switch digest_type {
	case DIGEST_SHA1:
		return 1 << 0
	case DIGEST_SHA256:
		return 1 << 1
	case DIGEST_SHA384:
		return 1 << 2
	}
	return 0
}

algorithm_supported :: proc "contextless" (algorithm: u8) -> bool {
	bit := algorithm_bit(algorithm)
	return bit != 0 && sync.atomic_load(&refused_algorithms) & bit == 0
}

// Implemented here, and turned down by the library: the one case where
// `verify_signature` has an answer without asking libcrypto for one.
@(private)
algorithm_refused :: proc "contextless" (algorithm: u8) -> bool {
	bit := algorithm_bit(algorithm)
	return bit != 0 && sync.atomic_load(&refused_algorithms) & bit != 0
}

digest_supported :: proc "contextless" (digest_type: u8) -> bool {
	bit := digest_bit(digest_type)
	return bit != 0 && sync.atomic_load(&refused_digests) & bit == 0
}

@(private)
probe_once: sync.Once

/*
Ask the linked libcrypto which of the algorithms above it will run.

Safe to call from any thread and any number of times; only the first call does
anything. `make_validator` calls it, so no validation can run against an
unprobed table, and `start_validator` calls it too - early, and while there is
still a log to say something on.
*/
probe_algorithms :: proc() {
	sync.once_do(&probe_once, run_probe)
}

/*
One algorithm, and a signature over `PROBE_DATA` that is known to be good.

Each was produced outside this implementation and verifies on a library with no
policy in the way, so a probe that fails is the library declining rather than a
vector gone stale - `test_no_probe_vector_can_be_rejected_as_a_forgery`
holds that end up. Algorithms 5 and 7 differ only in what the zone is allowed
to use them for and share the one RSA/SHA-1 vector.
*/
@(private)
Algorithm_Probe :: struct {
	algorithm: u8,
	name:      string,
	key:       string,
	signature: string,
}

// "elodin dnssec algorithm probe". Nothing about it matters except that every
// vector below was signed over exactly these bytes.
@(private)
PROBE_DATA :: "656c6f64696e20646e7373656320616c676f726974686d2070726f6265"

@(private)
PROBE_RSA_KEY ::
	"03010001b5c53b9bdc95bb838a1e8c5b902bf449f300e8187971c8d361fb6b21c4179d50ede3a1200235e477a4791f7dff" +
	"aba523bc170eeb244d9d53b2d413f9dd5d0842757090ab0d04a3bb6b9c961158921647176038a57b77b2d66fa4e4b890dc" +
	"85b3828718dd400505e97d08ff1f3019c2dcc9f1c2ec2a89fa0e1fe083d6d4550e047a67a055d9a139ae49b4525c73e269" +
	"b1079d70d663ff2b8b5ddde1464561bf9cee06801b5a7064d82a9b5611fc0e3a58064104b8e37496078f4937e631f203a9" +
	"1e896b7be19d190b865bac6f208e9b6515cd88892d3ca0452f74a8e5eb915b1ad5011f671f6bfb316666b156fdf52274b1" +
	"9f294847582872cb4fa85abb352859"

@(private)
PROBE_RSA_SHA1_SIG ::
	"60514ea6af984410798715405c5ce493841597e0daf7a2cab39097f42ea2bef19f577f53542d8f8a357472f6326760eba" +
	"ab7f33b3f4b4e6fab61838cc1cd12c9c38913153b0f6f2f1c8a36ded4e5b4b7eb6cf7b1ec1449622653035a6b48fa5868" +
	"956ab08091f48b46046366592d426a7bcd95b87f0f43d268b38b5468aecd0787997123f155a78df074439e5458cfeb1c6" +
	"a95b26ee424e978ee3e8e3aa802e1b478ceeb695013b6a8571582af3b7ba9372e6725b0cf6de689582d4640cd8e697e3a" +
	"50890892b4f02ea4de007edad7cb98af9a0e01f63caf460e3906df57a596a0ad7a92e6827d10a0c547f9738a2d83846aa" +
	"f6b714aab526c411bb81f2dc161"

@(private)
PROBE_RSA_SHA256_SIG ::
	"a5e1a51df0aad5537c6c32a0b6cfb2c72fa9732ce2963490b72ba29275f395f26e140be03f10bba7f1aef6b24ceb9105" +
	"bc8b5349ea7be5a8af8e594371494368793915757a87f81b6471eaffa839cbcdce54e0a7f3f6599fda1f978f6e87329e" +
	"d9e987adee5b4d4f39bc7f3202c58bf88a97589b6a14acdb817934f6baa513ce15b6658922fcef7aa0d31f5517775c4c" +
	"908e973bd1d0845844f9c4bacc07ff0aef11f3cef56f6c8375d033bb22bfb63d65ff746d82d7cfa199dce00c35fd2dd8" +
	"fbdfe024ba6cfe36a2ce25aab3c328ddfeb0ae9997b0fbf8b2d011c760c6457b2acd107a0ff8bebd653b5184755ba2f4" +
	"bee2dbf61410451c112ed24982bd0106"

@(private)
PROBE_RSA_SHA512_SIG ::
	"0a0266adc7c4cc5fe7e6abcff77633f7cfa8078e9182a63698d8e5514738c4e30354e684f40dd8fb47afb3214540755" +
	"517194a9eff526d7361de9638006d4c2e6f799a3616d1b2da6690bf0f924de988c9c5f26d898e72521579e4c0b92988" +
	"1ce7fd45e7650862da9c2d14c504c86d3216dee7413be76e00db59b81f6fa2ed511889e0d7e00b59589f83d24aa67fe" +
	"d5c51e15ab91558c1da87900bea0e44d42faca155ee166fc4fd7cb30c620cd8ce5314f3a0593591d6c204c2a5b0337b" +
	"0cb6db5035af19385b69d75278fac6aa4841dd4c1d9d200d3d9986f949b797c85839da62a0d677845341014d77995c5" +
	"f4a1b1fc404cad175d5527a1402fba9670091"

@(private)
PROBE_P256_KEY ::
	"af8d39015f08a412cdf07efd72ab3e464c3169157afb34003aae25781caaa9af" +
	"fdf8c3ef22899063904189b123e7bf5742e2337af1251059534e0e43e424c585"
@(private)
PROBE_P256_SIG ::
	"04752e63be8a02dd84b8740e4defbc798b1165a060c59cd4368d32a3320204a6" +
	"41ff6b134b7f4947eda7df065591376efcb1c9c933ef0e27f4acc894b9086074"

@(private)
PROBE_P384_KEY ::
	"59d4f4af5e70dc037499ba155632a423297a3a692ed07681a6c79bed4b2466ae" +
	"bb8a6b980640696dc984e01ddb0ee6c63e6165019cb7c5dab7d1a5c5c2211d35" +
	"1037e4a4b32edda9b586f6a06cd9c93c894359235713df37072b450efd8fe934"
@(private)
PROBE_P384_SIG ::
	"b2a36b0749020dc74f056aa191aa51edad5806d24799a2679c25ed21108ab24a" +
	"38018ce3eb0833f3a8cc388ff0bc75b7a418ce07e36506847dc3b4ee82c32759" +
	"01153e5eb5ab3bc001af19ff0ca18ea612b05b50e2ba9ad5501dedeaf7711970"

@(private)
PROBE_ED25519_KEY :: "a7a988ce384f0896069d02711a8fe5cfc4e63f1fa169474b3ea531ffa0af90a5"
@(private)
PROBE_ED25519_SIG ::
	"b322d23468ee9e08f9c647f4afb40ca5ed9110383ec5c9dc75659d2c248f02d1" +
	"b3513cbfe81075794da1c7a1ea7f89857d059a2dc67409b2618b976ef273f80c"

@(private)
PROBE_ED448_KEY ::
	"435d66a62f5eea468e105e7e2f96d8be46d025cba55d8821dd8ce8d619b49cc4" + "0776e9734f853fd9d5820777ee673b97634b8ea97773b40100"
@(private)
PROBE_ED448_SIG ::
	"480888267c352d2fd4eb037c93d3ab20fc2c853f30c5e4950db2ecd8a82ab9f2" +
	"20a878946923e2e6add5d7bcebd918864f57f48fe4fef82000780c25ef3ce17a" +
	"0fdcb1c9c59adf0efbdb2968c95a312d9b1bc13a78915d7ba0d7bc5d3c85251c" +
	"7b03ac61fd55557c03fbad05a3adfdff3700"

@(private)
ALGORITHM_PROBES := []Algorithm_Probe {
	{ALG_RSASHA1, "RSA/SHA-1", PROBE_RSA_KEY, PROBE_RSA_SHA1_SIG},
	{ALG_RSASHA1_NSEC3, "RSA/SHA-1 (NSEC3)", PROBE_RSA_KEY, PROBE_RSA_SHA1_SIG},
	{ALG_RSASHA256, "RSA/SHA-256", PROBE_RSA_KEY, PROBE_RSA_SHA256_SIG},
	{ALG_RSASHA512, "RSA/SHA-512", PROBE_RSA_KEY, PROBE_RSA_SHA512_SIG},
	{ALG_ECDSAP256SHA256, "ECDSA P-256/SHA-256", PROBE_P256_KEY, PROBE_P256_SIG},
	{ALG_ECDSAP384SHA384, "ECDSA P-384/SHA-384", PROBE_P384_KEY, PROBE_P384_SIG},
	{ALG_ED25519, "Ed25519", PROBE_ED25519_KEY, PROBE_ED25519_SIG},
	{ALG_ED448, "Ed448", PROBE_ED448_KEY, PROBE_ED448_SIG},
}

/*
One DS digest type, and what `PROBE_DATA` hashes to under it.

`PROBE_DATA` rather than the empty string, which is the obvious thing to hash
and the wrong one: every DS digest this server computes runs over an owner name
and a DNSKEY RDATA, so a probe over nothing at all would be the only caller in
the package handing `EVP_Digest` a nil pointer and a length of zero. A library
that declined that shape - and every failure here is read as the library
declining the digest - would drop all three types at once, and with them every
delegation attested by a DS, into insecure. The probe asks the question the
same way the code that depends on it will.
*/
@(private)
Digest_Probe :: struct {
	digest_type: u8,
	name:        string,
	want:        string,
}

@(private)
DIGEST_PROBES := []Digest_Probe {
	{DIGEST_SHA1, "SHA-1", "f7809f355da2917a366b116c0d181b708c2c7875"},
	{DIGEST_SHA256, "SHA-256", "c4bce1a5f7cb1d0e1fa8fba68ced9f3d9d88923ae5eb7a9a77b932c207f3ec2c"},
	{
		DIGEST_SHA384,
		"SHA-384",
		"325b8c35db4d3b4959dddf0f05261de211117638798881ced929e119222a89eb50331c9843386ecadf031fb640971be4",
	},
}

@(private)
run_probe :: proc() {
	/*
	A scratch arena rather than the caller's temporary allocator: this runs
	inside whoever built the first validator, and a probe has no business
	leaving a kilobyte of DER in an arena it did not open. One probe at a time
	fits several times over - the largest is an RSA-2048 key, its signature and
	the SubjectPublicKeyInfo built from it.
	*/
	backing: [16384]u8
	arena: mem.Arena
	mem.arena_init(&arena, backing[:])
	scratch := mem.arena_allocator(&arena)

	algorithms: u32
	for probe in ALGORITHM_PROBES {
		/*
		Anything but `Ok` is read as the library declining the algorithm, and
		one path here is not that: `EVP_MD_CTX_new` returning nil is reported as
		`.Refused` because `verify_now` has nowhere else to put it. That is
		libcrypto out of heap, at start-up, for a hundred bytes - a process
		about to fail at something more urgent than DNSSEC, and not a state to
		build insurance against. The arena below cannot produce it: it is a
		fixed stack buffer, so exhaustion there is deterministic rather than
		unlucky, and it surfaces as `.Bad` through a nil key anyway.
		*/
		key, key_ok := decode_hex(probe.key, scratch)
		signature, sig_ok := decode_hex(probe.signature, scratch)
		data, data_ok := decode_hex(PROBE_DATA, scratch)
		result := Verify_Result.Bad
		if key_ok && sig_ok && data_ok {
			result = verify_now(probe.algorithm, key, signature, data, scratch)
		}
		free_all(scratch)
		if result != .Ok {
			algorithms |= algorithm_bit(probe.algorithm)
			logx.warnf(
				"dnssec: this build's libcrypto will not verify %s (algorithm %d); a zone signed with it alone is insecure here rather than validated",
				probe.name,
				probe.algorithm,
			)
			/*
			Which of the two it was, because they read very differently in a bug
			report. `Refused` is a crypto policy declining the algorithm, which
			is what this probe is for. `Bad` is the library refusing to import
			the key or rejecting a signature that verifies everywhere else -
			`test_no_probe_vector_can_be_rejected_as_a_forgery` says the vectors
			are sound, so on a released build it means a libcrypto that will not
			take this key type at all, and the operator is looking for a
			different fault than the message above suggests.
			*/
			if result == .Bad {
				logx.errorf(
					"dnssec: and it declined the %s probe key rather than the algorithm, which is not a crypto policy; this build and that libcrypto disagree about the key format",
					probe.name,
				)
			}
		}
	}

	digests: u32
	message, message_ok := decode_hex(PROBE_DATA, scratch)
	for probe in DIGEST_PROBES {
		out: [64]u8
		want, want_ok := decode_hex(probe.want, scratch)
		size := digest_size(probe.digest_type)
		/*
		`len(want) == size` before the comparison below walks `want`: `digest`
		fills `out[:size]` and nothing else, so a constant longer than its own
		digest type would compare against stack bytes nobody wrote, and one over
		64 would walk off the end of `out`. The test holds the constants to
		their lengths, and the loop should not need it to.
		*/
		ran := message_ok && want_ok && len(want) == size && digest(probe.digest_type, message, out[:size])
		if ran {
			for b, i in want {
				if out[i] != b {
					ran = false
					break
				}
			}
		}
		if !ran {
			digests |= digest_bit(probe.digest_type)
			logx.warnf(
				"dnssec: this build's libcrypto will not compute %s (DS digest type %d); a delegation attested only by it is insecure here",
				probe.name,
				probe.digest_type,
			)
		}
	}

	/*
	Published at the end rather than as each probe finishes, so that nothing -
	including `verify_signature`, which reads this to answer for an algorithm
	without asking the library twice - can see a half-built table.
	*/
	sync.atomic_store(&refused_algorithms, algorithms)
	sync.atomic_store(&refused_digests, digests)
}
