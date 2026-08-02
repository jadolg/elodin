package dnssec

import "core:mem"
import "core:strings"
import "core:sync"
import "core:time"
import "elodin:dns"

/*
The chain of trust.

elodin forwards rather than recurses, so the material a validator needs is not
lying around from a resolution it did itself: every DS and DNSKEY has to be
asked for. `Query_Proc` is how, and the caller supplies it, which keeps this
package free of any dependency on the transports and makes the whole thing
testable against captured traffic.

The walk always starts at a trust anchor and works down. At each label the
parent's keys are used to check the child's DS, and the DS is used to check the
child's DNSKEY; when the parent shows that no DS exists the chain ends there and
everything below is insecure rather than forged. Nothing below an unproven step
is ever treated as authentic.
*/

Status :: enum u8 {
	// Checked against the chain of trust and genuine.
	Secure,
	// Provably outside the chain of trust: an unsigned zone, or an algorithm
	// this build cannot check. Correct data, just unverifiable.
	Insecure,
	// Signed, and the signature does not hold up. Never served to a client.
	Bogus,
	// The chain could not be assembled - an upstream failure, most likely.
	// Treated like bogus at the door, but distinguished so logs are honest.
	Indeterminate,
}

/*
Fetch one record set on the validator's behalf.

Must ask with DO and CD set: the validator wants the signatures, and it wants
the upstream's own opinion of them kept out of the way. `wire` is a complete DNS
response allocated from `allocator`.
*/
Query_Proc :: #type proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator) -> (wire: []u8, ok: bool)

Trust_Anchor :: struct {
	zone: string,
	ds:   Ds,
}

Options :: struct {
	// Zero uses the built-in root anchors.
	anchors:              []Trust_Anchor,
	// Iteration counts above this make a proof unusable rather than trusted.
	max_nsec3_iterations: int,
	max_cached_zones:     int,
}

Validator :: struct {
	anchors:              []Trust_Anchor,
	query:                Query_Proc,
	query_ctx:            rawptr,
	max_nsec3_iterations: int,
	max_cached_zones:     int,

	mu:                   sync.Mutex,
	zones:                map[string]^Zone_Entry,

	allocator:            mem.Allocator,
}

@(private)
Zone_Entry :: struct {
	// Owns the string the map is keyed by, so replacing an entry can hand the
	// same allocation back to the map rather than leave one of them dangling.
	zone:    string,
	status:  Status,
	keys:    []Dnskey,
	expires: time.Time,
}

// A chain longer than this is not a real delegation hierarchy.
MAX_CHAIN_DEPTH :: 24

/*
DS and DNSKEY lookups one client question may provoke, in total.

The chain depth alone does not bound the work: a response is free to carry
records under many different owner names, each naming a different signer, and
validating every one of them would have the resolver walk a chain apiece. That
turns one question into hundreds of upstream queries, with a worker held for all
of them. Real answers need a handful, so a response that needs more than this is
answered with SERVFAIL rather than chased.
*/
MAX_LOOKUPS_PER_QUERY :: 32

// Signatures tried on one RRset. A set carries one per algorithm in practice;
// more than this is a response trying to make us work rather than be believed.
MAX_SIGNATURES_PER_RRSET :: 8

// CNAME hops followed when checking that an answer addresses the question.
// Real chains are one or two; anything past this is a loop or a stall.
MAX_CNAME_CHAIN :: 16

// Keys a zone may publish. Far past any real zone, and it bounds both the
// canonical form built over the set and what the cache then holds on to.
MAX_KEYS_PER_ZONE :: 64

/*
What one call to `validate` is allowed to spend.

Carried down the whole walk rather than kept on the validator, because the limit
is per client question: two queries arriving at once each get their own.
*/
@(private)
Budget :: struct {
	lookups: int,
}

@(private)
spend_lookup :: proc(budget: ^Budget) -> bool {
	if budget.lookups >= MAX_LOOKUPS_PER_QUERY {
		return false
	}
	budget.lookups += 1
	return true
}

// RFC 9276 asks zones for zero iterations; a hundred is far past anything in
// use and still cheap to compute.
DEFAULT_MAX_NSEC3_ITERATIONS :: 100

DEFAULT_MAX_CACHED_ZONES :: 4096

// How long a zone's keys, or the fact that a zone is unsigned, may be reused.
// The record TTLs decide within these bounds.
MIN_ZONE_TTL :: 60
MAX_ZONE_TTL :: 3600

make_validator :: proc(
	query: Query_Proc,
	query_ctx: rawptr,
	opts: Options,
	allocator := context.allocator,
) -> ^Validator {
	v := new(Validator, allocator)
	v.allocator = allocator
	v.query = query
	v.query_ctx = query_ctx
	v.anchors = opts.anchors if len(opts.anchors) > 0 else root_anchors()
	v.max_nsec3_iterations = opts.max_nsec3_iterations if opts.max_nsec3_iterations > 0 else DEFAULT_MAX_NSEC3_ITERATIONS
	v.max_cached_zones = opts.max_cached_zones if opts.max_cached_zones > 0 else DEFAULT_MAX_CACHED_ZONES
	v.zones = make(map[string]^Zone_Entry, 64, allocator)
	return v
}

destroy_validator :: proc(v: ^Validator) {
	if v == nil {
		return
	}
	for _, entry in v.zones {
		free_entry(v, entry)
	}
	delete(v.zones)
	free(v, v.allocator)
}

@(private)
free_entry :: proc(v: ^Validator, entry: ^Zone_Entry) {
	for key in entry.keys {
		delete(key.rdata, v.allocator)
	}
	delete(entry.keys, v.allocator)
	delete(entry.zone, v.allocator)
	free(entry, v.allocator)
}

// ---------------------------------------------------------------------------
// Validating one response
// ---------------------------------------------------------------------------

Result :: struct {
	status: Status,
	// A short phrase for the log line and the extended DNS error.
	reason: string,
}

/*
Decide whether a response is authentic.

`wire` is the upstream's answer to the client's question, fetched with DO and CD
set. `now` is passed in rather than read here so the tests can pin it inside the
validity window of the captured signatures.
*/
validate :: proc(
	v: ^Validator,
	qname: string,
	qtype: dns.Type,
	wire: []u8,
	now: time.Time,
	allocator := context.temp_allocator,
) -> Result {
	msg, derr := dns.decode_message(wire, allocator)
	if derr != .None {
		return {.Bogus, "unparseable response"}
	}
	class := msg.question[0].class if len(msg.question) > 0 else dns.Class.IN
	unix := u32(time.to_unix_seconds(now))
	budget := Budget{}

	#partial switch dns.rcode_of(msg) {
	case .No_Error, .NX_Domain:
	case:
		/*
		REFUSED, SERVFAIL and the rest carry nothing to authenticate. Demanding a
		denial of existence from them would turn every upstream error into a
		DNSSEC failure, and report it as a forgery in the bargain.
		*/
		return {.Insecure, "no data to authenticate"}
	}

	/*
	Which path a response takes is decided by the records that can actually be
	authenticated, not by the answer section being non-empty.

	An RRSIG is never covered by a signature of its own, so it is skipped by
	`validate_answer` and can never be the thing that makes an answer genuine.
	Counting it as one would hand an attacker the denial path: a forged NXDOMAIN
	with a single junk RRSIG dropped into its answer section would be sent to
	`validate_answer`, which finds nothing it can check and says so - and the
	proof of non-existence that `validate_denial` would have demanded is never
	asked for. The denial is then served as merely unsigned.
	*/
	answerable := 0
	for rec in msg.answer {
		if rec.type != .RRSIG && rec.type != .OPT {
			answerable += 1
		}
	}
	if answerable > 0 {
		return validate_answer(v, &budget, msg, qname, qtype, class, unix, now, allocator)
	}
	/*
	A question about RRSIG records themselves is the one case where an answer
	made only of them is honest: an RRSIG RRset carries no signature of its own
	(RFC 4035 section 2.2), so there is nothing here to authenticate and no
	denial to demand either.
	*/
	if qtype == .RRSIG && len(msg.answer) > 0 {
		return {.Insecure, "nothing to authenticate"}
	}
	return validate_denial(v, &budget, msg, qname, qtype, class, unix, now, allocator)
}

@(private)
validate_answer :: proc(
	v: ^Validator,
	budget: ^Budget,
	msg: dns.Message,
	qname: string,
	qtype: dns.Type,
	class: dns.Class,
	unix: u32,
	now: time.Time,
	allocator: mem.Allocator,
) -> Result {
	worst := Status.Secure
	reason: string
	wildcard_seen := false
	checked := 0

	seen := make([dynamic]dns.Question, 0, len(msg.answer), allocator)
	for rec in msg.answer {
		if rec.type == .RRSIG || rec.type == .OPT {
			continue
		}
		if already_seen(seen[:], rec.name, rec.type) {
			continue
		}
		append(&seen, dns.Question{name = rec.name, type = rec.type})

		records := records_of(msg.answer, rec.name, rec.type, class, allocator)
		sigs := sigs_covering(msg.answer, rec.name, rec.type, class, allocator)

		status, wildcard, why := validate_rrset(v, budget, rec.name, rec.type, class, records, sigs, unix, now, allocator)
		wildcard_seen ||= wildcard
		checked += 1
		if status != .Secure {
			worst = worse(worst, status)
			reason = why
		}
	}

	/*
	A backstop. `validate` only sends a response here once it has counted a
	record this loop will check, so reaching this means the two disagree about
	what is authenticatable. Whatever the cause, an empty check is not a pass.
	*/
	if checked == 0 {
		return {.Insecure, "nothing to authenticate"}
	}

	/*
	Every RRset held up on its own. That is not yet an answer to the question:
	each was judged against the zone that claims it, and nothing so far has
	asked whether any of them concern the name that was asked about.

	An attacker with a signed zone of their own has an endless supply of validly
	signed RRsets, and offering one under someone else's question would pass
	every check above. The verdict would be `Secure`, the AD bit would go out,
	and a stub would read an authenticated answer holding nothing for the name
	it asked about - a denial of existence that was never proven.
	*/
	if worst == .Secure && !answers_question(msg.answer, qname, qtype, class) {
		return {.Bogus, "answer does not address the question"}
	}

	/*
	A wildcard answer is only good if the name really had nothing of its own.
	Without this an attacker holding one wildcard signature could serve it for
	names the zone answers for directly.
	*/
	if worst == .Secure && wildcard_seen {
		proof := validate_wildcard_proof(v, budget, msg, qname, class, unix, now, allocator)
		if proof != .Secure {
			return {proof, "wildcard expansion not proven"}
		}
	}
	return {worst, reason}
}

@(private)
validate_denial :: proc(
	v: ^Validator,
	budget: ^Budget,
	msg: dns.Message,
	qname: string,
	qtype: dns.Type,
	class: dns.Class,
	unix: u32,
	now: time.Time,
	allocator: mem.Allocator,
) -> Result {
	/*
	The zone is worked out from the name that was asked about, not from a signer
	named in the response.

	On the positive path a signer name is a safe hint: whatever zone it points
	at, the data still has to survive that zone's signature, so a wrong guess
	buys nothing. Here there is no such backstop. "None of these records
	verified" and "that was the wrong zone to check them against" look
	identical, so a single injected RRSIG naming some unsigned zone would have
	the whole denial written off as insecure and served - which is precisely the
	forged NXDOMAIN that DNSSEC exists to refuse. Walking down to the name costs
	a lookup and settles it.
	*/
	status, keys, established := zone_trust(v, budget, qname, now, allocator)
	#partial switch status {
	case .Insecure:
		return {.Insecure, "unsigned zone"}
	case .Bogus:
		return {.Bogus, "broken chain of trust"}
	case .Indeterminate:
		return {.Indeterminate, "chain of trust unavailable"}
	}

	nsecs, nsec3s := validated_denial_records(v, msg.authority, established, class, keys, unix, now, allocator)
	if len(nsecs) == 0 && len(nsec3s) == 0 {
		return {.Bogus, "no denial of existence"}
	}

	rcode := dns.rcode_of(msg)
	proof: Proof = .Failed
	if rcode == .NX_Domain {
		proof = nsec_proves_name_error(nsecs, qname, allocator) if len(nsecs) > 0 else .Failed
		if proof != .Proven && len(nsec3s) > 0 {
			proof = nsec3_proves_name_error(nsec3s, qname, established, v.max_nsec3_iterations, allocator)
		}
	} else {
		proof = nsec_proves_no_data(nsecs, qname, qtype, allocator) if len(nsecs) > 0 else .Failed
		if proof != .Proven && len(nsec3s) > 0 {
			proof = nsec3_proves_no_data(nsec3s, qname, established, qtype, v.max_nsec3_iterations, allocator)
		}
	}

	switch proof {
	case .Proven:
		return {.Secure, ""}
	case .Opt_Out:
		return {.Insecure, "opt-out span"}
	case .Failed:
		return {.Bogus, "denial of existence not proven"}
	}
	return {.Bogus, "denial of existence not proven"}
}

/*
Check one RRset.

Returns the wildcard flag as well, because a wildcard-expanded answer needs a
denial proof of its own that only the caller can assemble.
*/
@(private)
validate_rrset :: proc(
	v: ^Validator,
	budget: ^Budget,
	owner: string,
	type: dns.Type,
	class: dns.Class,
	records: []dns.Record,
	sigs: []Rrsig,
	unix: u32,
	now: time.Time,
	allocator: mem.Allocator,
) -> (
	status: Status,
	wildcard: bool,
	reason: string,
) {
	/*
	Each signature names the zone that claims the data, and each is judged
	against the chain down to that zone - rather than probing every label of the
	owner name for a delegation, which would cost a lookup per name.

	Every one of them gets a turn. Taking only the first would let anyone able to
	add a record to a response nominate a signer of their choosing and have the
	genuine signature sitting next to it go unexamined. Trying them all cannot
	help an attacker either: a signer outside the owner's ancestry is refused,
	one below the real zone cut has no DS to reach it, and one above it would
	have to hold a signature it was never in a position to make.
	*/
	unsupported := false
	attempts := 0
	for sig in sigs {
		if attempts >= MAX_SIGNATURES_PER_RRSET {
			break
		}
		if !name_in_zone(owner, sig.signer) {
			continue
		}
		attempts += 1

		zone_status, keys, established := zone_trust(v, budget, sig.signer, now, allocator)
		if zone_status != .Secure || !dns.name_equal_fold(sig.signer, established) {
			continue
		}
		result, expanded := check_signature(sig, owner, class, records, keys, unix, allocator)
		#partial switch result {
		case .Ok:
			return .Secure, expanded, ""
		case .Unsupported:
			unsupported = true
		}
	}

	if unsupported {
		// Nothing was checkable, so the data is unsigned as far as we are
		// concerned rather than forged.
		return .Insecure, false, "unsupported algorithm"
	}

	/*
	Nothing verified. Whether that means forged or merely unsigned is a question
	about the zone the name lives in, not about the signatures that arrived with
	it, so it is settled by walking down to the name itself.
	*/
	missing := "signature missing" if len(sigs) == 0 else "no valid signature"
	owner_status, _, _ := zone_trust(v, budget, owner, now, allocator)
	switch owner_status {
	case .Insecure:
		return .Insecure, false, "unsigned zone"
	case .Indeterminate:
		return .Indeterminate, false, "chain of trust unavailable"
	case .Bogus:
		return .Bogus, false, "broken chain of trust"
	case .Secure:
	}
	return .Bogus, false, missing
}

/*
Try one signature against the keys of its zone.

Rejects everything RFC 4035 section 5.3.1 asks to be rejected before any
cryptography happens: the wrong signer, a label count that does not fit the
owner name, an expired or not-yet-valid period.
*/
@(private)
check_signature :: proc(
	sig: Rrsig,
	owner: string,
	class: dns.Class,
	records: []dns.Record,
	keys: []Dnskey,
	unix: u32,
	allocator: mem.Allocator,
) -> (
	result: Verify_Result,
	wildcard: bool,
) {
	if !signature_current(sig, unix) {
		return .Bad, false
	}
	// A zone may only sign what is inside it. Without this a zone could vouch
	// for names it has no authority over, which is the whole point of the
	// hierarchy.
	if !name_in_zone(owner, sig.signer) {
		return .Bad, false
	}
	owner_labels := label_count(owner)
	signer_labels := label_count(sig.signer)
	if int(sig.labels) > owner_labels || int(sig.labels) < signer_labels {
		return .Bad, false
	}

	// Fewer labels than the owner name means the zone answered from a wildcard,
	// and the signature was made over that wildcard rather than over the name.
	signing_owner := owner
	if int(sig.labels) < owner_labels {
		signing_owner = wildcard_of(name_drop_labels(owner, owner_labels - int(sig.labels)), allocator)
		wildcard = true
	}

	data, built := signing_input(sig, signing_owner, class, records, allocator)
	if !built {
		return .Bad, wildcard
	}

	unsupported := false
	for key in keys {
		if key.algorithm != sig.algorithm || key.tag != sig.key_tag || !key_usable(key) {
			continue
		}
		switch verify_signature(sig.algorithm, key.public_key, sig.signature, data, allocator) {
		case .Ok:
			return .Ok, wildcard
		case .Unsupported:
			unsupported = true
		case .Bad:
		}
	}
	return .Unsupported if unsupported else .Bad, wildcard
}

/*
Prove that a wildcard was allowed to answer.

The zone has to show that the queried name has nothing of its own, which is the
same denial of existence a NODATA answer would carry, in the authority section
alongside the answer.
*/
@(private)
validate_wildcard_proof :: proc(
	v: ^Validator,
	budget: ^Budget,
	msg: dns.Message,
	qname: string,
	class: dns.Class,
	unix: u32,
	now: time.Time,
	allocator: mem.Allocator,
) -> Status {
	// Established from the queried name, for the same reason as the denial path.
	status, keys, established := zone_trust(v, budget, qname, now, allocator)
	if status != .Secure {
		return status
	}
	nsecs, nsec3s := validated_denial_records(v, msg.authority, established, class, keys, unix, now, allocator)
	if len(nsecs) > 0 {
		if _, covered := nsec_covering(nsecs, qname); covered {
			return .Secure
		}
	}
	if len(nsec3s) > 0 {
		if _, _, ce_ok := nsec3_closest_encloser(nsec3s, qname, established, v.max_nsec3_iterations); ce_ok {
			return .Secure
		}
	}
	return .Bogus
}

/*
Verify the NSEC and NSEC3 records of an authority section and hand back the ones
that held up. An unverified denial record is worse than none, so a single
failure discards the lot.
*/
@(private)
validated_denial_records :: proc(
	v: ^Validator,
	authority: []dns.Record,
	zone: string,
	class: dns.Class,
	keys: []Dnskey,
	unix: u32,
	now: time.Time,
	allocator: mem.Allocator,
) -> (
	nsecs: []Nsec_Rr,
	nsec3s: []Nsec3_Rr,
) {
	out_nsec := make([dynamic]Nsec_Rr, 0, 4, allocator)
	out_nsec3 := make([dynamic]Nsec3_Rr, 0, 4, allocator)
	seen := make([dynamic]dns.Question, 0, 4, allocator)

	for rec in authority {
		if rec.type != .NSEC && rec.type != .NSEC3 {
			continue
		}
		if already_seen(seen[:], rec.name, rec.type) {
			continue
		}
		append(&seen, dns.Question{name = rec.name, type = rec.type})

		records := records_of(authority, rec.name, rec.type, class, allocator)
		sigs := sigs_covering(authority, rec.name, rec.type, class, allocator)

		verified := false
		for sig in sigs {
			if !dns.name_equal_fold(sig.signer, zone) {
				continue
			}
			result, _ := check_signature(sig, rec.name, class, records, keys, unix, allocator)
			if result == .Ok {
				verified = true
				break
			}
		}
		if !verified {
			// Dropped rather than fatal. A proof assembled only from records
			// that verified is sound whatever else came along, and refusing the
			// lot would let one junk record added to a response deny every name
			// the real records were about to prove.
			continue
		}

		for r in records {
			rdata, is_raw := raw_rdata(r)
			if !is_raw {
				continue
			}
			if r.type == .NSEC {
				parsed, perr := parse_nsec(rdata, allocator)
				if perr != .None {
					continue
				}
				append(&out_nsec, Nsec_Rr{owner = r.name, rr = parsed})
			} else {
				parsed, perr := parse_nsec3(rdata)
				if perr != .None {
					continue
				}
				hash := make([]u8, 32, allocator)
				n, decoded := base32hex_decode(first_label(r.name), hash)
				if !decoded || n != len(parsed.next_hash) {
					continue
				}
				append(&out_nsec3, Nsec3_Rr{hash = hash[:n], rr = parsed})
			}
		}
	}
	return out_nsec[:], out_nsec3[:]
}

// ---------------------------------------------------------------------------
// Walking the chain
// ---------------------------------------------------------------------------

@(private)
Step :: enum u8 {
	// The child is a signed zone in its own right.
	Secure,
	// No delegation here, so the parent still covers everything below.
	No_Cut,
	Insecure,
	Bogus,
	Indeterminate,
}

/*
Establish the deepest signed zone at or above `name`.

Returns that zone's keys and its name. A `Secure` result means every step from a
trust anchor down to `established` was checked.
*/
@(private)
zone_trust :: proc(
	v: ^Validator,
	budget: ^Budget,
	name: string,
	now: time.Time,
	allocator: mem.Allocator,
) -> (
	status: Status,
	keys: []Dnskey,
	established: string,
) {
	root_status, root_keys := zone_keys(v, budget, ".", now, allocator)
	if root_status != .Secure {
		return root_status, nil, "."
	}

	zone := "."
	keys = root_keys
	depth := label_count(name)
	if depth > MAX_CHAIN_DEPTH {
		return .Indeterminate, nil, "."
	}

	for i in 1 ..= depth {
		child := name_drop_labels(name, depth - i)
		step, child_keys := zone_step(v, budget, zone, keys, child, now, allocator)
		switch step {
		case .Secure:
			zone = child
			keys = child_keys
		case .No_Cut:
			return .Secure, keys, zone
		case .Insecure:
			return .Insecure, nil, child
		case .Bogus:
			return .Bogus, nil, child
		case .Indeterminate:
			return .Indeterminate, nil, child
		}
	}
	return .Secure, keys, zone
}

/*
Take one step down: is `child` a signed zone, an unsigned delegation, or not a
zone cut at all?
*/
@(private)
zone_step :: proc(
	v: ^Validator,
	budget: ^Budget,
	parent: string,
	parent_keys: []Dnskey,
	child: string,
	now: time.Time,
	allocator: mem.Allocator,
) -> (
	step: Step,
	keys: []Dnskey,
) {
	if cached, found := cache_get(v, child, now, allocator); found {
		switch cached.status {
		case .Secure:
			return .Secure, cached.keys
		case .Insecure:
			return .Insecure, nil
		case .Bogus, .Indeterminate:
			// Nothing stores these; treating them as a broken step rather than
			// as an absent delegation keeps the failure closed if that changes.
			return .Bogus, nil
		}
	}

	if !spend_lookup(budget) {
		return .Indeterminate, nil
	}
	wire, ok := v.query(v.query_ctx, child, .DS, allocator)
	if !ok {
		return .Indeterminate, nil
	}
	msg, derr := dns.decode_message(wire, allocator)
	if derr != .None {
		return .Bogus, nil
	}
	unix := u32(time.to_unix_seconds(now))
	// We asked in class IN, and the transport already checked the reply's
	// question against ours; taking the class from the reply would only let it
	// choose which canonical form we build.
	class := dns.Class.IN

	ds_records := records_of(msg.answer, child, .DS, class, allocator)
	if len(ds_records) > 0 {
		sigs := sigs_covering(msg.answer, child, .DS, class, allocator)
		verified := false
		for sig in sigs {
			if !dns.name_equal_fold(sig.signer, parent) {
				continue
			}
			result, _ := check_signature(sig, child, class, ds_records, parent_keys, unix, allocator)
			if result == .Ok {
				verified = true
				break
			}
		}
		if !verified {
			return .Bogus, nil
		}

		set := make([dynamic]Ds, 0, len(ds_records), allocator)
		usable := false
		for r in ds_records {
			rdata, is_raw := raw_rdata(r)
			if !is_raw {
				continue
			}
			parsed, perr := parse_ds(rdata)
			if perr != .None {
				continue
			}
			append(&set, parsed)
			if algorithm_supported(parsed.algorithm) && digest_supported(parsed.digest_type) {
				usable = true
			}
		}
		if !usable {
			// Every DS names an algorithm or a digest we cannot check, which
			// RFC 6840 section 5.2 makes an insecure delegation rather than a
			// broken one.
			cache_put(v, child, .Insecure, nil, rrset_ttl(ds_records), now)
			return .Insecure, nil
		}

		child_keys, kstatus := fetch_keys(v, budget, child, set[:], unix, allocator)
		if kstatus != .Secure {
			if kstatus == .Insecure {
				cache_put(v, child, .Insecure, nil, rrset_ttl(ds_records), now)
				return .Insecure, nil
			}
			return .Bogus if kstatus == .Bogus else .Indeterminate, nil
		}
		cache_put(v, child, .Secure, child_keys, rrset_ttl(ds_records), now)
		return .Secure, child_keys
	}

	// No DS in the answer. The authority section has to say why, and say it in
	// a form the parent signed.
	nsecs, nsec3s := validated_denial_records(v, msg.authority, parent, class, parent_keys, unix, now, allocator)
	if len(nsecs) == 0 && len(nsec3s) == 0 {
		return .Bogus, nil
	}

	if len(nsecs) > 0 {
		if nsec_proves_no_ds(nsecs, child) == .Proven {
			cache_put(v, child, .Insecure, nil, negative_ttl(msg), now)
			return .Insecure, nil
		}
		if nsec_proves_no_delegation(nsecs, child) {
			return .No_Cut, nil
		}
	}
	if len(nsec3s) > 0 {
		if nsec3_proves_no_ds(nsec3s, child, parent, v.max_nsec3_iterations) == .Proven {
			cache_put(v, child, .Insecure, nil, negative_ttl(msg), now)
			return .Insecure, nil
		}
		if nsec3_proves_no_delegation(nsec3s, child, parent, v.max_nsec3_iterations) {
			return .No_Cut, nil
		}
	}
	return .Bogus, nil
}

/*
Fetch a zone's DNSKEY set and check it against the DS records the parent
published.

At least one key has to hash to a DS and then sign the whole set, which is what
binds the zone's own keys to its parent.
*/
@(private)
fetch_keys :: proc(
	v: ^Validator,
	budget: ^Budget,
	zone: string,
	ds_set: []Ds,
	unix: u32,
	allocator: mem.Allocator,
) -> (
	keys: []Dnskey,
	status: Status,
) {
	if !spend_lookup(budget) {
		return nil, .Indeterminate
	}
	wire, ok := v.query(v.query_ctx, zone, .DNSKEY, allocator)
	if !ok {
		return nil, .Indeterminate
	}
	msg, derr := dns.decode_message(wire, allocator)
	if derr != .None {
		return nil, .Bogus
	}
	class := dns.Class.IN

	records := records_of(msg.answer, zone, .DNSKEY, class, allocator)
	if len(records) == 0 || len(records) > MAX_KEYS_PER_ZONE {
		return nil, .Bogus
	}
	parsed := make([dynamic]Dnskey, 0, len(records), allocator)
	for r in records {
		rdata, is_raw := raw_rdata(r)
		if !is_raw {
			continue
		}
		key, perr := parse_dnskey(rdata)
		if perr != .None {
			continue
		}
		append(&parsed, key)
	}

	sigs := sigs_covering(msg.answer, zone, .DNSKEY, class, allocator)
	unsupported := false

	for ds in ds_set {
		if !algorithm_supported(ds.algorithm) || !digest_supported(ds.digest_type) {
			unsupported = true
			continue
		}
		for key in parsed {
			if key.tag != ds.key_tag || key.algorithm != ds.algorithm || !key_usable(key) {
				continue
			}
			if !ds_matches(zone, key, ds) {
				continue
			}
			// The key is vouched for by the parent; now it must vouch for the
			// rest of the set.
			for sig in sigs {
				if sig.key_tag != key.tag || sig.algorithm != key.algorithm {
					continue
				}
				if !dns.name_equal_fold(sig.signer, zone) {
					continue
				}
				/*
				This one key, and no other. A key tag is a 16-bit fold of the
				RDATA, not an identity: two keys can share one, and an attacker
				is free to make that happen. Offering the whole set here would
				let a key of their own satisfy the signature while the parent's
				DS went on attesting a key that had signed nothing - which is
				the entire chain of trust bypassed in one step.
				*/
				attested := [1]Dnskey{key}
				result, _ := check_signature(sig, zone, class, records, attested[:], unix, allocator)
				switch result {
				case .Ok:
					return parsed[:], .Secure
				case .Unsupported:
					unsupported = true
				case .Bad:
				}
			}
		}
	}
	return nil, .Insecure if unsupported else .Bogus
}

// Does this DNSKEY hash to this DS? The digest runs over the owner name in
// canonical form followed by the whole DNSKEY RDATA (RFC 4034 section 5.1.4).
ds_matches :: proc(zone: string, key: Dnskey, ds: Ds) -> bool {
	size := digest_size(ds.digest_type)
	if size == 0 || len(ds.digest) != size {
		return false
	}
	name_buf: [dns.MAX_NAME_WIRE]u8
	n, ok := canonical_name(zone, name_buf[:])
	if !ok {
		return false
	}

	input_buf: [dns.MAX_NAME_WIRE + 4096]u8
	if n + len(key.rdata) > len(input_buf) {
		return false
	}
	copy(input_buf[:], name_buf[:n])
	copy(input_buf[n:], key.rdata)

	computed: [64]u8
	if !digest(ds.digest_type, input_buf[:n + len(key.rdata)], computed[:]) {
		return false
	}
	return mem.compare(computed[:size], ds.digest) == 0
}

/*
The keys of a zone, from the cache or from the trust anchors.

Only the root takes the anchor path; every other zone reaches this through
`zone_step`, which has a parent to check against.
*/
@(private)
zone_keys :: proc(
	v: ^Validator,
	budget: ^Budget,
	zone: string,
	now: time.Time,
	allocator: mem.Allocator,
) -> (
	status: Status,
	keys: []Dnskey,
) {
	if cached, found := cache_get(v, zone, now, allocator); found {
		return cached.status, cached.keys
	}

	anchors := make([dynamic]Ds, 0, len(v.anchors), allocator)
	for a in v.anchors {
		if dns.name_equal_fold(a.zone, zone) {
			append(&anchors, a.ds)
		}
	}
	if len(anchors) == 0 {
		return .Indeterminate, nil
	}

	unix := u32(time.to_unix_seconds(now))
	fetched, fstatus := fetch_keys(v, budget, zone, anchors[:], unix, allocator)
	if fstatus != .Secure {
		return fstatus, nil
	}
	cache_put(v, zone, .Secure, fetched, MAX_ZONE_TTL, now)
	return .Secure, fetched
}

// ---------------------------------------------------------------------------
// The zone cache
// ---------------------------------------------------------------------------

@(private)
cache_get :: proc(
	v: ^Validator,
	zone: string,
	now: time.Time,
	allocator: mem.Allocator,
) -> (
	entry: Zone_Entry,
	found: bool,
) {
	fold_buf: [dns.MAX_NAME_PRESENTATION]u8
	key, key_ok := fold_into(zone, fold_buf[:])
	if !key_ok {
		return {}, false
	}

	sync.mutex_lock(&v.mu)
	defer sync.mutex_unlock(&v.mu)

	cached, in_map := v.zones[key]
	if !in_map {
		return {}, false
	}
	if time.diff(cached.expires, now) > 0 {
		return {}, false
	}
	/*
	The RDATA is copied, not referenced. A `Dnskey` is a handful of slices into
	memory this cache owns, and another thread may evict the entry the moment
	the lock is released; handing out the struct alone would leave the caller
	reading a freed key for the rest of its query. The caller works in a
	per-request arena, so the copy costs a couple of kilobytes and is dropped
	with everything else.
	*/
	out := Zone_Entry {
		status  = cached.status,
		expires = cached.expires,
	}
	if len(cached.keys) > 0 {
		copies := make([dynamic]Dnskey, 0, len(cached.keys), allocator)
		for key in cached.keys {
			rdata := make([]u8, len(key.rdata), allocator)
			copy(rdata, key.rdata)
			parsed, perr := parse_dnskey(rdata)
			if perr != .None {
				continue
			}
			append(&copies, parsed)
		}
		out.keys = copies[:]
	}
	return out, true
}

// `now` is the same clock the lookups use rather than the wall clock, so an
// entry cannot be written with an expiry the reader considers already past.
@(private)
cache_put :: proc(v: ^Validator, zone: string, status: Status, keys: []Dnskey, ttl: u32, now: time.Time) {
	fold_buf: [dns.MAX_NAME_PRESENTATION]u8
	key, key_ok := fold_into(zone, fold_buf[:])
	if !key_ok {
		return
	}
	lifetime := clamp(ttl, MIN_ZONE_TTL, MAX_ZONE_TTL)

	entry := new(Zone_Entry, v.allocator)
	entry.status = status
	entry.expires = time.time_add(now, time.Duration(lifetime) * time.Second)
	if len(keys) > 0 {
		owned := make([]Dnskey, len(keys), v.allocator)
		for k, i in keys {
			rdata := make([]u8, len(k.rdata), v.allocator)
			copy(rdata, k.rdata)
			parsed, perr := parse_dnskey(rdata)
			if perr != .None {
				delete(rdata, v.allocator)
				continue
			}
			owned[i] = parsed
		}
		entry.keys = owned
	}

	sync.mutex_lock(&v.mu)
	defer sync.mutex_unlock(&v.mu)

	if old, exists := v.zones[key]; exists {
		// Reuse the string the map is already keyed by. Re-inserting under the
		// caller's stack-backed `key` would leave the map holding a pointer
		// into a frame that is about to go away.
		entry.zone = old.zone
		old.zone = ""
		free_entry(v, old)
		v.zones[entry.zone] = entry
		return
	}
	if len(v.zones) >= v.max_cached_zones {
		// A flush is crude, but this cache holds zones rather than answers: it
		// fills slowly, and refilling it costs a handful of queries.
		for _, e in v.zones {
			free_entry(v, e)
		}
		clear(&v.zones)
	}
	entry.zone = strings.clone(key, v.allocator)
	v.zones[entry.zone] = entry
}

// Drop entries whose lifetime has run out. A zero `now` reads the wall clock;
// tests pass the same fixed clock the walk itself was made to trust, so an
// entry timed against fixture signatures is not judged against real time.
sweep :: proc(v: ^Validator, now: time.Time = {}) -> (removed: int) {
	if v == nil {
		return 0
	}
	sync.mutex_lock(&v.mu)
	defer sync.mutex_unlock(&v.mu)

	clock := now if now != {} else time.now()
	// Collected first: deleting from a map while walking it is not something to
	// rely on.
	expired := make([dynamic]^Zone_Entry, 0, 16, context.temp_allocator)
	for _, entry in v.zones {
		if time.diff(entry.expires, clock) > 0 {
			append(&expired, entry)
		}
	}
	for entry in expired {
		delete_key(&v.zones, entry.zone)
		free_entry(v, entry)
		removed += 1
	}
	return
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

@(private)
fold_into :: proc(name: string, buf: []u8) -> (string, bool) {
	if len(name) > len(buf) {
		return "", false
	}
	for i in 0 ..< len(name) {
		c := name[i]
		buf[i] = c + 32 if c >= 'A' && c <= 'Z' else c
	}
	return string(buf[:len(name)]), true
}

/*
Does this answer section address `qname`?

Walks the CNAME chain from the name that was asked about. Reaching the type
asked for settles it; so does running out of records after at least one hop,
because a chain that stops before its target is a perfectly ordinary answer -
the zone at the end may simply hold nothing of that type, and what proves that
is the denial in the authority section, not anything here.

What this refuses is an answer section with nothing at the queried name at all,
which is not an answer to this question whatever else it is.

Only the shape is checked. Every record here has already been through
`validate_rrset`, so reaching a name by following this chain means the records
that led there carried signatures from the zones that own them.
*/
@(private)
answers_question :: proc(records: []dns.Record, qname: string, qtype: dns.Type, class: dns.Class) -> bool {
	name := qname
	hops := 0
	for hops < MAX_CNAME_CHAIN {
		target := ""
		for r in records {
			if r.class != class || !dns.name_equal_fold(r.name, name) {
				continue
			}
			if r.type == qtype || qtype == .ANY {
				return true
			}
			if r.type == .CNAME {
				if v, is_name := r.data.(dns.Rdata_Name); is_name {
					target = v.name
				}
			}
		}
		if target == "" {
			// Nothing further to follow. Whether this answered the question
			// comes down to having got here by a CNAME the queried name owns.
			return hops > 0
		}
		name = target
		hops += 1
	}
	// A chain this long is a loop or a stall, and either way proves nothing.
	return false
}

@(private)
already_seen :: proc(seen: []dns.Question, name: string, type: dns.Type) -> bool {
	for q in seen {
		if q.type == type && dns.name_equal_fold(q.name, name) {
			return true
		}
	}
	return false
}

@(private)
records_of :: proc(
	recs: []dns.Record,
	name: string,
	type: dns.Type,
	class: dns.Class,
	allocator: mem.Allocator,
) -> []dns.Record {
	out := make([dynamic]dns.Record, 0, 4, allocator)
	for r in recs {
		if r.type == type && r.class == class && dns.name_equal_fold(r.name, name) {
			append(&out, r)
		}
	}
	return out[:]
}

@(private)
sigs_covering :: proc(
	recs: []dns.Record,
	name: string,
	type: dns.Type,
	class: dns.Class,
	allocator: mem.Allocator,
) -> []Rrsig {
	out := make([dynamic]Rrsig, 0, 2, allocator)
	for r in recs {
		if r.type != .RRSIG || r.class != class || !dns.name_equal_fold(r.name, name) {
			continue
		}
		rdata, is_raw := raw_rdata(r)
		if !is_raw {
			continue
		}
		sig, err := parse_rrsig(rdata, allocator)
		if err != .None || sig.type_covered != type {
			continue
		}
		append(&out, sig)
	}
	return out[:]
}

@(private)
rrset_ttl :: proc(records: []dns.Record) -> u32 {
	ttl := max(u32)
	for r in records {
		ttl = min(ttl, r.ttl)
	}
	return ttl if len(records) > 0 else 0
}

@(private)
negative_ttl :: proc(msg: dns.Message) -> u32 {
	return dns.negative_ttl(msg, MIN_ZONE_TTL)
}

@(private)
worse :: proc(a, b: Status) -> Status {
	rank :: proc(s: Status) -> int {
		switch s {
		case .Secure:
			return 0
		case .Insecure:
			return 1
		case .Indeterminate:
			return 2
		case .Bogus:
			return 3
		}
		return 3
	}
	return a if rank(a) >= rank(b) else b
}
