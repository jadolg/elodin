package server

import "core:mem"
import "core:net"
import "core:sync"
import "elodin:config"
import "elodin:dns"
import "elodin:logx"

/*
Refusing an upstream answer that points a public name at a private address.

A page loaded from `rebind.attacker.example` is same-origin with whatever that
name resolves to, for as long as it resolves to it. So the attacker publishes the
name with a one-second TTL, lets the browser fetch the page, and then answers the
next lookup with 192.168.1.1 - and the page is now permitted, by the browser's
own rules, to read the router's admin interface. Nothing was compromised: the
same-origin policy is keyed on a name, the attacker owns the name, and the
attacker also decides what it means. The victim's browser is the proxy and the
victim's LAN is the vantage point.

The browser cannot see this happening; it asked a resolver and believed the
answer. The resolver can. That is the whole argument for the check being here,
and it is why every comparable product has one: dnsmasq's `--stop-dns-rebind`,
Unbound's `private-address`, AdGuard Home's rebinding protection.

It matters more for this program than for a resolver in general, because the
deployment it is written for is the one the attack is aimed at - a box on a LAN
that every device points at, sharing an address space with the router, the
printer and the NAS. 169.254.169.254 is worth naming on its own: it is the cloud
instance metadata endpoint, it answers unauthenticated to anything that can send
it a request, and what it hands back is credentials.

What is refused

An answer becomes NODATA - NOERROR with an empty answer section, an SOA in the
authority section so the client remembers it, and RFC 8914 extended error 15
saying why. Two decisions in that, both of which had a plausible alternative.

SERVFAIL was the alternative rcode, and it is what "this answer is not
trustworthy" usually means. It is wrong here for a reason specific to what
follows it: a stub resolver configured with two servers treats SERVFAIL as this
server having failed and asks the other one, which on a home network is the
router - and the router answers 192.168.1.1 quite happily. The refusal would
route the attack around itself. NODATA is an answer, so the stub stops. This is
the same reasoning that has blocklist hits answer NXDOMAIN rather than REFUSED.

Filtering the offending record out of the answer was the alternative shape, and
it is what Unbound's `private-address` does. Two things are wrong with it. A
mixed answer - one public address and one private - would be served with the
private one removed, which means the guard has to be exhaustive over every way an
address can be written into a response, now and after the next RR type is added;
a check that fails closed on the whole message is one decision made once. And a
filtered answer is an answer no authority ever gave, handed to the client under
this server's name with nothing to say a record is missing.

The refusal is not cached. `resolve_query` calls this before `cache.put`, which
is the ordering that matters - without it the first client's private answer is
stored and every later client is served it without the check ever running again -
but the synthesised NODATA is not stored either. What this saw was one answer,
not a property of the name, and an upstream that returns something sensible a
second later should be believed. The client's own negative caching is bounded by
the SOA's TTL, which is `blocking.block_ttl`: the same question ("how long should
a client hold on to an answer we made up instead of the real one") already had a
number, and inventing a second one to set differently would be inventing a
difference.

What is checked

The answer section, for A and AAAA records, and the `ipv4hint`/`ipv6hint`
parameters of SVCB and HTTPS records - which are addresses a browser connects to
without ever asking for the A record, so leaving them out would be a guard with a
documented way round it.

Only when the question is one whose answer a client turns into a connection: A,
AAAA, ANY, SVCB, HTTPS. That is not a security judgement about the other types so
much as what the skip is for - the check has to decode the response, and decoding
every MX and TXT answer a second time to look for address records that a stub
would discard is work on the forwarding path for nothing. A browser cannot be
made to issue any other type.

The additional section is left alone, except beside an SVCB or HTTPS answer.
Addresses there are ordinarily glue for names other than the one asked about: a
stub does not resolve a hostname out of them, and this server stores and serves
the response as a whole under the question's key, so there is no way to retrieve
one on its own. SVCB is the exception in the specification rather than here - RFC
9460 section 5 has the resolver put A and AAAA for the ServiceMode TargetName in
the additional section precisely so that the client does not have to ask for
them, so a client following it connects to what it finds there. That is the same
"address a browser reaches without ever asking for the A record" the hints are
covered for, arriving by the other door, and an `HTTPS 1 target.` with no hints
at all was the way through.

An answer this server cannot decode is refused, not forwarded, for the five
question types above. That was the way round the whole guard and it cost the
attacker one byte: they own the authoritative server, so they emit a truthful
answer section carrying 192.168.1.1 and an ARCOUNT of 100 with nothing behind it,
the count check in `decode_message` rejects the message, and the bytes reach the
client verbatim - where glibc's `getanswer`, which only ever walks the answer
section, hands the browser the address.

What used to be written here in place of refusing was that such a message is also
one the validator cannot validate and the cache declines to store. The second
half is true and useless: the client is served either way. The first was simply
wrong. `validating` is false whenever `dnssec.enabled` is off - which is a
supported configuration and the one recommended for an upstream that cannot
return DNSSEC records - or the client sets CD; and an attacker's own zone is
unsigned in any case, so validation reaches Insecure and serves it. A mitigation
an attacker switches off by not signing their zone was never one.

So it fails closed, and only exactly here: with the guard on, for the questions
the guard covers, when the part of the message a client acts on cannot be read.
An undecodable MX or TXT answer is forwarded as it always was.

That last clause is narrower than "when the decode fails", and the difference
matters in both directions. `decode_message` refuses a message for a malformed
record anywhere in it, authority and additional sections included, and a stub
reads neither - so refusing on those two would take down a name that resolves
today over bytes nothing acts on. `rebind_decode` therefore falls back to the
answer section alone, which is what has to be readable, and keeps the whole-
message requirement for the one case where the rest is acted on: an answer
carrying SVCB or HTTPS, whose additional section a client following RFC 9460
section 5 connects to. The ARCOUNT bypass above is refused by either decode -
the count check is in the prologue both share - so nothing is given back to the
attacker; see `rebind_decode`.

What it still costs is a name whose upstream emits an answer section this decoder
rejects becoming NODATA for A and AAAA where it used to be forwarded - an answer
that was already not cacheable, not re-encodable and not validatable, so the
marginal loss is small and the fuzz corpus in `testdata/fuzz-corpus/dns` is what
keeps the set small. Widening it to every question type would be a different
change with a much larger blast radius, and is not this one.

What is exempt

`rewrites` need no exemption and have none: a rewritten name is answered out of
the configuration by `apply_rewrite`, several hundred lines before anything is
forwarded, so `nas.home` pointing at 192.168.1.50 never reaches an upstream and
never reaches this. Worth stating because it is the first thing an operator
worries about, and because it is a property of where the two checks sit rather
than of anything either of them does - a rewrite moved after the forwarding path
would quietly acquire the problem.

What does need an exemption is split horizon: a site whose upstream is its own
internal server, resolving `nas.corp.example` to an RFC 1918 address through the
public name space. `rebind.allow_domains` is the list of zones that may do it,
matched on the question rather than on the record's owner name - see the field.
`rebind.allow_loopback` is the other one, and is dnsmasq's
`--rebind-localhost-ok`.

`localhost.` is exempt without being configured, and only as far as loopback.
RFC 6761 section 6.3 makes 127.0.0.1 and ::1 the only answers that name may
have, so a loopback answer for it is legitimate by definition rather than by
anybody's policy - which is a different kind of exemption from the two above and
is why it is not a setting. Scoped to loopback rather than waved through
wholesale, because nothing forwards `.localhost` on purpose and an upstream that
answered `evil.localhost` with 192.168.1.1 would be doing something RFC 6761 does
not permit either; the exemption is for the addresses the RFC allows, not for the
name.

Answering the name here instead - which is what RFC 6761 asks a resolver to do,
and would mean it never reached the forwarding path at all - is a separate change
and a separate issue. This does not wait on it: two guards whose correctness
depends on which of them merged first is the coupling that turns into a live bug
when one lands and the other is still in review.

Whether this can be on by default is decided by these exemptions existing, and
the argument for the default it has is in `Rebind_Config`.
*/

/*
The name RFC 6761 section 6.3 reserves, with everything under it.

`name_at_or_below` gives both halves of what section 6.3 describes - the name
itself and any name ending in `.localhost.` - from one entry.
*/
@(private)
LOCALHOST_ZONE :: "localhost."

// RFC 8914 code 15, "Blocked": the answer was withheld for an internal security
// policy of the resolver's, which is exactly what this is. 17 ("Filtered") is
// the one for filtering the client itself asked for, and nobody asked for this.
EDE_BLOCKED :: 15

// SvcParamKeys 4 and 6, RFC 9460 sections 7.3 and 7.4. Everything else in the
// parameter list is a port, an ALPN or a public key, none of which name a host.
@(private)
SVCB_IPV4HINT :: 4
@(private)
SVCB_IPV6HINT :: 6

/*
The answer to send instead, when the upstream's answer cannot be passed on.

`refused` false means there was nothing to object to and the caller carries on
with the response it has. It is false for every query when `rebind.enabled` is
off, which is the only cost this feature has on a server that does not want it.

`detail` is what the query log records beside `outcome=blocked`, and separates
the two reasons: `rebind` for an answer that named a private address, and
`unreadable` for one that could not be decoded and therefore could not be
checked. Both are this guard withholding an answer and both move the same
counter - they should each be zero in production, and a second counter for a
number that never moves is a number nobody reads - but they point an operator at
completely different things, so the log has to be able to say which.
*/
@(private)
rebind_refusal :: proc(
	s: ^Server,
	query: dns.Message,
	q: dns.Question,
	resp: []u8,
	limit: int,
	allocator: mem.Allocator,
) -> (
	out: []u8,
	detail: string,
	refused: bool,
) {
	if !s.cfg.rebind.enabled {
		return nil, "", false
	}
	#partial switch q.type {
	case .A, .AAAA, .ANY, .SVCB, .HTTPS:
	case:
		return nil, "", false
	}
	if rebind_exempt(s.cfg.rebind.allow_domains, q.name) {
		return nil, "", false
	}

	/*
	Decoded here rather than sharing the decode the cache block does a few lines
	below. Deliberate and temporary: four changes are in flight against
	`resolve_query` at once, and one procedure call is what rebases cleanly
	between them where a restructured cache block does not. Folding the two into
	one decode is issue #188, to be done in the merge pass once there is a single
	shape to fold into - it is not an oversight, and it costs only the cache-miss
	path for the five question types above.
	*/
	decoded, readable, err := rebind_decode(resp, allocator)
	if !readable {
		sync.atomic_add(&s.stats.rebind, 1)
		report_unreadable(q.name, err)
		return rebind_nodata(s, query, q, limit, allocator), "unreadable", true
	}

	// Decided once, from the question, rather than read out of the configuration
	// beside each address: `localhost.` earns the same latitude the setting
	// grants, and one verdict per query is what keeps the two from drifting into
	// meaning different things about the same address.
	loopback_ok := s.cfg.rebind.allow_loopback || name_at_or_below(q.name, LOCALHOST_ZONE)

	addr, v6, found := first_private_answer(decoded, loopback_ok)
	if !found {
		return nil, "", false
	}

	sync.atomic_add(&s.stats.rebind, 1)
	report_rebind(q.name, addr, v6, allocator)
	return rebind_nodata(s, query, q, limit, allocator), "rebind", true
}

/*
The response, decoded as far as this guard has to read it.

`readable` false is the fail-closed case: bytes that cannot be checked are not
passed on, and `err` is what stopped the read. What is decided here is how much
of a message has to be readable before the answer counts as checkable, and it is
the answer section - plus the additional section when the answer carries an SVCB
or HTTPS record.

The full decode is tried first, because it is what the checks want. When it
fails, the question is which part of the message failed. A stub reads the answer
section and nothing else - glibc's `getanswer` never walks past it - so an answer
section that reads cleanly beside an authority or additional section that does
not is one this server can still check and still pass on. Refusing it would take
a name down over a part of the message nothing acts on, and that name resolves
today. `decode_through_answer` is the same decode stopped after the answer
section, and is what `resolve_query` already falls back to for the CNAME walk,
for the same reason.

None of which reopens the bypass the fail-closed rule was written for. That one
is an ARCOUNT claiming records that are not in the message, and the count check
that rejects it - eleven bytes needed per record, five per question, against the
bytes actually there - is in `decode_sections`' prologue, ahead of the branch
that stops at the answer section. Both decoders refuse it. What gets past the
prologue and fails later is a count that overruns by a record or two, and there
the answer section is read and checked exactly as it always was: a private
address in it is still found and the answer still refused. What the attacker
buys with the malformed tail is a decode that stops early, not an address that
goes unlooked-at.

The exception is an answer carrying SVCB or HTTPS. RFC 9460 section 5 has the
client take addresses for the target out of the additional section - see
`first_private_answer` - so there the part that did not read is a part that is
acted on, and the message is refused as it was before.

A record the decoder kept as `Rdata_Raw` is the other way a message can be
unreadable without saying so. `decode_record` does not fail on RDATA it cannot
parse; it keeps the bytes verbatim and reports success, which is right for a
forwarder and wrong for a check that reads the union tag to find addresses. An A
whose RDLENGTH disagrees or an SVCB whose TargetName this decoder refuses would
arrive as a blob, match none of the address cases, and be forwarded unexamined
with whatever a more forgiving client parses out of it - `ipv4hint` bytes sitting
untouched behind a target name only this decoder objects to. So a raw record
whose *type* is one of the four this guard reads addresses out of is unreadable,
by the same rule as the message: not checkable, not passed on. Every other type
is raw all the time by design and is none of this guard's business.
*/
@(private)
rebind_decode :: proc(
	resp: []u8,
	allocator: mem.Allocator,
) -> (
	msg: dns.Message,
	readable: bool,
	err: dns.Decode_Error,
) {
	decoded, full_err := dns.decode_message(resp, allocator)
	if full_err != .None {
		answer, answer_err := dns.decode_through_answer(resp, allocator)
		if answer_err != .None {
			return {}, false, answer_err
		}
		// The unread section is one the client acts on, so this is the refusal
		// the whole-message decode was already making.
		if answer_has_service(answer) {
			return {}, false, full_err
		}
		decoded = answer
	}
	if answer_has_raw_address(decoded) {
		return {}, false, .Bad_Rdata
	}
	return decoded, true, .None
}

/*
Whether the answer section carries an SVCB or HTTPS record.

On `rec.type` rather than on the union tag, because one caller is asking the
question about a message whose records may not have decoded.
*/
@(private)
answer_has_service :: proc(msg: dns.Message) -> bool {
	for rec in msg.answer {
		#partial switch rec.type {
		case .SVCB, .HTTPS:
			return true
		}
	}
	return false
}

/*
Whether the answer section carries an address record the decoder could not read.

The four types are the ones `first_private_answer` takes addresses from. A record
of one of those types that arrived as `Rdata_Raw` is one this guard would skip
in silence.
*/
@(private)
answer_has_raw_address :: proc(msg: dns.Message) -> bool {
	for rec in msg.answer {
		#partial switch rec.type {
		case .A, .AAAA, .SVCB, .HTTPS:
			if _, raw := rec.data.(dns.Rdata_Raw); raw {
				return true
			}
		}
	}
	return false
}

/*
NOERROR, no answer section, an SOA to say how long to remember it and an extended
error to say why.

One procedure for both reasons, so that a client cannot tell from the response
which of them it was. Not that it is secret - the query log says, and the whole
point of the extended error is that the reason travels - but the two differ only
in what an operator is told, and building them separately is how they would come
to differ in what a client is told as well.
*/
@(private)
rebind_nodata :: proc(
	s: ^Server,
	query: dns.Message,
	q: dns.Question,
	limit: int,
	allocator: mem.Allocator,
) -> []u8 {
	out_msg := dns.make_response(query, .No_Error, allocator)
	out_msg.authority = synth_soa(q.name, s.cfg.blocking.block_ttl, allocator)
	attach_extended_error(&out_msg, EDE_BLOCKED, "rebind", allocator)

	encoded, _, enc_err := dns.encode_message(out_msg, allocator, limit)
	if enc_err != .None {
		/*
		Whatever happens, not the upstream's bytes. An answer that could not be
		encoded is a header this server can always build, and a client that gets
		an empty NOERROR has lost a name; a client that gets the answer this
		procedure just decided to withhold has lost rather more than that.
		*/
		fallback, _ := dns.error_response(nil, query, .No_Error, allocator, limit)
		return fallback
	}
	return encoded
}

/*
Whether the question sits inside a zone the operator said may answer privately.

At or below, so `home.example` in the list covers `home.example` itself and
everything under it, which is what `--rebind-domain-ok=/home.example/` means in
dnsmasq and what an operator writing a zone name expects.
*/
@(private)
rebind_exempt :: proc(domains: []string, name: string) -> bool {
	for domain in domains {
		if name_at_or_below(name, domain) {
			return true
		}
	}
	return false
}

/*
The first address in the answer that is inside private space.

First rather than all of them: one is enough to refuse the whole message, and
what the caller does with it is name it in the log, so the rest would be a list
nobody reads.

The additional section joins the search only when the answer carried an SVCB or
HTTPS record, which is the one shape in which an address there is something a
client acts on - RFC 9460 section 5. Scoped to the answer's contents rather than
to the question type, because that is the condition that actually holds: an ANY
query returning an HTTPS record is in it, and an A query whose upstream attached
unrelated NS glue is not.
*/
@(private)
first_private_answer :: proc(msg: dns.Message, loopback_ok: bool) -> (addr: [16]u8, v6: bool, found: bool) {
	service_answer := false
	for rec in msg.answer {
		switch data in rec.data {
		case dns.Rdata_A:
			a: [16]u8
			a[0], a[1], a[2], a[3] = data.addr[0], data.addr[1], data.addr[2], data.addr[3]
			if rebind_private(a, false, loopback_ok) {
				return a, false, true
			}
		case dns.Rdata_AAAA:
			if rebind_private(data.addr, true, loopback_ok) {
				return data.addr, true, true
			}
		case dns.Rdata_SVCB:
			service_answer = true
			if a, is6, hit := private_svcb_hint(data.params, loopback_ok); hit {
				return a, is6, true
			}
		case dns.Rdata_Name, dns.Rdata_SOA, dns.Rdata_MX, dns.Rdata_TXT, dns.Rdata_SRV, dns.Rdata_CAA, dns.Rdata_OPT, dns.Rdata_Raw:
		// Nothing in any of these is an address a client connects to. A CNAME
		// in the chain is followed to a record above rather than being an
		// answer of its own; blocking a CNAME *target* by name is a separate
		// question and a separate setting.
		case:
		// No data at all, which is a record type the decoder produced nothing
		// for. Nothing to read an address out of.
		}
	}

	if !service_answer {
		return {}, false, false
	}
	for rec in msg.additional {
		#partial switch data in rec.data {
		case dns.Rdata_A:
			a: [16]u8
			a[0], a[1], a[2], a[3] = data.addr[0], data.addr[1], data.addr[2], data.addr[3]
			if rebind_private(a, false, loopback_ok) {
				return a, false, true
			}
		case dns.Rdata_AAAA:
			if rebind_private(data.addr, true, loopback_ok) {
				return data.addr, true, true
			}
		}
	}
	return {}, false, false
}

/*
Whether `addr` is somewhere this question's answer should not point.

`loopback_ok` is applied here rather than by leaving loopback out of the table,
so that the address is still recognised as private everywhere else and the
latitude means one thing: "and serve it anyway". Both tables are consulted
through the same unwrapped bytes, so an exemption cannot miss an address the
refusal caught.
*/
@(private)
rebind_private :: proc(addr: [16]u8, v6: bool, loopback_ok: bool) -> bool {
	bytes, family := rebind_unwrap(addr, v6)
	if !config.address_in(config.PRIVATE_NETWORKS, bytes, family) {
		return false
	}
	if loopback_ok && config.address_in(config.LOOPBACK_NETWORKS, bytes, family) {
		return false
	}
	return true
}

/*
The IPv4 address inside a v6 address that carries one, for the two forms
`address_in` does not already undo.

`address_in` unwraps `::ffff:a.b.c.d`, which is the form that matters to the ACL
as well - a client can arrive from one. These two only matter to an answer:

  - `64:ff9b::/96`, RFC 6052's well-known prefix. On a NAT64 network the stack
    connects to the embedded IPv4 host, so `64:ff9b::c0a8:0101` reaches
    192.168.1.1 as squarely as an A record for it would, and an AAAA is the
    record such a network's clients ask for. RFC 6052 section 3.1 forbids using
    the well-known prefix with a non-global address, which is the argument that
    a legitimate answer never carries one and refusing costs nothing.
  - `::a.b.c.d`, the IPv4-compatible form deprecated by RFC 4291 section
    2.5.5.1. Deprecated is not the same as not parsed, and it is one byte of
    difference from the mapped form that everything does parse.

Left alone deliberately: a *compat* address whose first embedded byte is zero,
so `::` and `::1` stay the addresses they are and keep matching the `::/128` and
`::1/128` entries - unwrapping them would turn `::1` into 0.0.0.1 and quietly
put it outside `LOOPBACK_NETWORKS`, taking `allow_loopback` away from the one
address it exists for. The same latitude under the NAT64 prefix would be a hole
rather than a nicety, and the one that matters most; see the body.

Not covered, and named because the rest of this file names what it leaves out: a
site-specific NAT64 prefix (RFC 6052 allows /32 through /64, RFC 8215 reserves
`64:ff9b:1::/48` for local use). This server is not told what its network's
prefix is, and the embedded octets sit at a different offset for each length,
skipping the `u` byte. A site running one has `allow_domains`, and dnsmasq and
Unbound do not recognise even the well-known prefix.
*/
@(private)
rebind_unwrap :: proc(addr: [16]u8, v6: bool) -> (bytes: [16]u8, family: bool) {
	if !v6 {
		return addr, false
	}
	// Bytes 4 through 11 are zero in both forms. `::ffff:a.b.c.d` fails here on
	// its own 0xff pair, which is what leaves it to `address_in`.
	for i in 4 ..< 12 {
		if addr[i] != 0 {
			return addr, true
		}
	}
	nat64 := addr[0] == 0x00 && addr[1] == 0x64 && addr[2] == 0xff && addr[3] == 0x9b
	compat := addr[0] == 0 && addr[1] == 0 && addr[2] == 0 && addr[3] == 0
	if !nat64 && !compat {
		return addr, true
	}
	/*
	The "left alone" rule above, and it belongs to the compat branch alone.
	Under a prefix of zeroes a zero first octet is `::` or `::1` - addresses in
	their own right, which the tables already hold as themselves.

	Under the NAT64 prefix it is nothing of the kind: `64:ff9b::` is RFC 6052's
	encoding of 0.0.0.0, and a stack on such a network translates it to 0.0.0.0
	and connects there. That is the entry `PRIVATE_NETWORKS` describes as a
	working bypass rather than an odd answer - "0.0.0.0 Day", where a browser
	reaches a service bound to 127.0.0.1 by connecting to 0.0.0.0 - so it is the
	last address that should be waved through for having a zero in it.
	*/
	if compat && addr[12] == 0 {
		return addr, true
	}
	v4: [16]u8
	v4[0], v4[1], v4[2], v4[3] = addr[12], addr[13], addr[14], addr[15]
	return v4, false
}

/*
The first private address hinted at by an SVCB or HTTPS record.

`params` is the SvcParams list as it arrived: a sequence of a two-byte key, a
two-byte length and that many bytes of value, in ascending key order (RFC 9460
section 2.2). Walked rather than parsed into anything, because two of the keys
matter and the rest are of no interest here.

A length that runs past the end stops the walk instead of being clamped, which
fails open for whatever came after it. Named rather than left to be discovered:
guessing at where the next parameter begins would mean reading a key out of the
middle of somebody else's value, and refusing the answer outright would mean an
SVCB record this walker disagrees with taking a name down - a young RR type where
the disagreement is as likely to be ours. What makes it safe to fail open is that
the attacker needs the *client* to act on the hint, and a client parsing the same
RDATA by the same lengths reaches the same truncation and has nothing to act on.
A client that reads past a declared length has a bug this could not have fixed.
*/
@(private)
private_svcb_hint :: proc(params: []u8, loopback_ok: bool) -> (addr: [16]u8, v6: bool, found: bool) {
	i := 0
	for i + 4 <= len(params) {
		key := int(params[i]) << 8 | int(params[i + 1])
		size := int(params[i + 2]) << 8 | int(params[i + 3])
		i += 4
		if i + size > len(params) {
			return {}, false, false
		}
		value := params[i:i + size]
		i += size

		switch key {
		case SVCB_IPV4HINT:
			for off := 0; off + 4 <= len(value); off += 4 {
				a: [16]u8
				copy(a[:], value[off:off + 4])
				if rebind_private(a, false, loopback_ok) {
					return a, false, true
				}
			}
		case SVCB_IPV6HINT:
			for off := 0; off + 16 <= len(value); off += 16 {
				a: [16]u8
				copy(a[:], value[off:off + 16])
				if rebind_private(a, true, loopback_ok) {
					return a, true, true
				}
			}
		}
	}
	return {}, false, false
}

/*
Say so, once loudly and then quietly.

The first refusal since start is a `warn` naming the name, the address and both
settings that would allow it, because the operator this line is for is the one
whose internal name has just stopped resolving and who has no other way to find
out why - NODATA looks exactly like a name that does not exist. Every one after
it is `debug`, and `rebind=` in the stats line carries the count, for the reason
the connection-limit and UDP-ceiling messages do the same: whoever is triggering
this decides how often it happens, and a line per query would let them decide how
much this server writes to disk.

Which is the same trade in both directions. An operator with a broken split
horizon sees the warning once, at start, when every internal name is failing. An
operator under an actual attack sees one warning and a counter that climbs, which
is what a graph is for.

Through `report_once` rather than the atomic on its own, so that the address is
rendered only when a line is going to carry it. Both callers of this are floods -
an attack, or a split horizon in which every query refuses - and `logx` throws a
debug line away at a level check that `rebind_address_text` has already allocated
and formatted for by then. That is the same reason `report_refusal` goes through
it, and the same arithmetic: work per refused query, decided by whoever is
sending them.
*/
@(private)
rebind_reported: bool

@(private)
report_rebind :: proc(name: string, addr: [16]u8, v6: bool, allocator: mem.Allocator) {
	say, first := report_once(&rebind_reported, logx.enabled(.Debug))
	if !say {
		return
	}
	text := rebind_address_text(addr, v6, allocator)
	if !first {
		logx.debugf("refused an answer for %s carrying the private address %s", dns.name_trim_root(name), text)
		return
	}
	logx.warnf(
		"refused an answer for %s carrying the private address %s: a public name resolving into private space is how a DNS rebinding attack reaches a service on this network, so the client was told NODATA",
		dns.name_trim_root(name),
		text,
	)
	logx.warnf(
		"if that name is served locally on purpose, add its zone to rebind.allow_domains (or set rebind.allow_loopback for 127.0.0.0/8 and ::1, or rebind.enabled to false); refusals are counted as rebind= in the stats line, and further ones are logged at debug level",
	)
}

/*
Say, once, that an answer was withheld because it could not be read.

A different diagnosis from the one above and so a flag of its own: an operator
who saw the private-address warning first would otherwise never be told that this
is happening at all. What it points at is not a network to exempt but an upstream
emitting something this decoder rejects - or somebody trying the one way there
was around the guard - so the line names the decode error rather than a setting,
and does not suggest `allow_domains`, which would not help.
*/
@(private)
unreadable_reported: bool

@(private)
report_unreadable :: proc(name: string, err: dns.Decode_Error) {
	say, first := report_once(&unreadable_reported, logx.enabled(.Debug))
	if !say {
		return
	}
	if !first {
		logx.debugf("refused an unreadable answer for %s: %v", dns.name_trim_root(name), err)
		return
	}
	logx.warnf(
		"refused an answer for %s that could not be decoded (%v): with rebinding protection on, an answer this server cannot read is one it cannot check, so it is not passed on",
		dns.name_trim_root(name),
		err,
	)
	logx.warnf(
		"this is an upstream sending something the decoder rejects, or an attempt to slip a private address past the check; it applies to A, AAAA, ANY, SVCB and HTTPS questions only, and rebind.enabled turns it off with the rest of the guard",
	)
}

// The address as an operator would write it, so that the log line can be
// searched for. `core:net` does the v6 compression, which is not worth a second
// implementation for a message nobody reads twice.
@(private)
rebind_address_text :: proc(addr: [16]u8, v6: bool, allocator: mem.Allocator) -> string {
	if !v6 {
		return net.address_to_string(net.IP4_Address{addr[0], addr[1], addr[2], addr[3]}, allocator)
	}
	a: net.IP6_Address
	for i in 0 ..< 8 {
		a[i] = u16be(u16(addr[i * 2]) << 8 | u16(addr[i * 2 + 1]))
	}
	return net.address_to_string(a, allocator)
}
