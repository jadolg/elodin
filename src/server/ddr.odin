package server

import "core:mem"
import "elodin:dns"

/*
Discovery of Designated Resolvers, answered here rather than forwarded.

RFC 9462 gives a client one question to ask before it commits to plain Do53: the
SVCB record at `_dns.resolver.arpa`, which the resolver it is already talking to
answers with its own encrypted endpoints. The name is special-use (RFC 9462
section 8.1) and locally served - no authoritative server on the Internet holds
it, and every answer is minted by whoever the client asked.

Which is the problem with forwarding it. The answer that comes back is the
*upstream's* designation - Quad9's DoT and DoH endpoints, say - and the client
takes it as this server's own and moves its traffic there. It stops asking us:
the block lists, the rewrites, the query log and the local zones all leave with
it, and the LAN sees a resolver silently swapped out from under it. The
certificate would not check out either, since this server's address is not in
the upstream's SAN list, so the client is as likely to end up with nothing that
works. RFC 9462 section 6.1 says it plainly: a DNS forwarder SHOULD NOT forward
queries for `resolver.arpa` (or any subdomains) upstream.

Forwarding it has a second cost that is what brought this to notice. The `arpa`
zone is signed and `resolver.arpa` is not in it - a query for the DS lands on
NXDOMAIN with an NSEC proving the name does not exist - so an upstream's
synthesised, unsigned SVCB answer under a signed parent is, to a validator,
exactly what a forged answer looks like. The verdict is Bogus, the client is
handed SERVFAIL, and an operator gets a `dnssec: SVCB _dns.resolver.arpa ... did
not validate` line for every client that probes. Both problems have the same
answer: the question never leaves.

NODATA is what it is answered with - NOERROR, no records, an SOA to say how long
to remember that. The zone exists and this server designates nothing in it, so
the client stays on Do53 and keeps talking to us, which is the outcome we want
and the one RFC 9462 leaves as the default. An operator who does want to
advertise this server's own DoT or DoH endpoints can still do it: `rewrites` are
applied ahead of this and a rule for the name wins, in the same spirit as a
trust anchor overriding the locally-served bypass.
*/
@(private)
RESOLVER_ARPA :: "resolver.arpa."

// How long a client is asked to remember that there is nothing here. Short
// enough that turning designation on later is noticed the same day, long enough
// that a client probing on every lookup is not asking us again each time.
@(private)
RESOLVER_ARPA_TTL :: u32(300)

// Whether `name` is the DDR zone or a name inside it. Same label-boundary and
// case-folding rules as the locally-served zones next door.
//
// Named a second time in `config.check_route_reachable`, which refuses an
// `upstream.zones` route into this zone: it is answered here before anything is
// forwarded and no key turns that off, so such a route could only ever sit in
// the file looking configured. The config package cannot import this one, hence
// the second copy of the name.
@(private)
is_resolver_arpa :: proc(name: string) -> bool {
	return name_at_or_below(name, RESOLVER_ARPA)
}

/*
The empty answer for a name in `resolver.arpa`.

The SOA names the zone itself rather than the question's parent - `synth_soa`
would hand back `arpa.` for a query at the apex, which is not a zone this server
has any business claiming.
*/
@(private)
build_resolver_arpa_response :: proc(
	query: dns.Message,
	q: dns.Question,
	allocator: mem.Allocator,
	limit: int,
) -> []u8 {
	resp := dns.make_response(query, .No_Error, allocator)
	resp.authority = synth_soa_for_zone(RESOLVER_ARPA, RESOLVER_ARPA_TTL, allocator)

	out, _, err := dns.encode_message(resp, allocator, limit)
	if err != .None {
		fallback, _ := dns.error_response(nil, query, .No_Error, allocator, limit)
		return fallback
	}
	return out
}
