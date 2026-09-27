# What is implemented, and what is not

## What is implemented

Queries of any type are answered: A, AAAA, CNAME, MX, TXT, SRV, SOA, NS, PTR,
CAA, SVCB/HTTPS, DS, DNSKEY, RRSIG and everything else. Types the codec does not
model natively are carried through as opaque RDATA per RFC 3597, and forwarded
answers are passed back byte for byte, so DNSSEC records survive untouched. With
validation on, an answer for a client that did not ask for DNSSEC records is
rebuilt without them; every other answer goes back as the upstream sent it, bar the OPT
record this server answers with and, from the cache, TTLs counted down.

Also handled: EDNS0 — the client's OPT record is forwarded upstream so payload
sizes are negotiated end to end, minus its cookie, its client-subnet option and
its keepalive request, which all stop here; a query with two OPT records, or with
one whose options cannot be read, is answered FORMERR rather than forwarded, no
such message being one they can be taken back out of. Then DNS cookies in both
directions, [EDNS(0) padding](edns.md#edns-padding) in both directions on DoT and DoH and
on neither of the clear transports, the
[connection idle timeout](edns.md#telling-a-client-how-long-its-connection-is-held) told
to a TCP or DoT client that asks for it, truncation with the TC bit and the
UDP→TCP retry, `version.bind`/`hostname.bind` in the CHAOS class, local NODATA answers
for `resolver.arpa`, refusal of zone-transfer requests, and the reserved names of
RFC 6761 and RFC 7686 answered here instead of forwarded.

## Known limitations

- Where the host's crypto policy forbids SHA-1, zones signed only with RSA/SHA-1 (algorithms 5 and 7) validate as insecure delegations; see [DNSSEC](dnssec.md#watch-out).
- [Rebinding protection](rebinding.md#dns-rebinding-protection) covers A, AAAA, ANY, SVCB and HTTPS questions only.
- TCP, DoT and DoH use a thread per connection, capped by `server.max_connections` and per prefix by `server.max_connections_per_prefix` (UDP uses reader threads and holds no per-client state); see [sizing](sizing.md#transports).
- Past what the UDP readers can drain, the kernel drops datagrams before any budget sees them; see [how fast datagrams can be read](connections.md#how-fast-datagrams-can-be-read).
- The handshake bound is per /24 and /64, and a refusal is cheap rather than free; see [a connection rate limit in front](public-resolver.md#a-connection-rate-limit-in-front).
- Upstream I/O is synchronous: a worker is held for each round trip; see [sizing](sizing.md#sizing).
- Upstream cookies go only on queries that carry an OPT record, so a non-EDNS client gets none unless DNSSEC validation is on (the default); cookie secrets are never rotated, so a restart costs each peer one round trip. See [DNS cookies](edns.md#dns-cookies).
- elodin does not advertise its own DoT/DoH over DDR: `resolver.arpa` is answered NODATA ([resolver.arpa](dnssec.md#resolverarpa)). Point clients at the encrypted listeners by configuration, the [Apple profile](doh.md#apple-devices-ios-ipados-macos), or a `rewrites` rule.
- EDNS Client Subnet is not implemented: a client's option is dropped upstream and cannot be forwarded, since the cache is not keyed per network (RFC 7871 section 7.3).
- No per-client rules, query log database, or web/API surface; statistics go to the [log](logging.md#stats) and [metrics](metrics.md#metrics).
- Configuration is read once at startup; only `SIGHUP` reloads, and only the DoT/DoH certificates ([signals](install.md#signals)).
