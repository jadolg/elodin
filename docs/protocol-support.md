# What is implemented, and what is not

## What is implemented

Queries of any type are answered: A, AAAA, CNAME, MX, TXT, SRV, SOA, NS, PTR,
CAA, SVCB/HTTPS, DS, DNSKEY, RRSIG and everything else. Types the codec does not
model natively are carried through as opaque RDATA per RFC 3597, and forwarded
answers are passed back byte for byte, so DNSSEC records survive untouched. The
one change made to opaque RDATA is to a domain name an upstream compressed inside
it - as older servers still do in an AFSDB or RP, and as RFC 4034 forbids in an
RRSIG signer or an NSEC next name: it is expanded (RFC 3597 section 4), so a
rebuilt answer still names the host the upstream named. With
validation on, an answer for a client that did not ask for DNSSEC records is
rebuilt without them; every other answer goes back as the upstream sent it, bar the OPT
record this server answers with, from the cache, TTLs counted down, and the header
flags that describe this server rather than the data: AA and the reserved Z bit
are cleared, RA is set, and RD and CD are the client's own (RFC 1035 section
4.1.1, RFC 4035 section 3.2.2). The AD bit is covered under [DNSSEC](dnssec.md).

Also handled: EDNS0 — elodin forwards a query of its own built from the
question, with an OPT record at 1232 bytes and none of the client's options, and
fits the answer to the client's payload size on the way back (see [What reaches
the upstream](edns.md#what-reaches-the-upstream)); a query with two OPT records,
one outside the additional section, one owned by a name other than the root, or
one whose options cannot be read, is answered FORMERR. Then DNS cookies in both
directions, [EDNS(0) padding](edns.md#edns-padding) in both directions on DoT and DoH and
on neither of the clear transports, the
[connection idle timeout](edns.md#telling-a-client-how-long-its-connection-is-held) told
to a TCP or DoT client that asks for it, truncation with the TC bit and the
UDP→TCP retry, `version.bind`/`hostname.bind` in the CHAOS class, local answers for
`resolver.arpa`, with this server's own DoT/DoH endpoints designated over
[DDR](doh.md#discovery-by-clients-ddr) when `ddr.name` is set, refusal of zone-transfer requests, and the reserved names of
RFC 6761 and RFC 7686 answered here instead of forwarded.

## Known limitations

- Where the host's crypto policy forbids SHA-1, zones signed only with RSA/SHA-1 (algorithms 5 and 7) validate as insecure delegations; see [DNSSEC](dnssec.md#watch-out).
- [Rebinding protection](rebinding.md#dns-rebinding-protection) covers A, AAAA, ANY, SVCB and HTTPS questions only.
- TCP, DoT and DoH hold a fiber per connection, capped by `server.max_connections` and per prefix by `server.max_connections_per_prefix` (UDP holds no per-client state); see [sizing](sizing.md#transports).
- Past what the UDP readers can drain, the kernel drops datagrams before any budget sees them; see [how fast datagrams can be read](connections.md#how-fast-datagrams-can-be-read).
- The handshake bound is per /24 and /64, and a refusal is cheap rather than free; see [a connection rate limit in front](public-resolver.md#a-connection-rate-limit-in-front).
- Upstream cookie secrets are never rotated, so a restart costs each peer one round trip. See [DNS cookies](edns.md#dns-cookies).
- [DDR](doh.md#discovery-by-clients-ddr) designates one name, and clients only use it automatically if the certificate has the Do53 address as an IP SAN, or the server is on a private address that `ddr.name` resolves to. Otherwise point clients at the encrypted listeners by configuration or the [Apple profile](doh.md#apple-devices-ios-ipados-macos).
- EDNS Client Subnet is not implemented: a client's option is dropped upstream and cannot be forwarded, since the cache is not keyed per network (RFC 7871 section 7.3).
- No per-client rules, query log database, or web/API surface; statistics go to the [log](logging.md#stats) and [metrics](metrics.md#metrics).
- `SIGHUP` reloads the configuration and the certificates, except the listeners, `ddr`, the metrics endpoint, the loop count and connection-table sizes, `server.user`/`group` and `blocking.cache_dir`, which need a restart ([signals](install.md#signals)).
