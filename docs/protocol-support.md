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
are cleared (AA is set only on answers from the zones elodin serves itself, see
[reserved names](reserved-names.md)), RA is set, and RD and CD are the client's own (RFC 1035 section
4.1.1, RFC 4035 section 3.2.2). The AD bit is covered under [DNSSEC](dnssec.md).

A message with the QR bit set is a response (RFC 1035 section 4.1.1), and one
arriving on a listener is dropped off its header before anything else is read:
over UDP and TCP/DoT it gets no reply, not even FORMERR, and over UDP it is not
charged to the [rate limit](rate-limiting.md), so it never draws a slip. Over DoH it
is answered **400**. It counts in `elodin_queries_dropped_total`, not as a query.

A query asking more than one question is answered FORMERR (RFC 9619 section 4),
whatever EDNS version it asks in, and no answer echoes more than one question.

A name whose compression pointer aims into the 12-byte header is not read as a
name. Those bytes are ones elodin writes per client (the ID, AD, and ARCOUNT
when an OPT record is added or removed), so the client would read a different
name from the one elodin checked. A query carrying one is answered FORMERR. An
answer carrying one in an owner name is handled like any answer that does not
decode: it is not cached, and [rebinding protection](rebinding.md) refuses it.
One inside a record's data (a CNAME, NS or MX target) leaves that record unread,
kept as the bytes it arrived as like any record data that does not decode; with
blocking on, a CNAME kept that way has the answer refused.

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
UDP→TCP retry, `version.bind`/`version.server`/`hostname.bind`/`id.server` in the CHAOS class (or withheld, see
[`server.identity`](access-control.md#what-it-says-about-itself)), local answers for
`resolver.arpa`, with this server's own DoT/DoH endpoints designated over
[DDR](doh.md#discovery-by-clients-ddr) when `ddr.name` is set, refusal of zone-transfer requests, and the reserved names of
RFC 6761 and RFC 7686 answered here instead of forwarded.

Some question types are answered here and never forwarded. Each is logged as
`outcome=refused`, whatever its rcode, with the detail below:

- OPT, TKEY, TSIG and the rest of types 128 to 250, NXNAME included, in any
  class: FORMERR with extended error 30 (Invalid Query Type), `detail=meta-type`.
  These types describe one message on one hop and mean nothing to an upstream
  (RFC 6895 section 3.1, RFC 9824 section 3.5).
- AXFR and IXFR: REFUSED, `detail=xfr`.
- MAILA and MAILB: NOTIMP, `detail=qtype`.

ANY is forwarded ([RFC 8482](https://www.rfc-editor.org/rfc/rfc8482)).

TLS is 1.2 or 1.3, on the DoT and DoH listeners and towards upstreams and list
hosts alike. Over TLS 1.2 the only suites are ECDHE with AES-GCM or
ChaCha20-Poly1305 (RFC 9325 section 4.2), and the listeners pick by their own
order, keeping ChaCha20 for a client that puts it first. TLS 1.3 follows the
same order: AES-128-GCM, AES-256-GCM, then ChaCha20-Poly1305. A peer that speaks
TLS 1.2 only, with none of those suites, cannot connect: static RSA, CBC and
finite-field DHE are not offered (RFC 9325 sections 4.1 and 4.2, and RFC 9113
Appendix A for DoH over HTTP/2). TLS 1.2 renegotiation is off at both ends (RFC 9113
section 9.2.1): a server's request for one is answered with a no_renegotiation
alert and the connection carries on, and a client's is refused.

A UDP answer leaves from the address its query was sent to, also on a
wildcard bind (`0.0.0.0` or `::`), as RFC 1123 section 2.3 asks of a
multihomed host. A host with several addresses, a VIP, or IPv6 temporary
addresses can be asked at any of them, and a client that checks where an answer
came from accepts it.

## Known limitations

- DNSSEC trust anchors are not updated in-band (no RFC 5011): a root KSK after KSK-2024 needs a new release or a `trust_anchors` change, and a new KSK for a zone you anchor yourself needs a `trust_anchors` change; see [trust anchors](dnssec.md#trust-anchors).
- Where the host's crypto policy forbids SHA-1, zones signed only with RSA/SHA-1 (algorithms 5 and 7) validate as insecure delegations; see [DNSSEC](dnssec.md#watch-out).
- [Rebinding protection](rebinding.md#dns-rebinding-protection) covers A, AAAA, ANY, SVCB and HTTPS questions only.
- TCP, DoT and DoH hold a fiber per connection, capped by `server.max_connections` and per prefix by `server.max_connections_per_prefix` (UDP holds no per-client state); see [sizing](sizing.md#transports).
- Past what the UDP readers can drain, the kernel drops datagrams before any budget sees them; see [how fast datagrams can be read](connections.md#how-fast-datagrams-can-be-read).
- The handshake bound is per /24 and /64, and a refusal is cheap rather than free; see [a connection rate limit in front](public-resolver.md#a-connection-rate-limit-in-front).
- The upstream client cookie is drawn afresh about daily (RFC 7873 §7.1) and on a restart; the next query carries the new client cookie alone, and the server cookie is learned from its answer. See [DNS cookies](edns.md#dns-cookies).
- [DDR](doh.md#discovery-by-clients-ddr) designates one name, and clients only use it automatically if the certificate has the Do53 address as an IP SAN, or the server is on a private address that `ddr.name` resolves to. Otherwise point clients at the encrypted listeners by configuration or the [Apple profile](doh.md#apple-devices-ios-ipados-macos).
- EDNS Client Subnet is not implemented: a client's option is dropped upstream and cannot be forwarded, since the cache is not keyed per network (RFC 7871 section 7.3).
- No per-client rules, query log database, or web/API surface; statistics go to the [log](logging.md#stats) and [metrics](metrics.md#metrics).
- `SIGHUP` reloads the configuration and the certificates, except the listeners, `ddr`, the metrics endpoint, the loop count, their pinning and connection-table sizes, `server.user`/`group` and `blocking.cache_dir`, which need a restart ([signals](install.md#signals)).
