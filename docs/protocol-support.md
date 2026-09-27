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

- DNSSEC validation is on by default, and where a distribution's crypto policy
  forbids SHA-1 signatures the two RSA/SHA-1 algorithms degrade to insecure
  delegations rather than validating. Start-up says so, and refuses to start
  outright if the policy leaves no trust anchor followable; see
  [DNSSEC](dnssec.md#dnssec).
- [Rebinding protection](rebinding.md#dns-rebinding-protection) runs only for A, AAAA, ANY,
  SVCB and HTTPS questions — the ones a browser can be made to ask. Addresses in
  the additional section are left alone unless the answer carried an SVCB or
  HTTPS record.
- **Connection-oriented transports get a thread per connection**, capped for TCP,
  DoT and DoH together by `server.max_connections` and per client prefix by
  `server.max_connections_per_prefix`. That suits clients that hold a connection
  open and pipeline over it, not tens of thousands of concurrent connections. UDP
  is the exception: a reader thread per usable CPU, to eight, and no per-client
  state.
- **Past what the UDP readers can drain, the kernel decides who is served.**
  Datagrams that overflow a receive queue are dropped by the socket, so no budget
  in this server applies to them; `listeners.udp.readers` raises the rate at which
  that starts and does not remove it. A publicly reachable instance wants a packet
  filter in front of it. See [how fast datagrams can be
  read](connections.md#how-fast-datagrams-can-be-read) for the measured figure.
- **The bound on TLS handshakes is per prefix, and a refusal is cheap rather than
  free.** Opening a connection is charged to
  `server.rate_limit.responses_per_second`, which held a 32-worker flood to 462
  handshakes a second and 0.29 of four cores against 6,032 and 1.25 uncharged. But
  it is keyed on the /24 and /64 like every other budget here, so an actor with
  addresses in several prefixes has several copies of it, and the flood's *dial*
  rate rose four times once being refused was cheap — the DoT bystander in that run
  recovers to 88% of its queries answered where the quiet baseline is 98%. A UDP
  bystander is untouched either way, which the same report measures. A publicly
  reachable instance wants a per-source connection rate limit in front of it: see
  [a connection rate limit in front](public-resolver.md#a-connection-rate-limit-in-front), and
  `bench/results/2026-09-04-handshake-budget.md` for the figures.
- **Upstream I/O is synchronous**, so concurrency is bounded by thread count
  rather than by in-flight queries. The h2 upstream client multiplexes onto one
  connection, but a worker is still held for the round trip. Async upstream I/O
  would lift this and the connection item above; the UDP half of it is done, the
  readers being behind `SO_REUSEPORT` since #233.
- **DNS cookies do not cover every query.** Only queries that already carry an
  OPT record are given one upstream, so a non-EDNS client behind elodin gets no
  cookie protection unless DNSSEC validation is on — which it is by default.
  Cookie secrets are drawn once at startup and never rotated: restarting costs
  each client and each upstream one extra round trip.
- **elodin does not advertise its own DoT or DoH endpoints over DDR.**
  `resolver.arpa` is answered NODATA rather than forwarded, which keeps clients
  here, but nothing designates its encrypted listeners automatically: point
  clients at them by configuration, by the [Apple
  profile](doh.md#apple-devices-ios-ipados-macos), or by a `rewrites` rule.
- **EDNS Client Subnet is not implemented, and a client's option is dropped on
  the way upstream** (RFC 7871). Forwarding one is only correct alongside the
  per-network caching of section 7.3, which this cache does not do — its key is
  the question plus the DO and CD bits — so a subnet a client named would steer
  the answer every other client behind elodin is then given, and would tell a
  public upstream where that client claims to be. Nothing is sent in its place,
  and there is no setting to turn forwarding back on, because there is nowhere
  honest to file the answers yet.
- No per-client rules, no query log database, no web or API surface. Statistics
  go to the log every five minutes, and to a Prometheus endpoint when
  [`metrics.enabled`](metrics.md#metrics) is set — counters only.
- Configuration is read once at startup, with one exception: `SIGHUP` reloads the
  DoT/DoH certificates. Listener addresses, the upstream set and blocking need a
  restart.
