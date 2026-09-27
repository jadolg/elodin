# Upstreams

```yaml
upstream:
  strategy: failover               # failover | round_robin | race
  timeout: 5s
  attempts: 2
  max_idle: 8                      # pooled connections per https/1.1 upstream
  idle_timeout: 30s
  bootstrap: [1.1.1.1, 9.9.9.9]    # resolves upstream hostnames
  servers:
    - name: cloudflare-dot
      type: tls                    # udp | tcp | tls | https
      address: 1.1.1.1
      port: 853
      hostname: cloudflare-dns.com # SNI and certificate name
    - https://dns.google/dns-query
    - tcp://9.9.9.9
    - 192.168.1.1
  zones: []                        # per-domain routes; see below
```

| `strategy`    | behaviour                                                        |
|---------------|------------------------------------------------------------------|
| `failover`    | try servers in configured order until one answers                |
| `round_robin` | the same, but the starting position advances on every query      |
| `race`        | query every healthy server at once, take the first usable answer |

`race` multiplies upstream traffic by the number of servers.

`bootstrap` resolves upstream hostnames. elodin does not use the system resolver
for them, since on a machine where elodin *is* the system resolver that would
loop back to a server that has not started yet.

## Time budget

A query waits at most about two `timeout`s on its upstreams, however many servers
and `attempts` there are, then answers SERVFAIL (a `race` forward: one). The
budget covers the whole question — the forward, the DNSSEC chain lookups, and
both groups a routed apex `DS` asks — counted from its first exchange; a lookup
that finds none left asks nobody. A rewrite alias's target is a lookup of its
own, with a budget of its own. With routes of different `timeout`s, the budget
is two of the longest among the question's route and the default group.

Within it, a dead first server hands over to the second, which gets its full
`timeout`; a third waits for the next query. A SERVFAIL, REFUSED or referral reply sends
the query on to the rest of the group (see [rcodes](#rcodes-and-the-rest-of-the-group)).
A query waiting on an identical one already in flight waits for what is left of
the budget plus one more span, and a forward of its own after that gets only
what is left.

One exchange with one server takes its `timeout`, whatever it does inside:
resolving a hostname through `bootstrap`, asking again with a fresh DNS cookie,
retrying a truncated answer over TCP. A truncated answer that arrives late
leaves its TCP retry little time, and fails rather than doubling the wait. The
only overruns left are about a second: a TCP or DoT server finishing a message it
has started sending, and a dead DoH connection being torn down before the next is
dialled.

## Failures and the cooldown

An upstream that fails three times in a row is skipped for ten seconds. If every
member is in that state they are tried anyway, as far as the budget allows — on
the second attempt, so `attempts: 1` gives up instead, or all at once under
`race`.

A dial that fails, a handshake that fails and a timeout all count. A peer that
hangs up before sending a byte of the reply does not, on its own: DNS-over-TCP
servers recycle idle connections, so the query is simply retried at once on a
fresh connection. A sustained run of those hang-ups does count, and parks the
server a few queries later than an unreachable one;
`elodin_upstream_failure_kind_total{error="peer_closed"}` names such a server.

Each *kind* of failure is logged once at `warn`, with the transport and address,
and at `debug` after that; `elodin_upstream_failures_total` and
`elodin_upstream_failure_kind_total` count every one. A member that fails every
few queries while the rest of the group covers for it is never parked, and this
line is the only place it shows up.

```
level=warn msg="upstream quad9-dot (TLS 9.9.9.9): Timeout"
level=warn msg="upstream quad9-dot: TLS handshake with \"dns.quad9.net\" failed: certificate has expired"
```

| kind | meaning |
|---|---|
| `Timeout` | nothing usable arrived inside `upstream.timeout`, including a TLS or HTTPS session that handshook and then went quiet |
| `Peer_Closed` | the peer hung up before a byte of the reply arrived, and hung up again on the retry |
| `IO_Error` | the transport failed on an established session, including a reply cut off partway |
| `Bad_Response` | a reply arrived and was thrown away: it did not echo the question, or on `udp://`/`tcp://` lacked the DNS cookie the query carried |
| `TLS_Failed`, `Verify_Failed` | the handshake; the log line carries OpenSSL's reason |

`Bad_Response` on a `udp://` or `tcp://` upstream means answers are arriving and
being refused. An anycast resolver whose nodes do not share a cookie secret does
that; `cookies.upstream: false` is the test, and the fix if it is.

## Connections

- `tcp://` and `tls://` upstreams pipeline every query onto one shared
  connection (RFC 7766 section 6.2.1.1).
- `https://` picks HTTP/2 or HTTP/1.1 by ALPN, preferring h2, and remembers the
  choice from the first connection. h2 multiplexes onto one connection; HTTP/1.1
  pools up to `max_idle` idle connections.
- `idle_timeout` is a ceiling. An upstream that hangs up after an idle gap has
  its connections reaped at three quarters of that gap from then on, never below
  two seconds; the learned figure only comes down, and is forgotten after an
  hour.
- A TLS handshake the peer resets partway through is retried once. Only a reset
  is retried.

## Rcodes and the rest of the group

An upstream's rcode is the client's answer, with two exceptions.

**SERVFAIL and REFUSED** say something about the server, not the name — an ACL,
its own recursion down, throttling. The rest of the group is asked instead, and
the member keeps its place and its health. If nobody does better, as with a
single upstream, the client gets the rcode that arrived. The member passed over
is counted in `elodin_upstream_swept_rcode_total{upstream}`.

**A referral** — a server that does not recurse for the name answering with a
zone's NS and no SOA, alone or after a CNAME into that zone — is swept the same
way. If no member does better the client gets SERVFAIL (`outcome=failed
detail=referral`), not an empty NOERROR it would read as "no such record". A
referral past a CNAME whose target is routed to another group is still swept,
then handed on as it stands, since the client's next question goes there.

Not swept, because they are statements about the name:

- a SERVFAIL carrying an RFC 8914 extended error of 6 to 12, a DNSSEC verdict.
  This only matters with `dnssec.enabled: false`: with validation on, queries go
  out with CD set and elodin judges the answer itself. It also needs an upstream
  that sends extended errors (Unbound only with `ede: yes`; dnsmasq never) and a
  client that asked with EDNS. An upstream whose own validation is broken is
  believed, and has to be taken out of the group.
- a REFUSED carrying extended error 15, 16 or 17 (blocked, censored, filtered),
  so a filtering resolver that says what it did stays usable in a group. Code 18
  (prohibited) is about the client and is swept.

A filtering member that does not say why it refused has its blocks answered by
the member beside it; elodin warns the first time. `dnssec.enabled: false` with
more than one server in a group gets a startup line for the same reason. Put an
upstream meant to filter on its own, or behind a route.

The sweep costs up to one extra exchange per remaining member, and stops asking
once it has spent one `timeout` or what is left of the budget, whichever is less
— so a query's worst case is three timeouts. A failure that cost nothing, such
as an unresolvable hostname, does not stop it, and a member this query already
failed to reach is not asked again. A live spare behind a member that swallows
the whole timeout is reached once that member is parked, three queries later. REFUSED from a rate-limiting upstream is
swept too, with no backoff; watch `elodin_upstream_swept_rcode_total` on a group
of two public resolvers under one busy client.

**Extended rcodes of 16 and above** (the eight bits in the OPT record, RFC 6891
section 6.1.3) are not passed on, since a stub reads only the header's four: a
BADVERS would read as NOERROR with no answer. The other members out of cooldown
are asked; if none answers readably the client gets SERVFAIL, with extended error
0 naming the rcode if it asked with EDNS. These show as `outcome=failed
detail=rcode:<upstream>`, `unreadable_rcode=` in the stats line and
`elodin_upstream_unreadable_rcode_total{upstream}`, and warn once. They are not
counted as upstream failures, since the bytes are forgeable and one forged packet
per query would otherwise park the whole group. A client's own EXTENDED-RCODE
bits are cleared before forwarding, as RFC 6891 requires.

## What a forwarded query carries

- The EDNS payload size is the client's figure held between 512 and 1232 bytes
  (RFC 9715), so no client can have the upstream send it fragmented UDP.
- On `udp://`, an answer that does not fit comes back truncated and is fetched
  again over TCP. Over streams the figure bounds nothing (RFC 7766 section
  6.2.1.1); an upstream that truncates a stream reply anyway has it passed on as
  it is, and cannot serve answers over 1232 bytes through elodin.
- A query with an OPT record outside the additional section, a second OPT, or
  OPT options that do not parse is answered FORMERR and not forwarded.

## Per-domain upstreams

If something on your network answers for a zone of its own — a domain controller
for `corp.example`, a router that answers `home.arpa`, a lab server with an
internal `.test` — route that zone to it:

```yaml
upstream:
  servers: [1.1.1.1, 9.9.9.9]     # everything else
  zones:
    - domains: [corp.example]
      servers: [10.0.0.1]         # the domain controller
    - domains: [home.arpa]
      servers: [192.168.1.1]      # the router
```

This is dnsmasq's `server=/corp.example/10.0.0.1`, unbound's `forward-zone`,
blocky's `conditionalMapping` and AdGuard Home's `[/corp.example/]10.0.0.1`.

A route takes anything `upstream` takes — `strategy`, `timeout`, `attempts`,
`max_idle`, `idle_timeout`, `bootstrap`, and servers of every transport — and
inherits whatever it does not set:

```yaml
upstream:
  timeout: 3s
  servers: [1.1.1.1]
  zones:
    - domains: [corp.example, corp.internal]
      strategy: race
      servers:
        - name: dc1
          type: tls
          address: 10.0.0.1
          hostname: dc1.corp.example
        - 10.0.0.2
    - domains: [dev.corp.example]   # longest match wins for names under dev
      servers: [10.1.0.1]
```

`domains` matches on label boundaries and ignores case: `corp.example` covers
itself and everything under it, not `notcorp.example`. The longest match wins.

The routing table is built at startup, so restart after changing a route.
`--check` and the startup log print one line per route that gives something up,
from the two points below.

### What a route implies

- **The zone is not validated.** A local zone is unsigned under a public parent
  that does not delegate it, so validating it would call every answer bogus.
  Routed names are served without the AD bit. A
  [`trust_anchors`](dnssec.md#dnssec) entry covering the zone turns the bypass
  off — which validates the zone only if the public tree delegates to it. Note
  that `trust_anchors` *replaces* the built-in root keys, so list the root DS as
  well.
- **The zone may answer with private addresses.**
  [Rebind protection](rebinding.md#dns-rebinding-protection) exempts a routed
  zone without a `rebind.allow_domains` entry.

A route into a zone that [`special_use`](reserved-names.md#reserved-names)
already answers is refused at load; turn that key off in the same edit. The
exception is `special_use.private_reverse`, which stands down for a routed name,
so a route is how a reverse zone reaches your router.

> **Coming from dnsmasq:** `server=/corp.example/10.0.0.1` in `blocking.rules`
> or `blocking.allow` does not route the zone; it is discarded.
> `server=/corp.example/` with no server, in `blocking.rules`, *blocks* the zone.
> `--check` warns about either when written inline in `blocking.rules` or
> `blocking.allow`. Routing lives under `upstream.zones` only.

### DS at a route's apex

The DNSSEC chain walk's own `DS` and `DNSKEY` lookups always go to
`upstream.servers`, never down a route: a local server answers `DS` for its zone
from its own data, which breaks the chain.

A client's `DS` query for a route's apex (say `home.arpa DS`) is the one question
about a routed zone that goes to the parent's upstreams — `upstream.servers`, or
the route covering the parent. The signed proof lives in the parent, and a
validating client below elodin needs it; RFC 8375 section 4 item 4.B requires
forwarding it. Names below the apex, and the apex `DNSKEY`, stay on the route.
That query names only the zone, so it is all the public upstream learns.

The parent's answer is kept only if it is "no data" — the delegation exists and
has no DS. Anything else goes to the route:

| parent says | why the route answers instead |
|---|---|
| NXDOMAIN | the public tree does not delegate the zone; a signed denial would make a validating client (RFC 8020) treat every name under it as gone |
| a DS record | split horizon: the internal view has no matching key, so the client would get bogus. To validate a mirror of a signed zone, anchor it |
| SERVFAIL, REFUSED, a NOERROR whose answer is not a DS, or nothing | nothing about the delegation was established. The rest of the parent's group is asked first |

If the route cannot be reached either, the answer is SERVFAIL (or a stale entry
with `cache.serve_stale`), never the parent's denial. If the parent's whole group
is in its cooldown, the route is asked directly, provided the route is not also
in its own.

An answer the route gave because the parent said nothing is not cached, so the
next query tries the parent again. The exception: after three such replies in a
row from the parent's group, each within ten seconds of the last, the route is
asked first for the next ten seconds. That memory holds up to eight apexes and
skips anchored zones. An answer given because the parent said NXDOMAIN or sent a
DS is cached normally.

A parent also says "no data" about a name inside its own zone that is not a
delegation — `corp.example.com` published as an A record there. elodin cannot
tell that apart and passes the proof on, which makes a validating client treat
the local answers below it as bogus, correctly. Anchor such a zone, or do not
route a name the public tree publishes.
