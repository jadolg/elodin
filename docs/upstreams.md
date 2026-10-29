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

`race` multiplies upstream traffic by the number of servers. The servers that
lose a race are left to answer or time out, so a server that keeps timing out is
still counted as failing and paused ([the cooldown](#failures-and-the-cooldown)). Every race query counts
against a process-wide budget, until it is answered or times out: `server.max_pending`
times the servers of the widest racing group, which ordinary load does not reach
and a member that stops answering - its losers waiting out the timeout - can.
Past it a race asks as many servers at once as there is room for, and with no
room asks them in turn, as `failover` does.

`bootstrap` resolves upstream hostnames. elodin does not use the system resolver
for them, since on a machine where elodin *is* the system resolver that would
loop back to a server that has not started yet. Each entry is an IP address with
an optional port (`9.9.9.9`, `[2620:fe::fe]:53`); a name there is a config error.

An `https` upstream is sent its url from the path on, query included
(`https://dns.example/dns-query?profile=ab12`), as the target of each POST. A
url with no path is sent to `/`.

A server's `name` is what the log and the `upstream` label on
[`/metrics`](metrics.md) call it. Without one it is `udp://`, `tcp://` or
`tls://` with the address and port, or for `https` the url up to its query, so
`https://dns.example/dns-query?token=…` goes by `https://dns.example/dns-query`:
a key in the query reaches neither. Two `https` servers whose urls differ only
in the query would share that name, and are refused at load, as is a `name:`
that is another server's url up to its query or fragment; give one a `name:` of its own,
which the map form of a server takes. Servers that share a name otherwise, one
set on several of them included, are counted as one.

## Time budget

`timeout` is from `1ms` to `24h`, at the top level and on a route; `0` is
refused at load rather than read as "no limit", since a query is given two of it.

A query waits at most about two `timeout`s on its upstreams, however many servers
and `attempts` there are, then answers SERVFAIL (a `race` forward: one). The
budget covers the whole question — the forward, the DNSSEC chain lookups, and
both groups a routed apex `DS` asks — counted from its first exchange; a lookup
that finds none left asks nobody. A rewrite alias's target is a lookup of its
own, with a budget of its own. With routes of different `timeout`s, the budget
is two of the longest among the question's route, the default group and every
route at, above or below a [`trust_anchors`](dnssec.md#trust-anchors) zone. That
last applies to every question, since any answer can CNAME into an anchored
zone.

Within it, a dead first server hands over to the second, which gets its full
`timeout`; a third waits for the next query. A SERVFAIL, REFUSED or referral reply sends
the query on to the rest of the group (see [rcodes](#rcodes-and-the-rest-of-the-group)).
A query waiting on an identical one already in flight waits for what is left of
the budget plus one more span, and a forward of its own after that gets only
what is left.

One exchange with one server takes its `timeout`, whatever it does inside:
connecting and the TLS handshake, however slowly the server sends it, resolving
a hostname through `bootstrap`, asking again with a fresh DNS cookie,
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
| `Timeout` | nothing usable arrived inside `upstream.timeout`, including a TLS handshake that did not finish in it and a TLS or HTTPS session that handshook and then went quiet |
| `Peer_Closed` | the peer hung up before a byte of the reply arrived, and hung up again on the retry |
| `IO_Error` | the transport failed on an established session, including a reply cut off partway |
| `Bad_Response` | a reply arrived and was thrown away: it did not echo the question, or on `udp://`/`tcp://` lacked the DNS cookie the query carried |
| `Too_Large` | an `https` 200 longer than a DNS message (65535 bytes, RFC 8484 section 6), over HTTP/2 or HTTP/1.1; over HTTP/2 also a stream whose DATA, padding included, passes half the 1 MiB receive window. A declared `Content-Length` past it is refused before the body is read; it is not retried on a fresh connection. Any other status is `HTTP_Error` whatever the size of its body |
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
- Idle connections are swept every 30 seconds: pooled HTTP/1.1 connections and
  the shared h2 or pipelined connection are closed at the first sweep after
  they have gone unused for `idle_timeout`, so they can live up to 30 seconds
  longer, and a shared one the peer has closed goes at the next sweep. One with
  a query still on it is left to finish.
- `idle_timeout` is a ceiling. A `tcp://` or `tls://` upstream that hangs up
  after an idle gap has its pipelined connection reaped at three quarters of
  that gap from then on, never below two seconds; the learned figure only comes
  down, and is forgotten after an hour.
- A TLS handshake the peer resets partway through is retried once, inside the
  same `timeout`. Only a reset is retried.

## Rcodes and the rest of the group

An upstream's rcode is the client's answer, with two exceptions.

**SERVFAIL and REFUSED** say something about the server, not the name — an ACL,
its own recursion down, throttling. The rest of the group is asked instead, and
the member keeps its place and its health. If nobody does better, as with a
single upstream, the client gets the rcode that arrived. The member passed over
is counted in `elodin_upstream_swept_rcode_total{upstream}`.

**A referral** — a server that does not recurse for the name answering with a
zone's NS and no SOA, alone, after a CNAME into that zone, or after a CNAME whose
target cannot be read — is swept the same way. If no member does better the
client gets SERVFAIL (`outcome=failed detail=referral`), not an empty NOERROR it
would read as "no such record". A referral past a CNAME whose target is routed
to another group is still swept, then handed on as it stands, since the client's
next question goes there.

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

**A malformed OPT record** — one outside the additional section, a second one,
one owned by a name other than the root, or one whose options do not parse
(RFC 6891 sections 6.1.1 and 6.1.2) — is swept the same
way and counted in `elodin_upstream_swept_rcode_total`. If no member does better
the client gets SERVFAIL (`outcome=failed detail=opt:<upstream>`), with extended
error 0 if it asked with EDNS, and elodin warns once a window per upstream. A
DNSSEC chain lookup answered this way is a lookup that could not be made.

## What a forwarded query carries

- The EDNS payload size is the client's figure held between 512 and 1232 bytes
  (RFC 9715), so no client can have the upstream send it fragmented UDP.
- On `udp://`, an answer that does not fit comes back truncated and is fetched
  again over TCP. Over streams the figure bounds nothing (RFC 7766 section
  6.2.1.1); an upstream that truncates a stream reply anyway has it passed on as
  it is, and cannot serve answers over 1232 bytes through elodin.
- A query with an OPT record outside the additional section, a second OPT, an
  OPT owned by a name other than the root, or OPT options that do not parse is
  answered FORMERR and not forwarded.

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

A [reload](install.md#signals) rebuilds the routing table along with the upstreams.
`--check` and the startup log print one line per route that gives something up,
from the two points below.

### What a route implies

- **The zone is not validated.** A local zone is unsigned under a public parent
  that does not delegate it, so validating it would call every answer bogus.
  Routed names are served without the AD bit. A
  [`trust_anchors`](dnssec.md#trust-anchors) entry covering the zone turns the
  bypass off and validates the zone against that anchor, with its keys fetched
  from the route's servers. Note that `trust_anchors` *replaces* the built-in
  root keys, so list the root DS as well.
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

The DNSSEC chain walk's own `DS` and `DNSKEY` lookups go to
`upstream.servers`, not down a route: a local server answers `DS` for its zone
from its own data, which breaks the chain. The exception is a zone covered by a
[`trust_anchors`](dnssec.md#trust-anchors) entry, where the walk starts at the
anchor and asks the route's servers for the zone's own keys.

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
| "no data", but its NSEC or NSEC3 shows no delegation at the apex: NS bit clear, SOA bit set, or the name absent | the parent holds the name itself (say `corp.example.com` published as an A record), so there is no insecure delegation to prove (RFC 4035 section 5.2, RFC 6840 section 4.4). The route's answer is not cached, the records being unvalidated — except a compact denial (an NSEC with NXNAME, RFC 9824), which is cached like NXDOMAIN |
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

A "no data" with no NSEC or NSEC3 beside it is kept: the parent is unsigned, so
there is no chain below it to break. So is one whose NSEC3 records are past
`dnssec.max_nsec3_iterations`, or that shows only an opt-out span, since neither
shows the name is not a delegation. The records are read, not validated; the
client validates what it is handed.

A strict validating client treats the route's unsigned answers below a name the
signed parent holds as bogus, correctly. Anchor such a zone, or do not route a
name the public tree publishes.
