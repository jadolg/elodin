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

However many servers and `attempts` there are, a query waits at most about two
`timeout`s on its upstreams before it gives up with SERVFAIL (a `race` forward
gives up after one, leaving the other for what follows it). That is the whole
question's figure, not each lookup's: the DNSSEC chain lookups and both groups a
routed apex `DS` asks all spend the same deadline, counted from its first
exchange, and a lookup that finds none left asks nobody. A rewrite alias's target
is a lookup of its own, with a deadline of its own.
With routes of different `timeout`s the deadline is two of the longest among
the groups the question can ask - its route, and the default group the chain
walk asks - so a fast LAN route does not starve the chain walk behind it, and a
slow route does not stretch the deadline of questions it never sees. A query
waiting on an identical one already in flight waits for what is left of the
same deadline, plus one more span for the leader's last exchange, and a forward of
its own after that gets only what the deadline has left. A dead first server still hands over to the second inside the query, which is asked with its
full `timeout`; a third is left for the next query, by which time the dead ones
are on their way to the cooldown below. A reply that did arrive but says
SERVFAIL or REFUSED sends the query on to the rest of the group, inside the
same two `timeout`s rather than on top of them. So does a referral - a server
that does not recurse for the name answering with the NS of a zone and no SOA,
on its own or after a CNAME whose target that zone holds - and where no member
does better the client gets SERVFAIL, not the empty NOERROR it would read as
"no such record" (`outcome=failed detail=referral` in the query log). A
referral past a CNAME whose target this server routes to another group is still
swept, and then handed on as it stands, since the client's next question goes
there. One exchange with one server
takes its `timeout`, whatever it does inside: resolving a hostname upstream
through `bootstrap`, asking again with a fresh DNS cookie, retrying a truncated
answer over TCP. A truncated answer that arrives late therefore leaves its TCP
retry little time, and fails rather than doubling the wait. What overruns
are left are about a second, and keep a shared connection sound: a TCP or DoT
server finishing a message it has already started sending, and a dead DoH
connection being torn down before the next is dialled.

`bootstrap` matters: elodin resolves upstream hostnames itself rather than
through the system resolver, since on a machine where elodin *is* the system
resolver the latter would come straight back to a server that has not started
listening yet.

An upstream that fails three times in a row is skipped for ten seconds; if every
upstream is in that state they are tried anyway — on the second attempt, so
`attempts: 1` gives up instead, or all at once under `race` — as many as the
two-`timeout` budget above leaves room for. One kind of failure is
exempt: a peer that hangs up without answering. Every DNS-over-TCP server
recycles its connections — of the two public resolvers this was measured
against, one closes an idle one after ten to fifteen seconds and the other
after five to ten — so a query landing on a connection that has just been
recycled is ordinary operation rather than an outage, and it is simply asked
again on a connection of its own. Letting a run of those trip the cooldown took
a server answering 97% of what it was asked out of service every couple of
minutes, and sent every query in each of those windows to the fallback. What
still parks an upstream at once is everything that says it is unreachable or
silent: a dial that failed, a handshake that failed, a connection that went
quiet until the timeout. The exemption is for a run rather than forever — a
server whose second connection is hung up on too, over and over, is parked a
few queries later than one that is simply unreachable, since otherwise it would
be asked for two connections per query indefinitely.
`elodin_upstream_failure_kind_total{error="peer_closed"}` is what names one.

No resolver in practice advertises edns-tcp-keepalive (RFC 7828), so the only
way to learn how long a peer will hold a connection is to be hung up on and
remember it. `upstream.idle_timeout` is therefore a ceiling rather than the
figure used: an upstream that hangs up after an idle gap has its connection
reaped at three quarters of that gap from then on, so the next query dials
instead of being handed something already gone. The learned value only ever
comes down, and never below two seconds; it is forgotten after an hour and
learned again, so a hang-up that was nothing to do with an idle timer — a
restart, a drain, a deploy — is not remembered as one for the life of the
process. A TLS handshake the peer
resets partway through is retried once first, since some public resolvers do that
to a fair share of fresh connections while the very next attempt goes through.
Only a reset is retried.

Each *kind* of failure an upstream produces is named once at `warn`, with the
transport and address, and left to `debug` after that:

```
level=warn msg="upstream quad9-dot (TLS 9.9.9.9): Timeout"
level=warn msg="upstream quad9-dot: TLS handshake with \"dns.quad9.net\" failed: certificate has expired"
```

Once per kind rather than once per exchange because the failure worth naming is
the one that never trips the cooldown. A member of a failover group that fails
every few queries, with the rest of the group covering for it, zeroes its
consecutive count on each success, so it is never parked and the warning above
about parking never fires — the only trace it left was a `debug` line and a
counter. Once per kind bounds the output at the size of the error list for the
life of the process, whatever the query rate does; the count is
`elodin_upstream_failures_total{upstream}`, and every individual failure is
still a `debug` line with how long it took.

What the kinds mean, on the transports where two of them used to look alike:

| | |
|---|---|
| `Timeout` | nothing usable arrived inside `upstream.timeout`. On `tls://` and `https://` this now includes a session that handshook and then went quiet, which used to be reported as `IO_Error` |
| `Peer_Closed` | the peer hung up *before a byte of the reply arrived*. Retried at once on a connection of this query's own — whether the connection was one it found already open or one it dialled itself — so what reaches the counter is a second hang-up as well. The one kind a single occurrence of which does not count towards the failure cooldown; a sustained run of them still does |
| `IO_Error` | the transport itself failed on an established session, which is neither of the two above — including a reply that started arriving and was cut off, since that is a server answering badly rather than one recycling a connection |
| `Bad_Response` | a reply arrived from the server we asked and was thrown away: it did not echo the question, or on `udp://`/`tcp://` it did not carry the DNS cookie the query went out with. On `udp://` this used to be indistinguishable from `Timeout`, since the loop passes over a datagram it will not accept and waits out the deadline |
| `TLS_Failed`, `Verify_Failed` | the handshake. `Error` has nowhere to carry OpenSSL's reason, so the line above carries it instead — it is the whole diagnosis, and `TLS_Failed` on its own is not |

`Bad_Response` on a `udp://` or `tcp://` upstream is worth reading closely: it
says this resolver is refusing answers that are arriving, not that the server is
unreachable. An anycast resolver whose nodes do not share a DNS cookie secret
does exactly that. `cookies.upstream: false` is the test, and the fix if it is.

An upstream's rcode is the client's answer, with two exceptions.

SERVFAIL and REFUSED are not answers about the name: RFC 2308 section 7.1 reads
the first as the server reporting on itself, and the second is it declining to
be asked — an ACL that no longer lists this resolver, its own recursion down,
throttling. A member of a failover group in that state answers promptly and
forever, which never trips the cooldown above, so the rest of the group is asked
instead and the first member keeps its place in the order. Where nobody does
better — a single upstream, the ordinary arrangement — the rcode that arrived is
still what the client is handed.

One SERVFAIL is exempt: the one carrying an RFC 8914 extended error that says
the name failed DNSSEC validation (codes 6 to 12). That is a verdict about the
name, and asking a member of the group that does not validate would fetch the
very answer the first member rejected — which matters with `dnssec.enabled:
false`, where nothing here is checking either. It is a second line rather than
the defence, and it has preconditions: the upstream has to send the extended
error, which several do not by default (Unbound needs `ede: yes`, dnsmasq has
none), and the client has to have asked with EDNS, since a reply to a query
without an OPT record cannot carry one. With `dnssec.enabled` on, as it ships,
the question goes out with CD set — so there is no SERVFAIL to read — and
validation here refuses the forgery whichever member of the group supplied it.
The other edge of it: an upstream whose own validation is broken, a drifted
clock or a stale root key, states one of these about every signed name and is
believed, so no failover happens for those names until it is taken out of the
group.

A REFUSED that carries an RFC 8914 extended error of 15, 16 or 17 — blocked,
censored or filtered — is exempt on the same grounds: those say the responder is
declining *this name* on policy, which is a statement about it, so a filtering
resolver (AdGuard Home, Blocky, an RPZ rule) stays usable as a member of a group
as long as it says what it did. Code 18, prohibited, is not exempt: that is the
responder declining this *client*, which is the ACL case the sweep exists for.

A filtering member that says nothing — most of them, today — has its blocks asked
of the member beside it and answered. The server says so once, at warn, the first
time it sweeps a REFUSED carrying no such code, naming the member; and
`dnssec.enabled: false` with any group of more than one server gets a line at
startup, for the same reason on the validation side. Neither changes what the
server does: an upstream meant to filter belongs on its own, as the only member
of its group or behind a zone route.

The member that was passed over is counted against its name in
`elodin_upstream_swept_rcode_total{upstream}`, since its health is deliberately
left alone and no other figure would name it.

What the sweep costs is up to one extra exchange per remaining member of the
group, and a bounded wait: the sweep counts what each exchange cost it and asks
nobody else once that reaches one `upstream.timeout`, or whatever is left of the
query's two once the first reply came back, whichever is less. The exchange that
crosses the line is allowed to finish, so the worst of the whole query is three
timeouts — what it rules out is the fourth and the fifth, however many spares a
group has. A failure
that cost nothing — a member whose hostname cannot be resolved, which never
parks either — is passed over rather than stopping the sweep. A live spare
standing behind one that swallows the whole timeout waits for that member to
accrue its three failures and be parked, three queries, after which the sweep
skips it and reaches the live one. A member this query has already failed to reach is not asked again
either, so a group with one dead member and one that declines pays that member's
timeout once rather than twice. Two upstreams — what the examples configure — pay
one extra exchange for a name the first cannot answer.

REFUSED is worth one more thought here, because it is also what some resolvers
answer when they are rate-limiting rather than when they are declining on
policy. Health is deliberately untouched for it, so there is no backoff: a
throttled member has its questions taken to the member beside it, at the moment
it asked to be asked less. A group of two public resolvers under one busy client
is the shape to watch `elodin_upstream_swept_rcode_total` for.

The other exception is an extended rcode. It is twelve bits (RFC 6891 section
6.1.3), four in the header and eight in the OPT record, and a stub client reads
the four: a BADVERS forwarded as it stands reads as NOERROR over an empty
answer section,
which is a client being told a name has no such record when what happened is
that its resolver could not find out. A DANE or MTA-STS client that believes it
downgrades. So a reply whose composed rcode is 16 or above is not one this
server passes on: the other members of the group that are not in their failure
cooldown are asked, and if none of them can answer readably the query is a
SERVFAIL. A client that asked with EDNS gets an extended DNS error (RFC 8914)
with it — code 0, `Other`, naming the rcode, since none of the registered codes
says "the rcode you were sent is not one you could read"; a client that asked
without EDNS has nowhere to be told and gets the bare SERVFAIL. elodin only ever
asks in EDNS version 0, which every EDNS implementation is required to support,
so a BADVERS in reply to one is a protocol violation by that server rather than a
fact about the name.

Those refusals reach the log as `outcome=failed detail=rcode:<upstream>` and are
counted as `unreadable_rcode=` in the stats line and
`elodin_upstream_unreadable_rcode_total{upstream}` on the metrics endpoint. The
warning naming the upstream is said once and demoted to debug after it, since the
bytes behind it are ones an on-path attacker can write — which is why the
counters are there, and why the per-upstream one exists: a reply like this is
deliberately *not* counted as an upstream failure, so a member doing it keeps a
clean `elodin_upstream_failures_total` and an `elodin_upstream_up` of 1. Counting
it as a failure would let one forged packet per query park every server in the
group, which is a worse outage than the answer being refused.

The same byte is cleared on the way out: RFC 6891 requires a request to leave
EXTENDED-RCODE at zero, so a client setting it cannot make an upstream that
echoes the OPT TTL answer every one of its queries unreadably.

The EDNS payload size a forwarded query carries is elodin's own, capped at the
1232 bytes of DNS Flag Day 2020 (RFC 9715), never the client's figure: that
field says how large a datagram *this server* is prepared to receive, and
passing the client's on would let any of them ask the upstream for 65000 bytes
of fragmented UDP — whose second fragment carries neither port nor transaction
ID. A client that advertised less than 1232 is not overruled upward. On a
`udp://` upstream an answer that no longer fits comes back truncated and is
re-fetched over TCP; on `tcp://`, `tls://` and `https://` the figure bounds
nothing, since RFC 7766 section 6.2.1.1 says not to apply the requestor's
payload size over a stream, and a truncated reply from an upstream that applied
it anyway is passed on to the client as it stands — which for a client already on
TCP or DoT is the end of the road, since TCP is where a TC bit sends it. An
upstream that truncates a stream reply by the requestor's figure cannot serve
answers over 1232 bytes through elodin; it also could not serve them to any
client that asked without EDNS, which RFC 1035 holds to 512.

A query carrying a record of type OPT outside its additional section — where RFC
6891 puts the one that counts — is answered FORMERR and not forwarded, alongside
the two other EDNS shapes elodin declines to read: a second OPT record, and an
OPT whose options do not parse. All three are records this server cannot strip a
cookie from or rewrite a size in, and would hand to an upstream untouched.

An `https` upstream picks between HTTP/2 and HTTP/1.1 with ALPN, preferring h2,
since some public resolvers answer HTTP/1.1 only. Concurrent queries against an
h2 upstream multiplex onto one connection; an HTTP/1.1 one keeps up to `max_idle`
idle connections pooled. `tcp://` and `tls://` upstreams pipeline every query onto
one shared connection instead (RFC 7766 section 6.2.1.1). Which it speaks is discovered from its first
connection and not re-checked.

## Per-domain upstreams

If something on your network answers for a zone of its own — a domain controller
for `corp.example`, a router that answers `home.arpa`, a lab server with an
internal `.test` — name that zone and where it goes, rather than choosing between
a public resolver that has never heard of it and an internal server asked to
recurse the whole Internet:

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

A route is a whole upstream in its own right, so it takes anything `upstream`
itself takes — `strategy`, `timeout`, `attempts`, `max_idle`, `idle_timeout`,
`bootstrap`, and servers in every form and transport, DoT and DoH included — and
inherits from the `upstream` block around it whatever it does not say:

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

`domains` matches on label boundaries and ignores case, so `corp.example` covers
itself and everything under it but not `notcorp.example`, and the longest
matching route wins — a sub-zone can be sent elsewhere without rewriting the
broader entry.

Two things follow from a route, both of which would otherwise have to be
configured separately and both of which break the deployment when forgotten:

- **The zone is not validated.** A local zone holds unsigned data under a public
  parent that delegates nothing to it, so walking the public chain for a name
  inside it finds a missing delegation and calls a good answer bogus. Routed
  names are served insecure, without the AD bit, exactly as the RFC 6303 private
  reverse zones are. A [`trust_anchors`](dnssec.md#dnssec) entry covering the zone stands
  that bypass down — read that as "the bypass is off" rather than "the zone now
  validates", since the chain walk descends by `DS` from the root and reaches an
  internal zone only if the public tree delegates to it. And `trust_anchors`
  *replaces* the built-in root keys rather than adding to them, so list the root
  DS alongside your own.
- **The zone may answer with private addresses.** A route says the zone is
  answered by a local authority, and answering with local addresses is what a
  local authority is for, so [rebind protection](rebinding.md#dns-rebinding-protection)
  exempts a routed zone without it also appearing in `rebind.allow_domains`.

What does *not* follow a route is the DNSSEC chain walk: the `DS` and `DNSKEY`
lookups elodin makes on its own account always go to `upstream.servers`, because
a server authoritative for `corp.example` answers `corp.example DS` out of its
own zone rather than fetching the signed proof from the parent, and that answer
breaks a chain instead of completing it.

A client's own `DS` query at a route's apex is kept off the route for the same
reason, and goes to whatever answers the parent zone — `upstream.servers`, or
the route covering the parent if there is one. It is the one question a routed
zone does not answer for itself: a validating client below elodin asks
`home.arpa DS` on its way down from `arpa`, and the router the route points at
replies out of its own zone with an unsigned "no data" instead of the signed
proof that lives in the parent, which the client reads as a broken chain and
turns into SERVFAIL for the whole zone. RFC 8375 section 4 item 4.B requires
that one query to be forwarded for exactly this reason. Names *below* the apex,
and the apex's own `DNSKEY`, stay on the route — those are the zone's own data.
That one query is also the only part of a routed zone the public upstream hears,
and it names no host: the zone's own name, which its parent already publishes if
the delegation exists.

The parent keeps that question only if it answers the thing it was asked for:
"no data", meaning the delegation exists and carries no DS. That is `home.arpa`'s
answer from `arpa`, and it is the only thing the parent can tell a validating
client that the local authority cannot. Anything else goes back on the route:

- **NXDOMAIN** — nothing in the public tree delegates the zone, the ordinary case
  being an internal `corp.example.com` under a public, signed `example.com`. There
  is no proof to fetch, and passing the NXDOMAIN on would be worse than the answer
  it replaced: an unsigned "no data" from the local server lets a lenient validator
  treat the zone as unsigned and resolve it, while a *signed* proof of
  non-existence takes that away — and a validator implementing RFC 8020 reads it as
  proof that every name under the apex is gone too.
- **A DS record** — the zone is delegated and signed in public and the route points
  at another view of it, which is split horizon. Handing the client the public DS
  makes it demand a `DNSKEY` the internal view has no matching key for, and it gets
  bogus instead of an answer. If you really are routing to a mirror of the signed
  zone, it is served insecure like any other routed zone; a
  [`trust_anchors`](dnssec.md#dnssec) entry over it is how you ask for it to be validated.
- **No answer at all** — a routed zone keeps standing on its own, so
  `upstream.servers` being down, or unreachable from the network the resolver sits
  on, does not take the chain out from under a zone whose own authority is
  answering.

"No data" is also what a parent says about a name that sits in its own zone
without being a delegation — `corp.example.com` published there as an A record,
or existing because `vpn.corp.example.com` is public. elodin does not tell that
apart from an insecure delegation (it would have to read the NS bit out of the
NSEC/NSEC3 bitmap), and passes the proof on either way. For that case the client
is right to act on it: the public tree does cover those names with signed data,
so the local server's unsigned answers below them are bogus, and the zone
resolved before only because the local NODATA hid the parent's proof. Anchor the
zone with [`trust_anchors`](dnssec.md#dnssec), or do not route a name the public tree
publishes.

A reply that says nothing about the name — SERVFAIL, REFUSED — counts as no
answer here rather than as an answer to pass on, which is a departure from how
every other rcode is handled: for a question about a *delegation*, only NOERROR
and NXDOMAIN say anything, so an upstream with an ACL, or a CPE resolver that
mangles every `DS` it meets, must not take an internal zone down with it. The
rest of that group is asked before the route is, so one server in
`upstream.servers` that refuses every `DS` does not hide a proof another one of
them is publishing. A NOERROR whose answer section carries something that is
not a DS is read the same way: "no data" means nothing in the answer at all,
and a resolver that hijacks NXDOMAIN answers this question with NOERROR and a
synthesised address, which is the first case above with the rcode written over.
And if the local server cannot be reached either, the answer is SERVFAIL rather
than whatever the parent said: a signed "this name does not exist" over a zone
that is served locally is the one answer worth withholding, since the client
caches it for the parent's whole negative TTL and a resolver implementing RFC
8020 reads it as covering every name under the apex. A SERVFAIL says what is
true — the delegation could not be established — and nothing keeps it, so the
zone comes back the moment its authority does. A parent whose upstreams are all
in their failure cooldown is not waited for at all; the question goes straight
to the route — so long as the route is out of its own cooldown, since skipping a
parent that may have come back for a server that is also down would only lose
the try that would have proved the delegation.

Where the parent said nothing — no reply, SERVFAIL, REFUSED, a NOERROR with the
wrong thing in it, or its group already in that cooldown — the route's answer
goes to the client and is not cached. It stood in for a fact nothing
established, and keeping it would hold the very broken chain this carve-out
exists to prevent over the zone for up to [`cache.negative_ttl`](cache.md#cache) after a
single lost round trip. The next query asks again — unless the parent's group
has now replied three times in a row without settling anything, each within ten
seconds of the last, in which case the route is asked first for the next ten
seconds. That memory holds up to eight route apexes and skips an anchored zone. An answer the route gave
because the parent *did* say something — NXDOMAIN, or a DS record — is cached
like any other, that statement about the public tree holding until the public
tree changes.

The answer cache is keyed on the question rather than on which upstream produced
it, which holds because the routing table is built once at startup — restart
after changing a route. `--check` and the startup log say out loud what each
route gives up, one line per route that gives anything up, since nothing at load can tell an internal
zone from a public signed one.

A route into a zone [`special_use`](reserved-names.md#reserved-names) already answers is refused
at load: those names are answered from the table before anything is forwarded,
so the route would sit in the file looking like the fix while every name went on
getting the table's NXDOMAIN. Turn the key off in the same edit. The one
exception is `special_use.private_reverse`, which stands down for a routed name
instead, so a route is how a reverse zone reaches your router.

> **Coming from dnsmasq:** `server=/corp.example/10.0.0.1` in `blocking.rules`
> or `blocking.allow` does not route that zone — it is discarded, which looks
> exactly like the route not working. Written without a server,
> `server=/corp.example/` in `blocking.rules` *blocks* the zone. `--check` warns
> about either written by hand. Routing lives under `upstream.zones` and nowhere
> else.
