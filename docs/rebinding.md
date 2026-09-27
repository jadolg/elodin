# DNS rebinding protection

```yaml
rebind:
  enabled: false                  # the default; set true to turn the guard on
  allow_domains: []               # zones that may answer with private addresses
  allow_loopback: false           # let 127.0.0.0/8 and ::1 through
```

A page loaded from `rebind.attacker.example` is same-origin with whatever that
name resolves to, for as long as it resolves to it. So the attacker publishes the
name with a one-second TTL, lets the browser fetch the page, and answers the next
lookup with `192.168.1.1` — and the page may now read the router's admin
interface. The browser cannot see this happening; the resolver can, which is why
dnsmasq (`--stop-dns-rebind`), Unbound (`private-address`) and AdGuard Home all
have a version of it.

elodin refuses an upstream answer that points a public name at loopback
(`127.0.0.0/8`, `::1`), the RFC 1918 ranges, link-local (`169.254.0.0/16`,
`fe80::/10`), IPv6 unique-local (`fc00::/7`), `0.0.0.0/8` or `::`. It checks answers to
A, AAAA, ANY, SVCB and HTTPS questions, reading A and AAAA records and the `ipv4hint`/`ipv6hint` parameters of SVCB and HTTPS records,
and beside an SVCB or HTTPS answer the additional section too, since RFC 9460
section 5 has the client take the target's address from there. Two entries in
that set are worth naming: `169.254.169.254` is the cloud instance metadata
endpoint, which answers unauthenticated and hands back credentials, and
`0.0.0.0` is how browsers on Linux and macOS reach services bound to
`127.0.0.1` — the "0.0.0.0 Day" bypass.

One offending record refuses the whole answer rather than being filtered out of
it, and an answer elodin cannot decode is refused too for those same five
question types: forwarding it verbatim was the way round the guard, glibc's
resolver only ever walking the answer section. That reads `detail=unreadable`
in the query log, against `detail=rebind` for a private address.

The client gets NODATA, with an SOA and RFC 8914 extended error 15. Not
SERVFAIL: a stub with two servers reads SERVFAIL as *this* server having failed
and asks the other, which on a home network is the router — and the router
answers `192.168.1.1` quite happily. The check runs before the answer is cached,
which is the ordering the whole thing rests on, and the refusal is not cached
either. Refusals are counted as `rebind=` and `elodin_rebind_refused_total`.

**Why it is off by default.** dnsmasq, AdGuard Home and Unbound all ship theirs
off, for the same reason: a box on a LAN that every device points at is commonly
the one running **split horizon**, where a public zone answering with a LAN
address is the configuration rather than the attack. On by default, every one of
those names would become NODATA on upgrade — not degraded, gone, and looking
exactly like a name that does not exist. [DNSSEC](dnssec.md#dnssec) defaults the other way
because an upstream that cannot return DNSSEC records is a misconfiguration to
fix, where split horizon is not.

**Turn it on if you are not running split horizon** — the failure it prevents is
silent, while the guard itself is loud. And if you do run split horizon, turn it
on and name the zones:

```yaml
rebind:
  enabled: true
  allow_domains: [corp.example, home.arpa]
```

Each entry covers itself and everything below it, the way
`--rebind-domain-ok=/corp.example/` does in dnsmasq, so write the zone rather
than a wildcard — a `*.corp.example` is refused at load. Matching is against the
name that was asked for, so a CNAME from an attacker's name into an exempt zone
exempts nothing. `allow_loopback: true` opens loopback for every name; prefer
`allow_domains`, since a service bound to `127.0.0.1` is the one least likely to
authenticate.

A zone with a route under [`upstream.zones`](upstreams.md#per-domain-upstreams) needs no
entry here — the route already says that zone is answered locally, and the
exemption follows from it. `allow_domains` is for the site whose *default*
upstream is the internal server, where there is no per-zone route to read that
fact off.

Two other things stop resolving once it is on: a development host that a public
zone points at `127.0.0.1`, which either setting covers, and **a chained
sinkhole** — an upstream filtering resolver that answers blocked names with
`0.0.0.0` or `127.0.0.1` has those answers refused here. The name is blocked
either way, but `rebind=` then tracks your own ad blocking, so **check whether
your upstream sinkholes before reading a rising `rebind=` as an attack**.

What needs no exemption: `rewrites`, answered before anything is forwarded;
reverse lookups, a PTR answer being a name rather than an address; elodin's own
blocking, `zeroip` included, which builds its answer locally; and `localhost.`,
which RFC 6761 section 6.3 makes loopback-only by definition — though the
[reserved-name table](reserved-names.md#reserved-names) answers those names first anyway.
