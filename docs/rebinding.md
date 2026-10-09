# DNS rebinding protection

```yaml
rebind:
  enabled: false                  # the default; set true to turn the guard on
  allow_domains: []               # zones that may answer with private addresses
  allow_loopback: false           # let 127.0.0.0/8 and ::1 through
```

With the guard on, elodin refuses an upstream answer that points a public name at
a private address. This stops a page on `rebind.attacker.example` from re-pointing
its own name at `192.168.1.1` and reading your router's admin interface. It is
dnsmasq's `--stop-dns-rebind` and Unbound's `private-address`.

**Refused addresses:** loopback (`127.0.0.0/8`, `::1`), the RFC 1918 ranges,
link-local (`169.254.0.0/16`, `fe80::/10`, which includes the `169.254.169.254`
cloud metadata endpoint), IPv6 unique-local (`fc00::/7`), `0.0.0.0/8` and `::`
(`0.0.0.0` reaches `127.0.0.1` services in browsers on Linux and macOS). An
IPv4 address written inside an IPv6 one (`::ffff:a.b.c.d`, `::a.b.c.d`,
`::ffff:0:a.b.c.d`, the NAT64 prefixes `64:ff9b::/96` and `64:ff9b:1::/96`, and
6to4 `2002:aabb:ccdd::/48`) is judged as the IPv4 address.

**What is checked:** answers to A, AAAA, ANY, SVCB and HTTPS questions. It reads A
and AAAA records and the `ipv4hint`/`ipv6hint` of SVCB and HTTPS records, and
beside an SVCB or HTTPS answer the additional section too (RFC 9460 section 5).

**What the client gets:**

- One offending record refuses the whole answer. An answer to those five
  question types that elodin cannot decode is refused too.
- The refusal is NODATA with an SOA and RFC 8914 extended error 15. Not SERVFAIL,
  which would send a stub to its second server (often the router, which answers
  with the private address).
- The check runs before the answer is cached; the refusal is not cached.
- The query log shows `detail=rebind` for a private address and
  `detail=unreadable` for an undecodable answer. Refusals count in `rebind=` and
  `elodin_rebind_refused_total`.

## Why it is off by default

A LAN resolver often runs **split horizon**, where a public zone answering with
a LAN address is intended. With the guard on, those names become NODATA and look
like names that do not exist. dnsmasq, AdGuard Home and Unbound ship theirs off
too.

**Turn it on if you do not run split horizon.** If you do, turn it on and name
the zones:

```yaml
rebind:
  enabled: true
  allow_domains: [corp.example, home.arpa]
```

- Each entry covers itself and everything below it, like dnsmasq's
  `--rebind-domain-ok=/corp.example/`. Write the zone: a wildcard such as
  `*.corp.example` is refused at load.
- Matching is against the name asked for, so a CNAME from an attacker's name into
  an exempt zone exempts nothing.
- `allow_loopback: true` opens loopback for every name. Prefer `allow_domains`:
  a service bound to `127.0.0.1` is the least likely to authenticate.
- A zone routed under [`upstream.zones`](upstreams.md#per-domain-upstreams) is
  exempt already. `allow_domains` is for a site whose *default* upstream is the
  internal server.

## What else stops resolving

- A development host that a public zone points at `127.0.0.1`. Either setting
  covers it.
- **A chained sinkhole**: an upstream filter that answers blocked names with
  `0.0.0.0` or `127.0.0.1` has those answers refused. The name stays blocked, but
  `rebind=` then tracks your ad blocking, so **check whether your upstream
  sinkholes before reading a rising `rebind=` as an attack**.

No exemption is needed for `rewrites` (answered before forwarding), reverse
lookups (a PTR is a name), elodin's own blocking including `zeroip` (built
locally), or `localhost.` (RFC 6761 section 6.3; the
[reserved-name table](reserved-names.md#reserved-names) answers it first anyway).
