# Reserved names

```yaml
special_use:
  enabled: true    # the table below
  onion: true      # onion.  (RFC 7686 section 2)
  local: false     # local.  (RFC 6762 section 22)
  test: false      # test.   (RFC 6761 section 6.2)
  home_arpa: false # home.arpa. (RFC 8375 sections 3 and 4)
  private_reverse: true # private reverse zones (RFC 6303, RFC 7793)
```

Three names are answered here rather than asked about, whatever
`upstream.servers` says:

| name | answer | why |
|---|---|---|
| `localhost.` and below | 127.0.0.1 for A, `::1` for AAAA, NODATA otherwise | RFC 6761 6.3. The only answer it is allowed to have |
| `onion.` and below | NXDOMAIN | RFC 7686 2, unless the upstream is Tor-aware |
| `invalid.` and below | NXDOMAIN | RFC 6761 6.4. It cannot exist |

**`private_reverse` is on by default.** The reverse zones for RFC 1918 private
space, CGNAT (100.64/10), loopback, `0/8`, IPv4 link-local, IPv6 unique-local
(`fd00::/8`) and IPv6 link-local are served here as empty zones (RFC 6303
section 3): `1.1.168.192.in-addr.arpa` is NXDOMAIN, `168.192.in-addr.arpa`
itself NODATA with its own SOA and NS. Forwarded, every LAN PTR from every client
tells the upstream which private addressing your network uses, and fetches the
AS112 blackhole servers' NXDOMAIN for it. Unbound, BIND and Pi-hole all answer
these locally by default. Only each zone's apex `DS` still goes out, for the
same reason `home.arpa DS` does.

If your router answers PTRs for its DHCP leases, route the zone to it —
`upstream.zones: [{domains: [168.192.in-addr.arpa], servers: [192.168.1.1]}]` —
and those names go there instead: a route over a name wins over this key, and so
does a [trust anchor](dnssec.md#dnssec) you configured over the zone while `dnssec.enabled`
is on. The same goes for a VPN that numbers its peers from CGNAT space and
answers their PTRs — Tailscale's MagicDNS at `100.100.100.100`, say: route
the CGNAT zones it numbers from (`64.100.in-addr.arpa` through
`127.100.in-addr.arpa`) to it, or its peers' reverse names are NXDOMAIN here.
Not `100.in-addr.arpa` as a whole: the rest of it is public, signed address
space, and a route takes every name under it out of DNSSEC validation.
`private_reverse: false` (or `enabled: false`) sends them all back to
`upstream.servers`, as before except that forwarded CGNAT reverse answers are
now served unvalidated like the other private ranges. These answers log as `outcome=local detail=private-reverse` and are left
out of the `special_use` counter below, which every LAN PTR would otherwise
drown.

`.onion` is the one this exists for: the query is the disclosure, since
forwarding it tells the upstream operator — and anyone on the path to a plain-UDP
upstream — that somebody here is reaching for one specific hidden service, which
is what Tor was being used not to publish. `localhost.` is a correctness problem
instead: forwarded, it resolves to whatever the upstream says, which is a
rebinding primitive given away for free.

These answers carry a 10-minute TTL and a synthesised SOA so a downstream
resolver can cache the negative, and they are not put in elodin's own cache. They
show as `outcome=local detail=special-use` and are counted as `special_use=` and
`elodin_special_use_total` — a counter worth a panel, since it climbing on a
network nobody resolves `.onion` from says either that somebody is, or that
`localhost.` lookups are reaching this resolver rather than a hosts file.

**`local.`, `test.` and `home.arpa.` are off by default**, though RFC 6762, RFC
6761 and RFC 8375 ask for the same handling, because they are the reserved names
networks really do serve: an Active Directory domain under `.local` older than
the reservation, an internal `.test` zone RFC 6761 permits, a home router
authoritative for `home.arpa`. Answering them with NXDOMAIN on an upgrade would
take those hostnames away from a network that had them. Turn them on if nothing
here serves them; against a public upstream the only change is that the NXDOMAIN
arrives without the round trip and without the hostname having left the building.
A `rewrites` rule outranks all of this, but what a rewrite cannot do is send the
query somewhere — a network whose router answers `.local` dynamically wants a
route under [`upstream.zones`](upstreams.md#per-domain-upstreams) pointed at it, alongside
the `local: false` that is already the default.

`home_arpa` is about privacy rather than a wrong answer: those names are your own
network's, and forwarded they name your hardware to a public resolver in exchange
for the blackhole servers' NXDOMAIN. What it does *not* do is send them to your
router instead — that is [`upstream.zones`](upstreams.md#per-domain-upstreams), which is what
a network whose router *does* answer the zone wants, and is why this key cannot
simply default on. The zone is served empty rather than absent,
which is what RFC 8375 section 4 asks for — `printer.home.arpa` is NXDOMAIN,
`home.arpa` itself NODATA with its own SOA and NS. One query still goes out with
the key on, `home.arpa DS`, whose signed proof lives in `arpa` and which a
validating client below elodin needs to conclude "insecure" instead of "broken";
see [DNSSEC](dnssec.md#dnssec).

A site running `.local` may not have working names there in the first place: with
validation on, its upstream's unsigned answer is checked against a root that
publishes a signed proof there is no `local.` to delegate, and SERVFAIL is the
likely verdict. `local: true` at least turns that into a clean NXDOMAIN, and a
`rewrites` rule turns it into an answer.

One upstream really should be asked `.onion`: a local `tor` with `DNSPort` and
`AutomapHostsOnResolve`. That wants `onion: false` and keeps the rest of the
table — RFC 7686 2 addresses a caching server "where not explicitly adapted to
interoperate with Tor", so this is the adapted case it leaves room for. It is
warned about at startup, the setting being a claim about the upstream rather than
about this resolver. `enabled: false` forwards those names too, and stands
validation down for them the same way rather than SERVFAILing an answer it just
asked for; the cost, if you turn the table off for some reason other than tor, is
that an ordinary upstream's NXDOMAIN for a `.onion` name arrives as insecure
rather than as the root-signed nonexistence it could have proved.

`localhost.` and `invalid.` have no key of their own and are not going to grow
one, neither having a deployment that wants them forwarded. `example.` is
deliberately absent: it is reserved, but RFC 6761 6.5 asks for the opposite,
`example.com` and its siblings being delegated names that resolve.
