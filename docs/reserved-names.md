# Reserved names

```yaml
special_use:
  enabled: true         # the table below
  onion: true           # onion.  (RFC 7686 section 2)
  local: false          # local.  (RFC 6762 section 22)
  test: false           # test.   (RFC 6761 section 6.2)
  home_arpa: false      # home.arpa. (RFC 8375 sections 3 and 4)
  private_reverse: true # private reverse zones (RFC 6303, RFC 7793)
```

These names are answered here rather than forwarded, whatever `upstream.servers`
says:

| name | answer | why |
|---|---|---|
| `localhost.` and below | 127.0.0.1 for A, `::1` for AAAA, NODATA otherwise | RFC 6761 6.3; forwarded, the upstream could point it anywhere |
| `onion.` and below | NXDOMAIN | RFC 7686 2; forwarding it tells the upstream and the path which hidden service is wanted |
| `invalid.` and below | NXDOMAIN | RFC 6761 6.4; it cannot exist |

These answers carry a 10-minute TTL and a synthesised SOA so a downstream
resolver can cache the negative, and are not put in elodin's own cache. They log
as `outcome=local detail=special-use` and count as `special_use=` and
`elodin_special_use_total`. That counter climbing where nobody uses `.onion`
means either somebody does, or `localhost.` lookups are reaching this resolver
instead of a hosts file.

A `rewrites` rule outranks everything on this page.

## private_reverse

On by default. The reverse zones for RFC 1918 space, CGNAT (100.64/10),
loopback, `0/8`, IPv4 link-local, IPv6 unique-local (`fd00::/8`) and IPv6
link-local are served as empty zones (RFC 6303 section 3):
`1.1.168.192.in-addr.arpa` is NXDOMAIN, `168.192.in-addr.arpa` itself NODATA
with its own SOA and NS. Forwarded, every LAN PTR would tell the upstream your
private addressing. Only each zone's apex `DS` still goes out, as for
`home.arpa DS`.

These answers log as `outcome=local detail=private-reverse` and are left out of
the `special_use` counter.

A route or a trust anchor takes a zone back from this key:

- **A router that answers PTRs for its DHCP leases:** route the zone to it, and a
  route over a name wins over this key:

  ```yaml
  upstream:
    zones:
      - domains: [168.192.in-addr.arpa]
        servers: [192.168.1.1]
  ```

- **A VPN that numbers peers from CGNAT space** (Tailscale's MagicDNS at
  `100.100.100.100`, say): route the CGNAT zones it uses, `64.100.in-addr.arpa`
  through `127.100.in-addr.arpa`, to it, or its peers' reverse names are NXDOMAIN
  here. Not `100.in-addr.arpa` as a whole: the rest is public, signed space, and
  a route takes every name under it out of DNSSEC validation.
- A [trust anchor](dnssec.md#dnssec) configured over the zone, while
  `dnssec.enabled` is on.

`private_reverse: false` (or `enabled: false`) forwards them all to
`upstream.servers`; the forwarded answers are served unvalidated.

## local, test and home_arpa

Off by default, though RFC 6762, RFC 6761 and RFC 8375 ask for the same handling,
because networks really do serve these: an Active Directory domain under
`.local`, an internal `.test` zone, a home router authoritative for `home.arpa`.
Turn them on if nothing on your network serves them; against a public upstream
the NXDOMAIN then arrives without the round trip and the name never leaves.

A rewrite cannot send a query somewhere. A router that answers `.local` or
`home.arpa` dynamically wants a route under
[`upstream.zones`](upstreams.md#per-domain-upstreams) pointed at it, with the key
left off.

`home_arpa: true` serves the zone empty rather than absent (RFC 8375 section 4):
`printer.home.arpa` is NXDOMAIN, `home.arpa` itself NODATA with its own SOA and
NS. One query still goes out, `home.arpa DS`, whose signed proof lives in `arpa`
and which a validating client below elodin needs; see [DNSSEC](dnssec.md#dnssec).

With validation on, a `.local` site's names may already fail: the root signs a
proof that there is no `local.`, so the upstream's unsigned answer is likely
SERVFAIL. `local: true` turns that into a clean NXDOMAIN, and a `rewrites` rule
into an answer.

## onion: false and enabled: false

`onion: false` is for a local `tor` with `DNSPort` and `AutomapHostsOnResolve`,
the adapted case RFC 7686 2 leaves room for. It keeps the rest of the table.
Startup warns:

```
special_use.onion is off: .onion queries are forwarded, which is only safe to a Tor-aware upstream
```

`enabled: false` forwards everything in the table and the private reverse zones:

```
special_use.enabled is off: localhost., onion., invalid. and the private reverse zones are forwarded to the upstream
```

Both keys stand DNSSEC validation down for `.onion` instead of SERVFAILing the
answer. With `enabled: false` and `dnssec.enabled` on, startup also warns:

```
special_use.enabled is off: .onion answers are served insecure, as nothing under a zone the root proves is not delegated can be signed
```

The cost, if you turn the table off for a reason other than tor, is that an
ordinary upstream's NXDOMAIN for `.onion` arrives insecure rather than proven.

## Not configurable

`localhost.` and `invalid.` have no key of their own; nothing needs them
forwarded. `example.` is deliberately absent: RFC 6761 6.5 asks for
`example.com` and its siblings to resolve normally.
