# Rewrites

```yaml
rewrites:
  - domain: nas.home
    answer: 192.168.1.50
  - domain: "*.lan"
    answers: [192.168.1.10, "fd00::10"]
  - domain: old.example.com
    answer: new.example.com    # a name becomes a CNAME
  - domain: telemetry.example.com
    answer: block              # answered as if it were on a blocklist
```

- Rewrites are matched before everything else, the block lists included.
- Wildcards match subdomains only: `*.lan` covers `host.lan`, not `lan`.
- `ttl` sets the answer's TTL; the default is 300 seconds.

**CNAMEs are followed.** The answer carries the target's records after the
alias, looked up as if the client had asked for the target: another rewrite, the
block lists, the cache, then the upstream. (glibc and musl report a bare CNAME
answer as not found.)

- A chain stops at the first name it has already passed, or after 8 aliases.
- With RD clear, the target's records are added only if this server has them
  without asking an upstream.
- A refused target leaves the alias alone as the answer.
- A target that is not a rewrite gets its own query log line. Metrics count the
  query once, by the target's outcome, or as rewritten where the target was
  refused or is a special-use name.

## Other record types

An answer may be a type and its RDATA, spelled as in a zone file:

```yaml
rewrites:
  - domain: example.com
    answers:
      - "MX 10 mail.example.com"       # preference, then the host
      - "MX 20 backup.example.com"
      - 'TXT "v=spf1 include:_spf.example.com -all"'
  - domain: _sip._tcp.example.com
    answer: "SRV 0 5 5060 sip.example.com"   # priority, weight, port, target
  - domain: nas.home
    answers: ["A 192.168.1.50", "AAAA fd00::50"]
```

- Types: `A`, `AAAA`, `CNAME`, `MX`, `TXT` and `SRV`, fields in their RFC order.
- The short forms still work: a bare address is A or AAAA, a bare name is a
  CNAME, `block` sinks the name. A type token counts only when something follows
  it, so `answer: mx` is a CNAME to the host `mx`.
- TXT unquoted is one string to the end of the line. Quoted, it is a sequence of
  strings (`'TXT "part one" "part two"'`), which anything over 255 bytes needs,
  that being the per-string limit. Inside quotes `\"` is a quote and `\\` a
  backslash; numeric escapes (`\065`) are not read.
- MX exchanges and SRV targets get no address in the additional section; clients
  ask for it themselves.

**A rule holding only MX, TXT and SRV records is additive.** It answers the
types it lists, and every other type at that name is looked up as if the rule
were not there (later rules, then the upstream). This is dnsmasq's `--mx-host`
and `--txt-record`: a real domain keeps its website while you add mail records.
Add an address, a name or `block` to the rule and it answers for the whole name,
so types it has no record of are NODATA.

For an internal-only name that nothing else resolves, an additive rule makes its
other types NXDOMAIN rather than NODATA, and a client that caches that stops
asking for the MX or SRV too (RFC 8020). Give such a rule an address or `block`.

**CNAME constraints.** A CNAME must be the only record in its rule, and there may
be only one (RFC 2181 section 10.1). Put other records on the name it points at.
`block` is not a record and is allowed beside it.

**Config errors**, each naming the rule and failing `--check`:

- a type with bad RDATA (`MX ten mail.example.com`);
- a type this does not answer (`PTR nas.home`, `NS ns1.internal`);
- any other answer with a space in it that does not start with a type;
- a CNAME beside another record;
- a host name the wire cannot carry, in `domain` or an answer: a label over 63
  bytes or a name over 255.

## Reverse lookups

A rule that hands out an address also answers its PTR, with the rule's TTL:
`nas.home` above answers `50.1.168.192.in-addr.arpa`, so `nslookup 192.168.1.50`
returns `nas.home`. This matches dnsmasq and AdGuard Home and needs no
configuration. Other types at a synthesised name are NODATA with an SOA, not
forwarded.

No PTR is synthesised for:

- a wildcard rule, which has no one name to point back at;
- a rule with `answer: block`;
- a rule the forward direction never reaches (shadowed by an earlier wildcard or
  an earlier rule with the same `domain:`), unless the shadowing rule hands out
  the same address;
- an address outside RFC 1918, RFC 3927 link-local, `fd00::/8` unique-local and
  RFC 4291 IPv6 link-local. A public address's PTR belongs to its owner; loopback
  and `0.0.0.0` are excluded as sinkholes.

Precedence:

- An address named by several rules gets the first rule's name in file order.
- A rule written for the reverse name itself wins outright.
- A `dnssec.trust_anchors` entry over the reverse zone turns synthesis off for
  the names it covers while `dnssec.enabled` is on, since a synthesised answer
  is unsigned and a validating client below you holding the same anchor would
  get SERVFAIL.

**Watch out:** if you sink a name by pointing it at a LAN host (a block page on
the router), that host's reverse becomes the sunk name. Say so with
`ptr: false`:

```yaml
rewrites:
  - domain: ads.example.com
    answer: 192.168.1.10
    ptr: false               # keep .10's own reverse
```

The rule keeps its forward answer and stops claiming the address. File order
settles it too, and `answer: block` or the [sink lists](blocking.md#sink-lists)
sink a name without an address to reverse.

**Watch out:** reverse answers make your local names sweepable. Anyone the
[client allow list](access-control.md#who-may-ask) admits can walk RFC 1918
reverse space and collect them, as with dnsmasq and AdGuard Home. The allow list
defaults to local networks only; if yours is wide, keep that in mind.
