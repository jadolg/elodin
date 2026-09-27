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

Wildcards match subdomains only, so `*.lan` covers `host.lan` but not `lan`. An
optional `ttl` sets what the answer carries, 300 seconds if left out. Rewrites are matched before
everything else, the block lists included.

A CNAME is followed: the answer carries the target's records after the alias,
looked up as though the client had asked for the target by name — another
rewrite, the block lists, the cache, then the upstream — since glibc and musl
report a name whose answer is a bare CNAME as not found. A chain stops at the
first name it has already passed through, or after 8 aliases, and a query with RD
clear gets the target's records only where this server has them without asking
an upstream. A refused target leaves the alias alone as the answer. A target
that is no rewrite shows in the query log as a line of its own, and the metrics count
the query once, by the target's outcome - or as rewritten, where the target was
refused or is a special-use name.

## Other record types

An answer may also be written as a type and that type's RDATA, spelled the way a
zone file spells it:

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

`A`, `AAAA`, `CNAME`, `MX`, `TXT` and `SRV`, with the fields in the order their
RFCs print them, so a line from your registrar's mail page or your SIP
provider's instructions can be copied across as it stands. The short forms are
unchanged and still what most rules want: a bare address is an A or AAAA, a bare
name is a CNAME, `block` sinks the name. A type token only counts when something
follows it, so `answer: mx` is still a CNAME to the host called `mx`.

TXT unquoted is one string to the end of the line. Quoted, it is a sequence —
`'TXT "part one" "part two"'` — which is what a TXT record is, and what anything
over 255 bytes has to be written as, that being the limit on each string. Inside
the quotes `\"` is a quote and `\\` a backslash; zone-file numeric escapes
(`\065`) are not read.

**A rule holding only MX, TXT and SRV records is additive**: the types it lists
are answered here, and every other type at that name is looked up as though the
rule were not there — the rules below it, then the upstream. That is what you
want for `example.com` with two MX records and an SPF `TXT`, a real domain whose
website must go on resolving, and it is what `--mx-host` and `--txt-record` do in
dnsmasq. Add an address, a name or `block` to the same rule and it speaks for the
whole name again, so the types it has no record of are NODATA.

The corollary matters for an internal-only name: if nothing else resolves it, its
other types now come back NXDOMAIN rather than NODATA, and a client that caches
that will stop asking for the MX or SRV the rule exists to serve (RFC 8020). Give
such a rule an address as well, or `block`, and it speaks for the name.

A CNAME may not share its rule with other records and there may be only one: a
CNAME says this name *is* another name, so it already answers every type, and a
CNAME beside an MX is a malformed answer (RFC 2181 section 10.1). Put the other
records on the name it points at. `block` is exempt, not being a record.

The MX exchange and the SRV target get no address in the additional section —
this server would have to resolve them upstream to find one, and clients ask for
it themselves.

An answer that names a type and gets it wrong is a config error naming the rule
rather than a CNAME to whatever was written: `MX ten mail.example.com` fails
`--check`, as does a type this does not answer (`PTR nas.home`, `NS
ns1.internal`), anything else with a space in it that does not start with a type,
a CNAME beside another record, and a host name the wire cannot carry — a label
over 63 bytes or a name over 255, in a rule's `domain` or in an answer.

## Reverse lookups

The PTR for an address a rule hands out comes for free: `nas.home` above also
answers `50.1.168.192.in-addr.arpa`, with the rule's own TTL, so `nslookup
192.168.1.50` gives back `nas.home` instead of the blackhole servers' NXDOMAIN.
dnsmasq and AdGuard Home both do this, and without it every `ssh` banner, mail
server check and log viewer on the LAN reports a name that does not exist for a
name this server is answering. Nothing to configure. Other types at a synthesised
name are NODATA with an SOA rather than a forwarded query.

Only a rule that really does hand out the address gets to name it, and only if
the address is one this network holds. Nothing is synthesised for:

- a wildcard rule, which answers every name below its suffix with the same
  address, so there is no one name to point back at;
- a rule with `answer: block`, which hands out no address at all;
- a rule the forward direction never reaches — shadowed by an earlier wildcard or
  by an earlier rule with the same `domain:` — unless the rule shadowing it hands
  out the same address, the test being on the answer rather than on which rule
  won;
- an address outside RFC 1918, RFC 3927 link-local, `fd00::/8` unique-local and
  RFC 4291 IPv6 link-local. A rule pointing a local name at a public address says
  nothing about who owns it, and its real PTR is somebody else's to answer;
  loopback and `0.0.0.0` are out too, a rule pointing at one of those being a
  sinkhole rather than an address.

An address named by several rules gets the first rule's name in file order, the
precedence the forward direction already uses, and a rule written for the reverse
name itself wins outright — the synthesis is what happens when nothing more
specific was said. A `dnssec.trust_anchors` entry over the reverse zone turns it
off for the names it covers while `dnssec.enabled` is on: anchoring a zone is a
request to validate it, and an answer invented here carries no signature, so a
validating client below you holding the same anchor would get SERVFAIL.

Two things to know before turning this loose on an existing installation. If you
sink a name by pointing it at a host on your LAN — a block page served off the
router — that host's reverse would become the sunk name, and nothing here can
tell that rule from one naming the host itself. Say so with `ptr: false`:

```yaml
rewrites:
  - domain: ads.example.com
    answer: 192.168.1.10
    ptr: false               # keep .10's own reverse
```

The rule keeps its forward answer and stops claiming the address. File order
settles it too, and `answer: block` or the [sink lists](blocking.md#sink-lists) sink a name
without handing out an address to reverse at all; the key is for when the block
page really does have to be an address.

And the reverse direction makes your local name inventory sweepable: anyone your
[client allow list](access-control.md#who-may-ask) admits can walk RFC 1918 reverse space and
collect the names, where before they had to guess forward ones. dnsmasq and
AdGuard Home answer the same sweep the same way, and the allow list defaults to
local networks only — but if that list is wide, this is one more thing behind it.
