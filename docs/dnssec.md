# DNSSEC

```yaml
dnssec:
  enabled: true
  max_nsec3_iterations: 100
  max_chain_walks: 0      # 0 is server.max_pending less a reserved quarter
  max_connection_walks: 0 # the same, from server.max_connections
  max_cached_zones: 0     # 0 is 4096
  trust_anchors: []       # empty uses the built-in root keys
```

elodin checks the signatures on the answers it forwards:

- an answer that does not validate becomes SERVFAIL, with an extended DNS error
  (RFC 8914) saying why;
- one that validates gets the AD bit;
- a name in an unsigned zone is served normally, without AD.

Turn it off (`enabled: false`) to get unvalidated answers on purpose, or behind
an upstream that does not return
DNSSEC records, such as an ISP or captive-portal resolver; against one of those
every signed zone would stop resolving.

As a forwarder, elodin fetches what it validates against: every DS and DNSKEY
down from the root, or from the closest trust anchor, through the configured
upstreams, with DO and CD set. Zone keys are cached, so the cost falls on the
first query into a zone.

## What is checked

| | |
|---|---|
| chain of trust | root → TLD → zone, DS against DNSKEY at every step |
| algorithms | RSA/SHA-1, RSA/SHA-256, RSA/SHA-512, ECDSA P-256 and P-384, Ed25519, Ed448 |
| DS digests | SHA-1, SHA-256, SHA-384 |
| denial of existence | NSEC and NSEC3, including closest-encloser proofs and opt-out |
| wildcards | a wildcard answer must come with a proof that the name had nothing of its own |
| a CNAME chain ending in NODATA or NXDOMAIN | the denial is checked in the zone holding the chain's last name, the name the rcode is about (RFC 6604 section 3): proven, it gets AD with its NSEC or NSEC3 and SOA (RFC 6840 section 5.8); unproven in a signed zone, SERVFAIL, whether or not the CNAMEs before it are signed; in an unsigned zone, insecure. It costs at most one more chain walk per answer, inside the same per-question bounds |
| unsigned zones | insecure: served, no AD bit |
| a DS question | judged against the parent zone, which holds the DS (RFC 4035 section 5.3.1): its signed proof of no DS gets AD, a proof through an opt-out span does not (RFC 5155 section 9.2), and a DS set signed only by the zone it names, or not at all under a signed parent, is bogus |
| bounds | 32 DS/DNSKEY lookups and 64 signature checks per question, 24 zone cuts of chain, 8 signatures per RRset, 64 keys per zone and 8 KB of them cached, 8 hint targets per answer, 100 NSEC3 iterations |
| a DS set naming nothing we can check | an insecure delegation, whether the algorithm is unimplemented here or refused by the host's crypto policy (RFC 6840 section 5.2) |
| a DS set naming something we can check | that path has to hold up: a DNSKEY set it does not lead to is bogus, however many uncheckable DS records sit beside it |
| bad signature, broken chain, missing proof | SERVFAIL, with an extended DNS error saying which |
| signature validity | inception up to 1 hour in this server's future is accepted, for a signer whose clock runs ahead; expiration is exact (RFC 4035 section 5.3.1) |
| TTLs | a validated RRset and its RRSIGs are served with no more than the RRSIG's original TTL or the time left before it expires, whichever is less (RFC 4035 section 5.3.3); zone keys and unsigned-delegation facts are kept no longer than the original TTL (with a 60 s floor) and never past the expiration of the signatures that proved them |

An answer that gets AD is first cut down to the records that earned it (RFC 4035
section 3.2.3). Address hints beside an HTTPS, SVCB, SRV or MX answer (RFC 9460
section 5) are kept only when they validate in the target's own zone; a hint
never changes the verdict on the answer.

A client that sets CD gets the data whatever the verdict; those answers are
cached under a separate key, so they never reach a client that wanted the check.
A client that did not set DO gets the DNSSEC records stripped.

## Logging

The first refusal of each verdict is logged at `warn` with the verdict, the
reason, the zone and step of the chain that broke, and the upstream the answer
came from. After that one refusal a minute per zone (zones share 16 slots, so
two may share one) is logged at `warn` too, with `held=<n>` counting the
refusals not logged at `warn` since the warning before it; the rest are
`debug`. The `warn` line does not name the client, which would otherwise be
recorded every minute with `log.queries` off; the `debug` line and the query
line do. Every
refusal's query line carries `outcome=failed detail=dnssec:<upstream>`, or
`detail=dnssec:cache` when answered from the cache:

```
ts=2026-08-07T09:12:52Z level=warn msg="dnssec: A xc.example.com did not validate: Bogus (broken chain of trust: example.com: the reply to the DS question held neither a DS nor a denial signed by the parent); answer came from quad9-dot"
ts=2026-08-07T09:12:52Z level=info msg=query client=192.0.2.10 port=44188 proto=udp qtype=A qname=xc.example.com outcome=failed detail=dnssec:quad9-dot ms=126.5
```

The upstream is named because members of one group can disagree about a zone: the
same question can fail through one server and validate through another.
`detail=dnssec` matches every refusal.

## Trust anchors

The built-in anchors are the root KSKs IANA publishes, KSK-2017 and KSK-2024, so
a rollover between them needs no new build. `trust_anchors` replaces them, as
bare DS fields or a full presentation-form record:

```yaml
dnssec:
  trust_anchors:
    - ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
    - "corp.example. IN DS 54707 15 2 FF085C4C1865D42641957E67182575E9DCB20BF2D9DD001D7BB9C5C4D2AC5384"
```

An anchor for a zone below the root validates that zone against your own key.
A name is checked from the closest anchor at or above it (RFC 6840 Appendix
C.1), so the public tree is not asked about `corp.example` at all: a zone signed
only internally validates, and a public DS for it is not used. An anchor left
behind after the zone changes its key makes every name in the zone SERVFAIL.

- The list must still name the root, or `--check` and startup refuse it.
- The server refuses to start if every anchor for a zone names an algorithm
  or digest this build cannot check.
- For a zone routed under [`upstream.zones`](upstreams.md#per-domain-upstreams),
  the zone's keys are fetched from the route's servers.

## max_nsec3_iterations

The most hashing one NSEC3 record may ask for. A record above it is not computed:

- a denial made only of such records is insecure: the NXDOMAIN or NODATA is
  served without AD and with extended error 27 (RFC 5155 section 10.3, RFC 9276);
- an unsigned answer inside such a zone is SERVFAIL with extended error 27, since
  an unreadable unsigned delegation cannot be told from a forgery;
- where readable records sit beside refused ones, the readable ones decide; if
  they prove nothing, SERVFAIL with extended error 27;
- the zone's signed records still validate, and a forged record, wildcard
  included, is still SERVFAIL.
- the parent's NODATA for a routed zone's apex `DS` is not read as showing a
  name the parent holds; see [DS at a route's apex](upstreams.md#ds-at-a-routes-apex).

The cost: anyone on the path can make a name in such a zone look absent — and,
for a zone that has moved off such a chain, for as long as the old chain's
signatures last. RFC 9276
asks zones for zero and real zones use single digits, so leave it alone.

The ceiling is 255, derived from the per-query hashing allowance; above it the
allowance is what answers, so a larger value buys SERVFAIL, not more validation.
A configured value above 255 is held down to 255 at startup, with a log line
saying so, rather than refused.

## max_chain_walks and max_connection_walks

How many chain-of-trust walks may be waiting on an upstream at once. A walk costs
one DS lookup per label, waited for on behalf of the query being validated, and
the client chooses the labels; the bound keeps a flood of fresh names from
holding every query the server may have in flight for a whole walk. A large
enough flood still fills [`server.max_pending`](sizing.md#queries-in-flight),
since the reserved queries can be busy on their own forward, but each comes back
in one round trip rather than thirty. A cached apex is not a cached name: a name
below one still costs a DS lookup per label.

| setting | covers | default (0) |
|---|---|---|
| `max_chain_walks` | queries counted in `server.max_pending`: UDP, DoH over HTTP/2, cache refreshes | `server.max_pending` less a reserved quarter (at least two): 307 of 409 on a 1 GiB machine |
| `max_connection_walks` | queries on a connection: TCP, DoT and DoH over HTTP/1.1 | the same from `server.max_connections`: 384 of 512 connections |

The two are counted separately, so a flood on one transport cannot spend the
other's allowance, and lowering one does nothing for the other. To cap the
upstream volume a flood can provoke, set both lower. Negative values are refused.

When the bound binds, a walk reads the caches and answers SERVFAIL where it would
have gone upstream, with the same extended error as an upstream that did not
answer. It is never served as insecure, and the answer is not cached, so a cold
name asked again is forwarded and shed again. While every slot is held, only what
the caches hold still answers: every other cold name is SERVFAIL, signed or not,
since proving a zone unsigned also takes a DS lookup. The forward itself is not
saved, only the walk's own DS and DNSKEY lookups.

`elodin_dnssec_queries_shed_total` counts the shed queries. It says the bound was
reached, not why: a flood, a restart with real traffic on a cold cache, or an
upstream black-holing (every walk then holds its slot to the timeout) all look
the same. If upstream latency is normal and the load is yours, raise the number.
The client's extended error does not say which limit stopped the walk; the log
and the counter do.

`--check` prints both as `chain_walks=` and `connection_walks=`, and the startup
log names them. Startup warns when a configured value leaves nothing reserved of
what it covers, which switches the bound off:

```
dnssec: max_chain_walks <n> leaves none of the <n> queries server.max_pending allows in flight reserved, so a flood of fresh names can hold them all; see issue #356
dnssec: max_connection_walks <n> leaves none of the <n> connections reserved, so a flood of fresh names can hold them all; see issue #356
```

## max_cached_zones

How many zones the key cache holds: an apex's keys, or the fact that it is
unsigned. 0 means 4096; negative values are refused. An entry costs about 12 KB
at worst (keys are capped at 8 KB of RDATA), so the ceiling is about 48 MB at the
default. Set it lower to keep validation inside a memory budget; raise it only if the
resolver really sees more zones than that. Above 4096,
startup warns with the memory the new value implies:

```
dnssec: max_cached_zones <n> lets the zone cache reach about <m> MB of keys, against <m> MB at the default of 4096
```

Past the bound the coldest zone is dropped, one at a time, so a value too small
costs re-walks for the zones that fell out and nothing else. The root, the TLDs
and other zones in steady use stay warm, so a flood of fresh delegations cannot
evict them.

## Names served insecure

These are served without AD, because there is no chain to walk:

- The RFC 6303 and RFC 7793 locally-served reverse zones: the RFC 1918 ranges,
  CGNAT (100.64/10), `0/8`, IPv4 link-local and loopback, IPv6 unique-local and
  link-local. Nobody signs them, so validating would make every LAN PTR lookup
  SERVFAIL. A `trust_anchors` entry covering one turns validation back on for it.
- Zones routed under [`upstream.zones`](upstreams.md#per-domain-upstreams): their
  public parent delegates nothing to them, so the walk would call a good answer
  bogus. A `trust_anchors` entry turns validation back on the same way.
- `home.arpa`. Its delegation from `arpa` has no DS by design, but when the
  upstream is a router authoritative for the zone, it answers `home.arpa DS`
  itself and the insecurity proof never arrives. The names are still forwarded to
  `upstream.servers` by default; point
  [`upstream.zones`](upstreams.md#per-domain-upstreams) at a router that answers
  the zone, or let [`special_use.home_arpa`](reserved-names.md#reserved-names)
  answer it here. Either way the `home.arpa DS` query itself goes to
  `upstream.servers`, neither down the route nor from the reserved-name table
  (RFC 8375). A zone you run with private
  addresses trips [rebind protection](rebinding.md#dns-rebinding-protection)
  unless it is routed or listed in `rebind.allow_domains`.
- `.onion`, whenever it is forwarded, since the root signs a proof that `onion.`
  does not exist and a Tor-aware upstream's answer would read as forgery. Both
  `special_use.onion: false` and `special_use.enabled: false` forward those names
  and stand validation down for them; see
  [Reserved names](reserved-names.md#reserved-names).

## resolver.arpa

`resolver.arpa` is answered NODATA rather than forwarded (RFC 9462 section 6.1).
Forwarded, it would return the upstream's designated resolvers, and a client that
used them would bypass the block lists, rewrites and query log. A `rewrites` rule
for the name still wins, to advertise this server's own endpoints.

## Watch out

- **Distribution crypto policy can take algorithms away.** Fedora and RHEL refuse
  SHA-1 signatures (DNSSEC algorithms 5 and 7). At startup elodin verifies one
  known-good signature per algorithm and warns naming any refused. A zone signed
  only with a refused algorithm is an insecure delegation (RFC 6840 section 5.2):
  served, no AD. A zone that also publishes a checkable algorithm is validated on
  that one, and an RRset carrying only the refused signature is bogus (RFC 6840
  section 5.11). If no root trust anchor survives the probe, or no anchor for a
  zone below it does, the server refuses to start; the built-in anchors both use
  RSA/SHA-256.
- **A policy can also refuse a key size.** Fedora's and RHEL's DEFAULT policy
  requires RSA keys of at least 2048 bits. The probe uses a 2048-bit key, so RSA
  reports runnable, and a zone with a 1024-bit RSA zone-signing key then fails its
  signature check inside a secure zone: SERVFAIL, not an unvalidated answer.
- **NS records in the authority section of a positive answer need not be signed**;
  a forwarder cannot tell the parent's copy of a delegation from the child's. The
  answer section is validated in full.
