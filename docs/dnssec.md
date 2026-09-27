# DNSSEC

```yaml
dnssec:
  enabled: true
  max_nsec3_iterations: 100
  max_chain_walks: 0      # 0 is server.workers less a reserved quarter
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
down from the root, through the configured upstreams, with DO and CD set. Zone
keys are cached, so the cost falls on the first query into a zone.

## What is checked

| | |
|---|---|
| chain of trust | root → TLD → zone, DS against DNSKEY at every step |
| algorithms | RSA/SHA-1, RSA/SHA-256, RSA/SHA-512, ECDSA P-256 and P-384, Ed25519, Ed448 |
| DS digests | SHA-1, SHA-256, SHA-384 |
| denial of existence | NSEC and NSEC3, including closest-encloser proofs and opt-out |
| wildcards | a wildcard answer must come with a proof that the name had nothing of its own |
| unsigned zones | insecure: served, no AD bit |
| bounds | 32 DS/DNSKEY lookups and 64 signature checks per question, 24 zone cuts of chain, 8 signatures per RRset, 64 keys per zone and 8 KB of them cached, 8 hint targets per answer, 100 NSEC3 iterations |
| a DS set naming nothing we can check | an insecure delegation, whether the algorithm is unimplemented here or refused by the host's crypto policy (RFC 6840 section 5.2) |
| a DS set naming something we can check | that path has to hold up: a DNSKEY set it does not lead to is bogus, however many uncheckable DS records sit beside it |
| bad signature, broken chain, missing proof | SERVFAIL, with an extended DNS error saying which |

An answer that gets AD is first cut down to the records that earned it (RFC 4035
section 3.2.3). Address hints beside an HTTPS, SVCB, SRV or MX answer (RFC 9460
section 5) are kept only when they validate in the target's own zone; a hint
never changes the verdict on the answer.

A client that sets CD gets the data whatever the verdict; those answers are
cached under a separate key, so they never reach a client that wanted the check.
A client that did not set DO gets the DNSSEC records stripped.

## Logging

The first refusal of each verdict since start is logged at `warn` with the
verdict, the reason and the upstream the answer came from; later ones at
`debug`. Every refusal's query line carries `outcome=failed
detail=dnssec:<upstream>`, or `detail=dnssec:cache` when answered from the cache:

```
ts=2026-08-07T09:12:52Z level=warn msg="dnssec: A xc.example.com from 192.0.2.10:44188 did not validate: Bogus (denial of existence not proven); answer came from quad9-dot"
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
```

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
one blocking DS lookup per label, on the worker answering the client, and the
client chooses the labels; the bound keeps a flood of fresh names from holding
every worker for a whole walk. A large enough flood still fills the pool, since
the reserved workers can be busy on the query's own forward, but each comes back
in one round trip rather than thirty. A cached apex is not a cached name: a name
below one still costs a DS lookup per label.

| setting | covers | default (0) |
|---|---|---|
| `max_chain_walks` | the shared handler pool: UDP and DoH over HTTP/2 | `server.workers` less a reserved quarter (at least two): 12 of 16 workers |
| `max_connection_walks` | per-connection threads: TCP, DoT and DoH over HTTP/1.1 | the same from `server.max_connections`: 384 of 512 connections |

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

`--check` and the startup log name both numbers in use. Startup warns when a
configured value leaves nothing reserved in its pool, which switches the bound
off:

```
dnssec: max_chain_walks <n> leaves none of the <n> workers reserved, so a flood of fresh names can hold them all; see issue #356
dnssec: max_connection_walks <n> leaves none of the <n> connection threads reserved, so a flood of fresh names can hold them all; see issue #356
```

With `strategy: race`, a waiting walk also holds one racer job per upstream in the
group (`server.upstream_workers`), so handler threads the reservation keeps free
can still queue there. Raise `upstream_workers` with the number of upstreams if
that matters more than the memory. `failover` and `round_robin` resolve on the
calling thread and are unaffected.

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
  section 5.11). If no root trust anchor survives the probe, the server refuses to
  start; the built-in anchors both use RSA/SHA-256.
- **A policy can also refuse a key size.** Fedora's and RHEL's DEFAULT policy
  requires RSA keys of at least 2048 bits. The probe uses a 2048-bit key, so RSA
  reports runnable, and a zone with a 1024-bit RSA zone-signing key then fails its
  signature check inside a secure zone: SERVFAIL, not an unvalidated answer.
- **NS records in the authority section of a positive answer need not be signed**;
  a forwarder cannot tell the parent's copy of a delegation from the child's. The
  answer section is validated in full.
