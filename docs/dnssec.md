# DNSSEC

```yaml
dnssec:
  enabled: true
  max_nsec3_iterations: 100
  max_chain_walks: 0     # 0 is server.workers less a reserved quarter
  max_connection_walks: 0 # the same, from server.max_connections
  max_cached_zones: 0    # 0 is 4096
  trust_anchors: []      # empty uses the built-in root keys
```

elodin checks the signatures on the answers it forwards instead of taking the
upstream's word for them. An answer that does not check out becomes SERVFAIL and
never reaches the client; one that does gets the AD bit; a name in an unsigned
zone is served normally, because unsigned is not the same as forged. Turning it
off is for an upstream that cannot be trusted to return DNSSEC records — an ISP
or captive-portal resolver — against which every signed zone would otherwise stop
resolving rather than merely going unverified.

`max_nsec3_iterations` is the most hashing a single NSEC3 record may ask for. A
record above it is not computed. A denial made only of such records is insecure,
so the NXDOMAIN or NODATA is served without the AD bit — what RFC 5155 section
10.3 asks and what Unbound, BIND and Knot do past their own ceilings — and with
extended error 27, as RFC 9276 asks. The zone's signed records still validate,
and an unsigned answer inside it is still refused: this server cannot tell an
unsigned delegation it could not read from a forgery, so a name below one comes
back SERVFAIL with extended error 27, as it did before. The cost is that anyone
on the path can make a name in such a zone look absent — and in a zone that has
moved off such a chain, for as long as the old chain's signatures last, by
replaying its records alone. What it cannot do is have a forged record served, a
wildcard included, which stays SERVFAIL. Where readable records sit beside
refused ones, as in a zone changing its parameters, the readable ones decide; if
they prove nothing the name comes back SERVFAIL with extended error 27, because
the work this server declined may have held the proof. RFC 9276 asks zones for
zero and the zones still publishing NSEC3 use single digits, so this is a guard
against a zone that has picked a number nobody should, rather than a setting to
tune.

`max_chain_walks` is how many chain-of-trust walks may be waiting on an upstream
at once. Establishing the zone an answer was signed by means one DS lookup per
label of the name, each a blocking round trip on the worker already answering the
client, and how many labels there are is the client's to choose — so without a
bound, a flood of names whose upper labels are fresh holds every worker for the
better part of a second apiece. Past this many, a walk reads the caches and
answers SERVFAIL where it would have gone upstream, with the same extended error
an upstream that did not answer produces. It is never served as insecure: load
shedding must not be a way to strip a zone's signatures.

Zero, the default, is `server.workers` less a reserved quarter of them (at least
two). The reserved quarter is free of the *walk*, not idle — one may still be
parked on the query's own upstream forward, which nothing here bounds — so what
the reservation buys is that those workers come back in a round trip instead of
in the thirty a walk may take, and the pool keeps draining its queue. Enough of a
flood will still fill every worker; what it can no longer do is hold them for a
walk apiece.

It is a reservation rather than a ceiling on purpose: every cache-missing
name that is not already known to be no zone cut needs a slot, so a resolver that
is merely busy — a restart with real traffic pointed at it, where nearly every
query is a cold walk — would refuse validated answers if the bound were set to
what a flood should be allowed. Reserving leaves the honest load nearly untouched
and still denies an attacker the last worker.

What it does not bound tightly is upstream volume: nearly the whole pool may be
walking, so a flood is answered rather than absorbed. That is the trade — worker
starvation for upstream volume, degraded rather than down — and an operator who
would rather cap the volume sets a smaller number here.

There are two of these bounds, and `max_chain_walks` is the one for the shared
handler pool — UDP and DoH over HTTP/2. TCP, DoT and DoH over HTTP/1.1 answer on
the connection's own thread and get `max_connection_walks`, derived the same way
from `server.max_connections` and counted separately, so a flood on one transport
cannot spend the other's allowance. Two numbers because the two are sized by
different things: a figure right for sixteen workers would refuse ordinary stream
traffic, and one right for 512 connections would bound the pool at nothing. The
defaults differ accordingly — 12 against 16 workers, 384 against 512 connections
— so lowering one does nothing for the other, and an operator capping the upstream
volume a flood can provoke has to set both.

What the bound costs while it binds is much more than the flood's own names, and
it is worth reading before choosing a number. A cached apex is not a cached name
— a name below one still costs a DS lookup per label — and a cold name in an
*unsigned* zone costs one too, because there is no way to know a zone is unsigned
without asking for the DS and being shown there is none. So while every slot is
held, what still answers is what the caches hold: every other cold name is
SERVFAIL, signed or not.

One thing shedding does not do is save the forward: the upstream answer is
already in hand by the time validation runs, so what is saved is the chain walk's
own DS and DNSKEY lookups — the amplification #356 is about — and not the
client's own question. The answer is discarded rather than cached, too, so a
legitimate cold name asked repeatedly during a flood is re-forwarded and shed
again each time rather than settling.

`elodin_dnssec_queries_shed_total` counts the queries that stopped. It says the
bound was reached; it does not say why, and nothing here can — an attack and
honest saturation look identical from inside. A flood is one way to reach it. So
is a restart with real traffic pointed at a cold cache, and so is one upstream in
the group black-holing, since every walk then runs to the timeout and holds its
slot for the whole of it. Read a rising count as "more concurrent cold walks than
this bound allows" and go looking: if upstream latency is normal and the load is
yours, the number wants raising. `--check` and the startup log both name the two
numbers in use, and startup warns if a configured one leaves nothing reserved in
its own pool, which is that bound switched off. The client is told the answer
could not be established and no more: which internal limit stopped the walk is in
the log and the counter, not in the extended error, since it would otherwise tell
one client how busy this server is with everybody else's traffic.

One thing the number does not account for: with `strategy: race`, a walk waiting
on an upstream also holds one job per candidate server in the racer pool
(`server.upstream_workers`), so a group of three upstreams turns each walk into
three jobs, and the handler threads the reservation was keeping free can still
queue there. Raise `upstream_workers` with the number of upstreams if that matters
more than the memory. `failover` and `round_robin` resolve on the calling thread
and have no racer job to take, so they are unaffected.

A query also has a hashing allowance of its own, and above a ceiling of 255 —
derived from that allowance, so a build that retunes it says its own number in
the log line below — the allowance is what answers: the zones a higher ceiling
admits are the ones whose proofs it cannot pay for, so a larger number buys
SERVFAIL rather than more validation. A configuration carrying one is held down
to 255 at startup, with a line in the log saying so, rather than refused — a
resolver that will not come up is worse than either.

Being a forwarder rather than a recursor, elodin fetches the material it
validates against: every DS and DNSKEY down from the root, through the configured
upstreams, with DO and CD set. Zone keys are cached, so the cost falls on the
first query into a zone and not the ones after it.

`max_cached_zones` is how many zones that cache holds — an apex's keys, or the
fact that an apex is unsigned. Zero, the default, is 4096, which covers the
hierarchy a busy forwarder touches with room to spare; a household resolver never
fills it. It is exposed because it is the one dial on how much memory validation
may hold: a zone's keys are capped at 8 KB of RDATA whatever it publishes, and
an entry costs about 12 KB at worst once the key structs, the entry and the name
are counted — so the ceiling is that times this number, about 48 MB at the
default. A box that must keep validation inside a slice of its memory sets it
here; raising it above 4096 logs the figure the new number implies. Past the
bound the coldest zone is dropped, one at a time — so a number that is too small
costs chain walks for the zones that fell out, and nothing else. There is no
reason to raise it above the default unless the resolver genuinely sees more
zones than that; the memory is the cost.

What a flood of fresh delegations cannot do is take everybody else's keys with
it. The root, the TLDs and whatever else is in steady use are read at the start of
every walk, which keeps them at the warm end of the cache, while each single-use
name the flood inserts displaces only the coldest thing there. Up to 0.18.0 the
full cache was emptied wholesale instead, so 4096 names of one client's choosing
cost every other client a re-walk from the root.

| | |
|---|---|
| chain of trust | root → TLD → zone, DS against DNSKEY at every step |
| algorithms | RSA/SHA-1, RSA/SHA-256, RSA/SHA-512, ECDSA P-256 and P-384, Ed25519, Ed448 |
| DS digests | SHA-1, SHA-256, SHA-384 |
| denial of existence | NSEC and NSEC3, including closest-encloser proofs and opt-out |
| wildcards | a wildcard answer must come with a proof that the name had nothing of its own |
| unsigned zones | insecure: served, no AD bit |
| bounds | 32 DS/DNSKEY lookups and 64 signature checks per question, 24 zone cuts of chain, 8 signatures per RRset, 64 keys per zone and 8 KB of them cached, 8 hint targets per answer, 100 NSEC3 iterations |
| a DS set naming nothing we can check | an insecure delegation, whether the algorithm is unimplemented here or refused by the host's crypto policy — RFC 6840 section 5.2 |
| a DS set naming something we can check | that path has to hold up: a DNSKEY set it does not lead to is bogus, however many uncheckable DS records sit beside it |
| bad signature, broken chain, missing proof | SERVFAIL, with an extended DNS error (RFC 8914) saying which |

The first refusal of each verdict since start reaches the log as a warning
carrying the verdict, the reason and the server the answer came from, and later
ones are logged at `debug`. Every refusal carries `outcome=failed
detail=dnssec:<upstream>` on its query line, or `detail=dnssec:cache` when the
verdict was answered from the cache:

```
ts=2026-08-07T09:12:52Z level=warn msg="dnssec: A xc.example.com from 192.0.2.10:44188 did not validate: Bogus (denial of existence not proven); answer came from quad9-dot"
ts=2026-08-07T09:12:52Z level=info msg=query client=192.0.2.10 port=44188 proto=udp qtype=A qname=xc.example.com outcome=failed detail=dnssec:quad9-dot ms=126.5
```

The upstream is on both lines because the verdict belongs to the answer and not
to the name: where the members of a group disagree about a zone — one that
cannot reach it, one serving a denial that proves nothing — the same question
fails through one server and validates through another, and nothing else on the
line tells those apart. The reason stays in front of the name, so
`detail=dnssec` still matches every one of them.

The trust anchors are the root key-signing keys IANA publishes, both KSK-2017 and
KSK-2024, compiled in, so a rollover between the two needs no new build.
`trust_anchors` replaces them, taking either bare DS fields or a full
presentation-form record:

```yaml
dnssec:
  trust_anchors:
    - ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
```

An answer that gets the AD bit is first cut down to the records that earned it,
RFC 4035 section 3.2.3 allowing the bit only over data the resolver
authenticated. Address records beside an HTTPS, SVCB, SRV or MX answer are the
exception, and not by being waved through: RFC 9460 section 5 asks for them so a
client can connect without a second query, so elodin establishes the target's own
zone and keeps the hints whose signatures hold up there. Nothing about a hint can
change the verdict on the answer it came with.

A client that sets CD gets the data whatever the verdict — resolvers chaining
behind elodin rely on that — and those answers are cached under a separate key so
they can never reach a client that did want the check. A client that did not set
DO gets the DNSSEC records stripped back out.

**Four groups of names are served insecure**, without the AD bit, because there
is no chain to walk and refusing them would be worse than not validating them:

- The RFC 6303 and RFC 7793 locally-served reverse zones — the RFC 1918 ranges,
  CGNAT (100.64/10), `0/8`, IPv4 link-local and loopback, IPv6 unique-local and
  link-local. Nobody signs them,
  so validating would turn every LAN PTR lookup into SERVFAIL. Unbound and BIND
  ship the same default. A `trust_anchors` entry covering one turns validation
  back on for it.
- Zones routed under [`upstream.zones`](upstreams.md#per-domain-upstreams), which hold
  unsigned data under a public parent that delegates nothing to them, so the
  chain walk would find a missing delegation and call a good answer bogus. A
  `trust_anchors` entry stands that bypass down the same way.
- `home.arpa`. `arpa` delegates it to the blackhole servers with no DS and signs
  that delegation, so against a public upstream a validator learns the zone is
  insecure and serves the router's unsigned answer. It breaks when the upstream
  *is* the router: authoritative for the zone, it answers `home.arpa DS` from its
  own zone rather than forwarding to `arpa`, so the proof the delegation is
  insecure never arrives and the chain reads as broken rather than provably
  absent. Nothing under `home.arpa` can be secure in any case, the delegation
  having no DS by design. The names are still forwarded to `upstream.servers` by
  default; a router here that does answer the zone wants
  [`upstream.zones`](upstreams.md#per-domain-upstreams) pointed at it, and if nothing serves
  the zone at all, [`special_use.home_arpa`](reserved-names.md#reserved-names) answers those names
  here. Either way the `home.arpa DS` query itself goes to `upstream.servers` —
  not down the route, and not answered from the reserved-name table — RFC 8375
  requiring that proof be fetched rather than invented. If you do run the zone,
  its private addresses trip [rebind
  protection](rebinding.md#dns-rebinding-protection) unless it is routed or named in
  `rebind.allow_domains`.
- `.onion`, whenever it is forwarded at all, since the root publishes a signed
  proof that there is no `onion.` to delegate and a Tor-aware upstream's answer
  therefore reads as forgery. Both `special_use.onion: false` and
  `special_use.enabled: false` forward those names and stand validation down for
  them; see [Reserved names](reserved-names.md#reserved-names).

`resolver.arpa` is answered NODATA here rather than forwarded. That is where a
client looks for the encrypted endpoints of the resolver it is already using (RFC
9462's Discovery of Designated Resolvers), so forwarded it would hand back the
*upstream's* designation and a client that took it would move to Quad9 or
Cloudflare directly, leaving the block lists, the rewrites and the query log
behind; RFC 9462 section 6.1 says a forwarder should not forward these. A
`rewrites` rule for the name still wins, for an operator who does want to
advertise this server's own endpoints.

Two things worth knowing with validation on:

- **Distribution crypto policy can take algorithms away.** Fedora and RHEL ship an
  OpenSSL that refuses SHA-1 signatures outright, covering DNSSEC algorithms 5
  and 7. elodin asks the library which algorithms it will actually run — one
  known-good signature per algorithm, at start-up — and names anything refused in
  a warning as it starts, so the downgrade is not a silent one. A zone signed
  only with a refused algorithm is then an insecure *delegation*, which is where
  RFC 6840 section 5.2 puts that decision: served, no AD bit, same as any
  unsigned zone. A zone that publishes a refused algorithm beside one we can
  check is validated on the one we can check, and an RRset inside it that
  arrives with only the refused signature is bogus rather than unsigned — the
  strip attack RFC 6840 section 5.11 is about. If no trust anchor for the root
  survives the probe the server refuses to start rather than come up validating nothing:
  the built-in root anchors both name RSA/SHA-256, so a policy that took that
  one algorithm away would leave no way into the DNS at all. `dnssec.enabled:
  false` is how to ask for unvalidated answers on purpose.
- **A policy can also refuse a key rather than an algorithm, and that one costs
  resolution.** Fedora's and RHEL's DEFAULT policy sets a minimum RSA modulus of
  2048 bits alongside the SHA-1 ban. The probe verifies with a 2048-bit key, so
  RSA is reported runnable, and a zone whose own key is smaller is then refused
  when its signature is checked — inside a zone already established as secure,
  which is SERVFAIL rather than an unvalidated answer. It is what RFC 6840
  section 5.11 asks for and what other validators do there, but on such a host a
  zone with a 1024-bit RSA zone-signing key stops resolving rather than resolving
  without the AD bit. Answering it any other way means judging the key at the
  delegation, which nothing here does yet.
- **NS records in the authority section of a positive answer are not required to
  be signed**, a forwarder being unable to tell the parent's copy of a delegation
  from the child's. The answer section is validated in full; this affects only
  what rides alongside it.
