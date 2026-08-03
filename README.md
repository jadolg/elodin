# elodin

A filtering DNS forwarder in [Odin](https://odin-lang.org), in the spirit of
Pi-hole and AdGuard Home, minus the web interface. One binary, one YAML file.

- Serves plain DNS (UDP + TCP), DNS-over-TLS and DNS-over-HTTPS (HTTP/2 and HTTP/1.1)
- Forwards to plain, TCP, DoT and DoH upstreams
- Three upstream strategies: failover, round-robin and race
- Sink lists in hosts, plain-domain and adblock syntax, with allowlists
- Answer cache with negative caching and optional stale serving
- Local rewrites (A, AAAA, CNAME, or "answer as if blocked")
- DNSSEC validation against the root trust anchors, on by default
- DNS cookies towards clients (RFC 7873/9018), on by default

## Requirements

- [mise](https://mise.jdx.dev) — pins the toolchain (Odin, clang, and Go for the
  benchmark) and runs the tasks; `mise install` fetches them
- OpenSSL 3.x with headers (`openssl-devel` / `libssl-dev`) for DoT, DoH and the
  DNSSEC signature checks

Odin shells out to `clang` as its linker driver, so mise pins that too rather
than relying on the distribution shipping an unversioned `clang`. The pinned
build is a conda-forge one that defaults to conda's own sysroot, so the tasks
pass `--sysroot=/ -B/usr/bin` to send the linker back to the system — elodin
links against the system OpenSSL, and that pair of flags names no library
directory, so it holds across distributions. The flags live in `ELODIN_LDFLAGS`
in `mise.toml`; drop the `clang` pin from `[tools]` and they become unnecessary
if you would rather use your own toolchain.

```sh
mise trust
mise run build      # bin/elodin, with debug info
mise run release    # bin/elodin, optimised
mise run test       # unit tests
mise run itest      # integration tests against the built binary
mise run verify     # check + test + itest
mise run check      # type-check with -vet -strict-style
mise run certs      # self-signed certificate for local DoT/DoH testing
mise run bench      # throughput, latency, CPU and memory (see bench/README.md)
```

## Running

`mise run run` starts elodin with `examples/dev.yaml`, which listens on 5354 and
caches blocklists under `.cache/` so it runs as an ordinary user.

```sh
mise run run                                            # local, unprivileged
./bin/elodin --config examples/elodin.yaml              # the real thing
./bin/elodin --config examples/elodin.yaml --check      # validate and exit
./bin/elodin --config examples/elodin.yaml --no-fetch   # skip list downloads
```

`examples/elodin.yaml` binds port 53 and caches under `/var/cache/elodin`, so it
needs privileges. The way to give it exactly the one it needs is
`CAP_NET_BIND_SERVICE`, which lets it bind below 1024 and start unprivileged:

```sh
sudo setcap 'cap_net_bind_service=+ep' ./bin/elodin
```

Starting as root works too, but then set `server.user` so it does not stay
root — see [Privileges](#privileges).

If the port is already taken it is usually the system resolver:
`sudo systemctl stop systemd-resolved`. elodin says as much when a bind fails.

A cache directory it cannot write is a warning, not an error: the lists are
still downloaded and applied, they just have to be fetched again on the next
start.

`examples/elodin.yaml` documents every setting. A minimal config is:

```yaml
upstream:
  servers:
    - tls://1.1.1.1:853#cloudflare-dns.com
blocking:
  lists:
    - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
```

### As a service

`packaging/elodin.service` is a systemd unit for the usual arrangement: the
binary at `/usr/local/bin/elodin`, the configuration at
`/etc/elodin/elodin.yaml`.

```sh
sudo install -m755 bin/elodin /usr/local/bin/elodin
sudo install -Dm644 examples/elodin.yaml /etc/elodin/elodin.yaml
sudo install -m644 packaging/elodin.service /etc/systemd/system/
sudo systemctl enable --now elodin
```

It binds :53 through `AmbientCapabilities=CAP_NET_BIND_SERVICE` rather than as
root, and runs under `DynamicUser=yes` with `ProtectSystem=strict`, so systemd
provides the state, cache and configuration directories and nothing else on the
filesystem is writable. `RestrictAddressFamilies=AF_INET AF_INET6` leaves it the
two families it actually uses.

A published GitHub release carries a `linux-amd64` and a `linux-arm64` tarball
built by `.github/workflows/release.yml`, each holding the optimised binary, the
unit file and the example configuration. Both are built natively, on a runner of
the architecture they target, because elodin binds the system libssl and
libcrypto and cross-compiling would mean carrying a sysroot for each. CI runs
`mise run check` once and `mise run test` and `mise run itest` on both
architectures, on every push and pull request.

### Privileges

Binding a port below 1024 is the only privileged thing elodin does, and it is
over within a second of starting. Everything after that — DNS wire data, HTTP/2
frames, TLS records — is parsing input that came off the network, and it runs
for the life of the process. A resolver that is still root while doing that
turns any single bug in that code into a root compromise rather than the loss of
one service account. The release build keeps bounds checks on, so a missed guard
in a parser is a crash rather than a write at an offset the peer chose — but a
bounds check is the last line, not the only one, and it does nothing for the
classes of bug it cannot see.

There are two ways not to be root, and either is enough:

**Never become root.** Grant the capability instead, which is what the systemd
unit does with `AmbientCapabilities=CAP_NET_BIND_SERVICE` and `DynamicUser=yes`.
By hand, `sudo setcap 'cap_net_bind_service=+ep' ./bin/elodin` and start it as
an ordinary user. Leave `server.user` empty here — there is nothing to drop.

**Start as root and put it down.** Name an account in `server.user`, and elodin
switches to it the moment the listeners have their ports:

```yaml
server:
  user: elodin        # a name or a numeric uid
  group: elodin       # optional; defaults to the user's primary group
```

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin elodin
```

The supplementary groups are cleared first, then the gid, then the uid, all
three of real, effective and saved — so there is no saved uid to step back
into — and the result is read back from the kernel before it is reported. A drop
that was configured and did not happen ends the process rather than leaving it
running as root.

`blocking.cache_dir` changes owner along with the process, because the lists are
downloaded before the listeners bind and a refresh hours later has to reopen
them. `log.file` needs nothing: it is opened once at startup and the process
keeps writing through that descriptor.

A misspelt account name is caught by `--check`, so a bad `server.user` is a
configuration error before a restart rather than a resolver that comes up, takes
port 53 and then exits. Running as root with no `server.user` set logs a warning
at startup.

### Stopping

`SIGTERM` and `SIGINT` ask for an orderly shutdown: the listeners stop, the
worker pools drain what they had queued, and everything those jobs use is
released afterwards rather than out from under them. An idle server is gone in
well under a tenth of a second.

Open client connections are waited on, and a connection sitting idle is only
noticed when its read times out — so with clients connected, stopping can take
up to `server.client_timeout` (ten seconds by default). That is comfortably
inside systemd's `TimeoutStopSec`. A second signal skips the wait and terminates
immediately, for when that is not what you want.

### Observing it

There is no metrics endpoint. Statistics go to the log every five minutes —
queries, blocked, cached, forwarded, failed, dropped, secure and bogus counts,
plus cache entries, hits, misses and evictions — and `log.queries` adds one line
per query, at the cost noted under [Resource use](#resource-use).

## Configuration

### Upstreams

Each server is either a mapping or a shorthand string:

```yaml
upstream:
  strategy: failover
  timeout: 5s
  attempts: 2
  bootstrap: [1.1.1.1, 9.9.9.9]   # resolves upstream hostnames
  servers:
    - name: cloudflare-dot
      type: tls                    # udp | tcp | tls | https
      address: 1.1.1.1
      port: 853
      hostname: cloudflare-dns.com # SNI and certificate name
    - https://dns.google/dns-query
    - tcp://9.9.9.9
    - 192.168.1.1
```

`bootstrap` matters: elodin resolves upstream hostnames itself rather than
through the system resolver, since on a machine where elodin *is* the system
resolver the latter would come straight back to a server that has not started
listening yet.

A `https` upstream picks between HTTP/2 and HTTP/1.1 with ALPN, preferring h2,
the same way the [DoH listener](#dns-over-https) does — some public resolvers
answer HTTP/1.1 only, and elodin does not assume either is always available.
Every concurrent query against an h2 upstream multiplexes onto one shared
connection instead of opening one per request; an upstream that turns out to
speak HTTP/1.1 falls back to the same pooled-connection model TCP and DoT use.
Which protocol a given upstream speaks is discovered once, from its first
connection, and not re-checked after.

Strategies:

| `strategy`    | behaviour                                                        |
|---------------|------------------------------------------------------------------|
| `failover`    | try servers in configured order until one answers                |
| `round_robin` | the same, but the starting position advances on every query      |
| `race`        | query every healthy server at once, take the first usable answer |

An upstream that fails three times in a row is skipped for ten seconds, so a
dead server stops costing every query a full timeout. If every upstream is in
that state they are all tried anyway.

A TLS handshake the peer resets partway through is retried once before it counts
as one of those failures — some public resolvers do this to a fair share of
fresh connections while the very next attempt goes through, and without the
retry a run of them parks a server that is working. Only a reset is retried: it
comes back in a round trip, where a timeout has already spent the query's budget
and a rejected certificate will not improve on a second look. This covers DoT
and every HTTPS upstream alike.

### Sink lists

```yaml
blocking:
  enabled: true
  response: nxdomain     # nxdomain | nodata | zeroip | custom | refused
  custom_ipv4: 0.0.0.0
  custom_ipv6: "::"
  block_ttl: 60
  refresh: 24h
  cache_dir: /var/cache/elodin

  lists:
    - name: steven-black
      url: https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
      format: hosts      # auto | hosts | domains | adblock
    - name: personal
      file: /etc/elodin/blocklist.txt

  allowlists: []
  rules: ["||doubleclick.net^"]
  allow: ["||googleadservices.com^"]
```

What each list format matches:

| syntax                | matches                          |
|-----------------------|----------------------------------|
| `0.0.0.0 ads.foo.com` | `ads.foo.com` exactly            |
| `ads.foo.com`         | `ads.foo.com` and its subdomains |
| `\|\|ads.foo.com^`    | `ads.foo.com` and its subdomains |
| `*.foo.com`           | subdomains of `foo.com` only     |
| `@@\|\|safe.foo.com^` | never blocked                    |

Hosts entries are exact because hosts-format lists spell out every subdomain
they mean; bare domains and `||` rules cover subtrees. This matches how AdGuard
Home reads the same files. Allow rules always win over block rules.

Downloaded lists are cached under `cache_dir`. A refresh that fails falls back
to the cached copy, so a network outage cannot silently turn blocking off.
Rules that cannot be expressed as a domain (regexes, path-scoped rules) are
skipped rather than failing the whole list.

### DNS-over-HTTPS

The endpoint serves both HTTP/2 and HTTP/1.1 and picks between them with ALPN,
preferring h2. That matters because Firefox and Chrome will only use a DoH
resolver over HTTP/2; curl, `dnscrypt-proxy` and routers that speak HTTP/1.1
keep working unchanged. A client offering neither gets a clean handshake
failure rather than a connection that then talks past us.

```yaml
listeners:
  doh:
    enabled: true
    address: "0.0.0.0"
    port: 443
    path: /dns-query
    cert_file: /etc/elodin/cert.pem
    key_file: /etc/elodin/key.pem
```

Both request forms of RFC 8484 are accepted on either version: `POST` with an
`application/dns-message` body, and `GET` with a base64url `dns` parameter.

Requests arriving on one HTTP/2 connection are answered on the query worker pool
rather than one after another on the connection's reader thread, so the A and
AAAA lookups a browser issues for the same name run at the same time. Responses
are written under the connection's write lock and may complete in any order.

The implementation (`src/h2/`) covers what a DoH endpoint needs: the connection
preface and SETTINGS exchange, HPACK with Huffman decoding and a full dynamic
table, HEADERS with CONTINUATION, DATA, connection- and stream-level flow
control, WINDOW_UPDATE, PING, RST_STREAM and GOAWAY. Server push is refused in
SETTINGS and stream priority is parsed and ignored, which RFC 9113 permits.

### DNSSEC

```yaml
dnssec:
  enabled: true
  max_nsec3_iterations: 100
  trust_anchors: []      # empty uses the built-in root keys
```

With this on, elodin checks the signatures on the answers it forwards instead of
taking the upstream's word for them. An answer that does not check out becomes
SERVFAIL and never reaches the client; one that does gets the AD bit; a name in
an unsigned zone is served normally, because unsigned is not the same as forged.

It is on by default: a resolver that forwards signatures without checking them
gives the answers an authority they have not earned. Turning it off is for an
upstream that cannot be trusted to return DNSSEC records — an ISP or
captive-portal resolver, say — since against one of those every signed zone
would stop resolving rather than merely going unverified. That is a decision
for whoever runs the resolver.

Being a forwarder rather than a recursor, elodin has to ask for the material it
validates against: every DS and DNSKEY on the way down from the root is fetched
through the configured upstreams, with DO and CD set so the signatures arrive
and the upstream's own verdict stays out of the way. Zone keys are cached, so
the cost falls on the first query into a zone and not on the ones after it —
measured here, a name under a cold TLD takes 20–70 ms to establish and nothing
thereafter.

What is checked, and what happens when it does not hold:

| | |
|---|---|
| chain of trust | root → TLD → zone, DS against DNSKEY at every step |
| algorithms | RSA/SHA-1, RSA/SHA-256, RSA/SHA-512, ECDSA P-256 and P-384, Ed25519, Ed448 |
| DS digests | SHA-1, SHA-256, SHA-384 |
| denial of existence | NSEC and NSEC3, including closest-encloser proofs and opt-out |
| wildcards | a wildcard answer must come with a proof that the name had nothing of its own |
| unsigned zones | insecure: served, no AD bit |
| bounds | 32 DS/DNSKEY lookups per question, 24 labels of chain, 8 signatures per RRset, 64 keys per zone, 100 NSEC3 iterations |
| algorithm we cannot check | insecure, not bogus — RFC 4035 treats unverifiable data as unsigned |
| bad signature, broken chain, missing proof | SERVFAIL, with an extended DNS error (RFC 8914) saying which |

The trust anchors are the root key-signing keys IANA publishes, both KSK-2017
and KSK-2024, compiled in — a rollover between the two needs no new build.
`trust_anchors` replaces them, taking either bare DS fields or a full
presentation-form record:

```yaml
dnssec:
  trust_anchors:
    - ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
```

A client that sets CD is asking for the data whatever the verdict, and gets it —
that is what the bit is for, and resolvers chaining behind elodin rely on it.
Those answers are cached under a separate key so they can never be handed to a
client that did want the check. A client that did not set DO gets the DNSSEC
records stripped back out of its answer, which is both what RFC 4035 asks for
and what keeps ordinary answers from growing past the point of needing a retry
over TCP.

Two things worth knowing about running with it on:

- **Distribution crypto policy can take algorithms away.** Fedora and RHEL ship
  an OpenSSL that refuses SHA-1 signatures outright (`rh-allow-sha1-signatures =
  no`), which covers DNSSEC algorithms 5 and 7. elodin treats an algorithm it
  cannot check as unsigned rather than as broken, so those zones — `pir.org` and
  `comcast.net` among them — come back without the AD bit instead of failing.
  That is the safe direction, but it is a downgrade, and it is silent.
- **NS records in the authority section of a positive answer are not required
  to be signed.** A forwarder cannot tell the parent's copy of a delegation,
  which is unsigned by definition, from the child's, which is not. The answer
  section is validated in full; this affects only what rides alongside it.

### DNS cookies

```yaml
cookies:
  enabled: true
  require: false
  secret: ""             # 32 hex characters; empty draws a random one at startup
```

A client talking to elodin over UDP has two things standing between it and a
forged answer from somewhere on the local network: a 16-bit transaction ID and a
randomised source port. That is about 32 bits, and both are visible to anyone on
the path. Cookies (RFC 7873, RFC 9018) add 64 bits that are not: a client that
has asked once holds a token only this server could have produced, and an answer
that comes back without it did not come from here.

Nothing is remembered per client. The token is recomputed on each query from the
client's own cookie, its address and a timestamp, keyed by a secret this process
holds — so there is no table for a flood of clients to fill, and a cookie that
does leak stops working within the hour. Clients that do not use cookies are
untouched: an answer only carries one when the query did.

`require` is the other half of the mechanism, and is off by default. With it on,
a UDP query that carries a cookie but cannot show a valid server cookie is
answered with BADCOOKIE and a cookie to come back with, before the name is
looked up at all — so an attacker forging queries from someone else's address
never gets an answer sent there. The cost falls on honest clients too, one extra
round trip the first time each one asks, which is why RFC 7873 has it for use
while an attack is actually under way. Queries carrying no cookie, and queries
over TCP, DoT or DoH, are unaffected either way.

`secret` matters when more than one elodin answers on the same address: without
it each draws its own at startup and rejects the cookies the others handed out.
A single instance can leave it empty.

The client's cookie stops at elodin and is never forwarded upstream. It is a
secret between that client and this server — a stable identifier an upstream has
no business seeing — and its server half was minted here, so an upstream that
implements cookies would read it as a forgery and answer BADCOOKIE instead of
the question. elodin does not yet present cookies of its own to its upstreams;
correlation there rests on the transaction ID, a randomised source port, the
echoed question and 0x20 case randomisation.

### Rewrites

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

Wildcards match subdomains only, so `*.lan` covers `host.lan` but not `lan`.

## What is implemented

Queries of any type are answered: A, AAAA, CNAME, MX, TXT, SRV, SOA, NS, PTR,
CAA, SVCB/HTTPS, DS, DNSKEY, RRSIG and everything else. Types the codec does not
model natively are carried through as opaque RDATA per RFC 3597, and forwarded
answers are passed back byte for byte, so DNSSEC records survive untouched.
With validation on, an answer for a client that did not ask for DNSSEC records
is rebuilt without them; every other answer still goes back verbatim.

Also handled: EDNS0 (the client's OPT record is forwarded upstream so payload
sizes are negotiated end to end, minus its cookie, which stops here), DNS
cookies towards clients (RFC 7873, RFC 9018), truncation with the TC bit and the
UDP→TCP retry, `version.bind`/`hostname.bind` in the CHAOS class, and refusal of
zone-transfer requests.

The cache stores upstream answers as untouched wire bytes plus the offsets of
their TTL fields, and rewrites those TTLs in place on each hit. That keeps the
original name compression intact and avoids a decode/encode round trip on the
hot path.

## Capacity

Everything below comes out of `mise run bench`, against a mock upstream held at
a realistic 20 ms and with the shipped defaults. The harness lives in `bench/`
and is documented there; the run these figures are from is
`bench/results/2026-08-03-ryzen7-6850u.md`. Re-taking them is the point — a
number here that the harness does not produce is a number to delete.

The machine is a Ryzen 7 PRO 6850U laptop, 16 logical cores. It is a 15 W part
that cannot hold its boost clock through a long run, so read these as the shape
of the thing rather than as a specification: the same table taken from a cold
machine and from a hot one differs by 20–30%, and figures in one table should
not be compared with figures in another.

| workload | throughput | p50 | p99 | peak RSS |
|---|---|---|---|---|
| cache hits | 164,000 qps | 1.1 ms | 3.2 ms | 43 MB |
| blocked | 157,000 qps | 1.2 ms | 2.9 ms | 43 MB |
| rewritten | 158,000 qps | 1.2 ms | 2.8 ms | 43 MB |
| light mixed load (20 in flight) | 136,000 qps | 0.13 ms | 0.42 ms | 43 MB |
| sustained cache misses | 6,100 qps | 21 ms | 24 ms | 47 MB |

Every transport serves many clients at once. With 100 concurrent clients, each
holding its own connection for the run:

| transport | throughput | p50 | p99 | answered per client (min–max) |
|---|---|---|---|---|
| UDP | 158,000 qps | 0.59 ms | 1.7 ms | 15659 – 15923 |
| TCP | 177,000 qps | 0.21 ms | 4.4 ms | 17206 – 18486 |
| DoT | 133,000 qps | 0.36 ms | 5.4 ms | 12935 – 13743 |
| DoH over HTTP/1.1 | 65,000 qps | 0.81 ms | 11 ms | 6256 – 6787 |
| DoH over HTTP/2 | 30,000 qps | 0.59 ms | 21 ms | 2777 – 3233 |

No errors on any of them. The per-client spread stays inside 9% on UDP, TCP, DoT
and HTTP/1.1, so no client is starved by the others; on HTTP/2 it is 16%, which
is what multiplexing costs in fairness — streams from one connection compete for
the same worker pool rather than taking turns. TCP was also run at 500
concurrent connections: 149,000 qps, with the spread widening to 28% as the
per-connection threads start contending.

How each transport reaches that:

- **UDP** has one reader thread that hands every datagram to the worker pool.
  There is no per-client state and no connection limit.
- **TCP, DoT and DoH** give each connection a thread, capped by
  `server.max_connections` (512). Within a single connection, TCP, DoT and
  HTTP/1.1 answer one query at a time; **HTTP/2 multiplexes**. Connections are
  reused, so the cap bounds concurrent *clients*, not queries per second — the
  100-connection runs above carry well over 100,000 qps.

HTTP/2 costs about two and a half times as much CPU per query as HTTP/1.1 on
answers that come straight from the cache — 220 µs against 87 µs — because of
framing, HPACK and the hand-off to the worker pool, and it serves under half the
throughput on that workload. It earns all of that back the moment queries are
slow, which is when a browser is actually waiting. Ten clients issuing eight
concurrent requests each, all of them cache misses against a 20 ms upstream:

| | throughput | p50 |
|---|---|---|
| HTTP/1.1 | 460 qps | 171 ms |
| HTTP/2 | 3,702 qps | 21 ms |

Eight times the throughput at an eighth of the latency — the eight requests
overlap instead of queueing, and p50 settles at one upstream round trip.

Past `max_connections`, DoT and DoH refuse cleanly during the handshake. Plain
TCP cannot: the kernel completes the handshake from the listen backlog before
the server sees it, so a refused client gets a connection reset on first use and
has to reconnect.

The number that governs sizing is the sustained cache-miss row. A worker thread is occupied for
the whole of an upstream round trip, so

```
sustained cache-miss throughput  ≈  server.workers / upstream_rtt
```

which is about 50 qps per worker against a 20 ms upstream. The default of 128
therefore carries roughly 6,000 misses per second. Two consequences worth
knowing:

- **Every query shares that pool**, so running short on workers delays cache
  hits as much as misses. At the old default of 8 workers, answers that take
  60 µs to produce from cache were coming back after 413 ms because the workers
  were all parked on upstream I/O.
- **Memory scales with workers**, at roughly 0.3 MB of scratch arena each.

Past capacity the server drops queries rather than queueing them
(`server.max_pending`, derived as `workers * 8`). With 6,000 clients all asking
for cache misses at once — a thousandfold more demand than a 128-worker pool can
carry against a 20 ms upstream — that is 4,900 qps served at a bounded 166 ms,
and about 25,000 queries dropped over twenty seconds. Given an effectively
unbounded queue the same load serves a comparable 5,900 qps but at 978 ms,
because the backlog rather than the work becomes the latency, and every client
waits behind queries whose own clients have already given up. A dropped query
gets no answer at all, so a client sees it as a timeout and retries, which is
the failure DNS is built for.

### Resource use

CPU, measured on the server process alone while it was saturated:

| transport | CPU per query | at 5,000 qps |
|---|---|---|
| TCP | 37 µs | 0.19 core |
| UDP | 37 µs | 0.19 core |
| DoT | 61 µs | 0.31 core |
| DoH over HTTP/1.1 | 87 µs | 0.44 core |
| DoH over HTTP/2 | 220 µs | 1.10 core |

Answering queries is cheap. **TLS handshakes are not**: 1.1 ms of CPU each with
an ECDSA P-256 certificate and 2.3 ms with RSA-2048 — some thirty times the cost
of answering a query on an established connection. A client that reuses its
connection costs 61 µs per query over DoT; one that reconnects for every query
costs more than a thousand. Sustained fresh handshakes top out around 3,300/s
(ECDSA) or 2,400/s (RSA) and consume most of the machine doing it. `mise run
certs` generates ECDSA for that reason; use ECDSA for real deployments too.

Memory, for a full configuration under load:

| | |
|---|---|
| idle, no lists | 11 MB |
| worker scratch arenas | ~0.26 MB per worker (34 MB at 128) |
| blocklists | ~129 B per rule (31 MB for 250,000 rules) |
| answer cache | ~463 B per entry (4 MB at the default 10,000) |
| **realistic total under load** | **154 MB** with 250,000 rules and 180,000 cached answers |

Each row but the first is a difference between two runs that vary in one thing,
so the cache is not charged for the worker arenas that the same load brings up.

Disk is negligible: an 840 KB binary, and a blocklist cache the size of the
lists themselves (6.5 MB for two large ones). Nothing is written in steady
state — with one exception.

That exception is `log.queries`, which writes 22 MB/s at 220k qps, about 104
bytes per query. It wants rotation. What it does *not* cost is throughput: on
this machine the server was consistently around 20% **faster** with it on
(191,000 qps against 230,000), reproducibly and with a run-to-run spread of a
few percent — while the same configuration measured against itself differs by
under 1%, so it is not an artefact of the ordering. The likeliest explanation is
that the per-query write staggers 128 workers that otherwise contend on the same
hot path. Do not read it as a reason to turn logging on; read it as a reason not
to expect it to cost anything.

The `race` strategy is the other setting with a real price: it multiplies
upstream traffic by the number of servers.

## Known limitations

- DNSSEC validation is **on by default**, and where a distribution's crypto
  policy forbids SHA-1 signatures the two RSA/SHA-1 algorithms degrade to
  insecure rather than validating. See the DNSSEC section above.
- **Connection-oriented transports get a thread per connection**, capped for
  TCP, DoT and DoH together by `server.max_connections` (512). That is fine for
  clients that hold a connection open and pipeline over it, but it does not suit
  tens of thousands of concurrent connections. UDP is the exception: one reader
  thread, no per-client state, no limit.
- Upstream I/O is synchronous, so concurrency is bounded by thread count rather
  than by in-flight queries. The h2 upstream client is the exception — its
  queries multiplex onto one connection — but a worker is still held for the
  round trip. Async upstream I/O, or several UDP reader threads behind
  `SO_REUSEPORT`, would lift both this and the item above; neither is needed at
  the scale measured in the previous section.
- **DNS cookies are answered but not asked.** Clients get one; upstreams are
  never sent one, so correlation on that side still rests on the transaction ID,
  a randomised source port, the echoed question and 0x20 case randomisation. The
  cookie secret is drawn once at startup and never rotated, so restarting costs
  every client one extra round trip.
- No per-client rules, no query log database, no web or API surface. Statistics
  go to the log every five minutes; there is no metrics endpoint to scrape.
- Configuration is read once at startup; there is no reload signal yet.

## Layout

```
src/main/      entry point: arguments, startup order, signals, maintenance loop
src/dns/       message codec: names, compression, records, EDNS, TTL patching
src/yaml/      YAML subset parser and typed accessors
src/config/    configuration schema, loading and validation
src/filter/    sink-list matching and list-format parsers
src/cache/     LRU answer cache
src/dnssec/    validation: canonical form, signatures, NSEC/NSEC3, chain of trust
src/upstream/  transports (UDP/TCP/DoT/DoH), pooling, strategies, HTTP/1.1 and h2 clients
src/server/    resolver, listeners, DoH endpoint, cookies, list refresh
src/h2/        HTTP/2 framing, HPACK, and the server connection state machine
src/tlsx/      OpenSSL bindings and a small TLS wrapper
src/pool/      worker pool
src/logx/      logging
src/privdrop/  giving up root once the listeners hold their ports
src/itest/     integration suite: harness, mock upstreams (DNS, HTTP, DoH/h2), clients, fixtures
bench/         benchmark harness and DNSSEC survey, in Go, with committed results
```

Two worker pools run underneath: one answering queries, one dedicated to racing
upstreams. They are kept separate on purpose — a race job is submitted *by* a
query handler and waited on by it, so sharing a pool could deadlock once every
worker was blocked on jobs nobody was left to run. TCP, DoT and DoH connections
get a thread each instead, capped by `server.max_connections`.

## Testing

Two layers, both run by `mise run verify`. A third, `mise run bench`, measures
rather than asserts: it is where every number in [Capacity](#capacity) comes
from, and it is documented in [`bench/README.md`](bench/README.md).

**Unit tests** (`mise run test`, 162 cases) cover the message codec — round trips
for every modelled RDATA type, compression, truncation, EDNS, pointer loops,
hostile record counts — plus the YAML parser, configuration loading, list
parsing and matching, the cache, and the HTTP/2 codec — the HPACK cases run the
worked examples from RFC 7541 appendix C, so the codec is checked against the
specification's own vectors rather than against itself.

They run per package, so a failure names one: `dns` 16, `yaml` 9, `config` 10,
`filter` 8, `privdrop` 9, `cache` 10, `dnssec` 37, `tlsx` 4, `upstream` 15,
`h2` 30, `server` 14. Much of `tlsx`, `upstream`, `h2` and `server` is what the
suite grew for the bugs recorded below — the HTTP reader's framing and body limits,
the TLS handshake retry, the HTTP/2 stream table under RST_STREAM, and the DoH
request parser read against an allocator that scribbles over what it releases.

The DNSSEC cases work the same way. `src/dnssec/fixtures_test.odin` holds real
signed traffic captured from a public resolver: the root and `com` signed with
RSA/SHA-256, `example.com` and `www.cloudflare.com` with ECDSA P-256,
`ed25519.nl` with Ed25519, a real NSEC denial from the root, a real NSEC3 denial
from `com`, and a real unsigned delegation. The validator walks those chains for
the whole distance, and the same fixtures are then tampered with — a flipped
address byte, a stripped signature, a corrupted DS digest, a trust anchor that
does not match, a clock a year later — and every one of them has to come back
bogus. Signatures expire, so the tests pin the moment they are judged against
rather than reading the clock.

Three of those cases exist to hold specific attacks down: a DNSKEY set signed by
a key sharing the attested key's tag, an injected RRSIG trying to name the zone a
denial is checked against, and a response built to make one question cost as many
upstream lookups as possible. Each was checked against the code as it stood
before the fix, so they are known to fail when the property they guard does.

**Integration tests** (`mise run itest`, 135 cases, ~25s) start the built binary
as a separate process against scripted mock upstreams, so what is exercised is
the artefact that ships rather than the library it was compiled from. The suite
is hermetic: no public resolver is contacted, ports are allocated from a private
range, and the certificate for the TLS cases is generated by the suite itself.

```
mise run itest              # summary
./bin/itest -v              # one line per case
./bin/itest --keep          # keep the working directory and server logs
./bin/itest --binary <path> # test a specific build
```

What it covers:

| area | cases |
|---|---|
| command line | `--version`, `--help`, `--check` accepting and rejecting configs, error text and line numbers, a DoT listener with no certificate, an unknown `server.user`, a privilege drop that cannot happen stopping the server, the shipped example config |
| shutdown | `SIGTERM` produces an orderly exit rather than a killed process |
| wire format | all 23 captured fixtures replayed and compared byte for byte, EDNS forwarding, 0x20 case preservation, truncation and the TC bit, FORMERR / NOTIMP / silent-drop handling |
| listeners | UDP, TCP (single and pipelined), DoT, DoH POST and GET, keep-alive, 404 / 405 / 415 / 400 |
| DoH over HTTP/2 | ALPN selection, POST and GET, Huffman-coded headers, CONTINUATION, concurrent streams proved parallel by timing, flow control with a tiny window, DATA splitting for a 27 KiB answer, PING, RST_STREAM, error statuses, HTTP/1.1 fallback |
| DoH upstreams | a query resolved over an h2 upstream, one connection multiplexed across queries rather than reopened, fallback to HTTP/1.1 when the upstream does not offer h2 |
| blocking | all five response modes, hosts vs domains vs adblock semantics, allow precedence, wildcards, modifiers, dnsmasq syntax, unusable rules, case folding |
| rewrites | A, AAAA, CNAME, wildcard scope, `block`, NODATA for unmatched types |
| cache | hits avoid the upstream, TTL countdown, cross-transport reuse, question re-casing, negative caching, key separation by type |
| upstreams | failover, round-robin, race, health cooldown, TCP and DoT clients, connection pooling, UDP→TCP retry, total outage → SERVFAIL |
| blocklist downloads | two lists fetched over HTTP and both applied, written to the cache directory, reused on restart without re-fetching, unwritable cache directory degrades to a warning |
| DNSSEC | an answer with no chain of trust is refused rather than served, the forwarded query carries DO and CD, a CD client is served unvalidated, the refusal carries an extended DNS error, and none of it happens unless it is configured |

`src/itest/fixtures.odin` holds real DNS responses captured from a public
resolver, including compression pointers, DNSSEC records and types the codec
does not model. The mock replays them verbatim and the suite compares the bytes
the client receives against the bytes the upstream sent. Generating the fixtures
with elodin's own encoder instead would let a codec bug agree with itself and
still pass.

**Against live DNS**, because neither layer can prove the absence of false
failures — both work from fixtures, so both can show that a forged answer is
refused and neither can show that validation leaves working names working. A
validator that refused everything would pass the entire suite.

`go run ./cmd/bench -survey 9.9.9.9:53` from `bench/` asks every name in
`bench/domains.txt` through elodin with validation on, asks a reference
validating resolver the same thing, and compares the rcode and the AD bit. The
run in `bench/results/2026-08-03-dnssec-survey.md` covers 129 names: no false
failure, all four deliberately broken zones (`dnssec-failed.org`,
`brokendnssec.net`, `sigfail.verteiltesysteme.net`, `rhybar.cz`) refused, and
the same verdict as the reference on 120 of the 125 that are meant to resolve.

The five that differ — `cmu.edu`, `comcast.net`, `pir.org`, `afilias.info` and
`kisa.or.kr` — come back served but without the AD bit, and every one of them is
signed with DNSSEC algorithm 5 or 7, RSA/SHA-1, which this machine's OpenSSL
refuses to compute under the Fedora crypto policy. That is the downgrade the
DNSSEC section describes, measured: a fact about the host rather than the zone,
and the safe direction to fail in.

### Bugs worth recording

Every one of these was invisible to the unit tests:

- **A response with no framing at all could take as much memory as the peer
  liked.** Four paths read a body — no content, chunked, `Content-Length`, and
  read-to-end — and the last was the one with no size limit on it, while the
  header scan stops at 64 KB and the other two check `MAX_HTTP_BODY`. Omitting
  both headers was the obvious way in; the other was a `Content-Length` that
  parses but cannot be a length, since `-1` slipped past the `== 0` and `> 0`
  cases and landed on the same unbounded reader, so the limit guarding the
  ordinary case sat inside a branch it never reached. The final copy doubles the
  peak. Reachable from blocklist downloads, which run at startup and on every
  refresh, and from a DoH upstream that ALPN resolved to HTTP/1.1.
- **A reset HTTP/2 stream nobody owned was never retired.** `RST_STREAM` marked
  a stream cancelled and left it in the table. Only `respond` retires a stream
  and it runs for dispatched streams alone, so one reset between its headers and
  a body that never came was held for the life of the connection — with its
  parked request and one of the `MAX_CONCURRENT` slots. Two frames per stream
  and a peer wedges the connection. Retiring unconditionally would break the
  other half, since `respond` reads `cancelled` off the stream to skip its
  answer; `Stream.dispatched` splits the two, so a reset closes what nobody was
  given and leaves the rest to `respond`.
- **A handshake the peer reset counted as a dead upstream.** Quad9 resets a
  share of TLS handshakes partway through while the very next attempt goes
  through — measured from one network at about 22% of fresh connections, of
  which a single retry rescued two thirds. Three in a row park the upstream for
  the cooldown, sending every query to the fallback for ten seconds. OpenSSL
  leaves its error queue empty for these, because nothing about the protocol
  went wrong — the socket died — so the log said only `Handshake_Failed: no
  OpenSSL error recorded`. `SSL_get_error` and `errno` are read at the point of
  failure now, which both names the cause and tells a reset apart from a timeout
  or a rejected certificate. Only the reset is retried: it comes back in a round
  trip, where a timeout has already spent the caller's budget and a bad
  certificate will not improve on a second look. A pause before the retry was
  measured and did not help, so there is none. DoT and every HTTPS upstream —
  HTTP/1.1, h2 and the bootstrap resolver — share the one path.
- **A malformed query was answered with someone else's transaction ID.**
  `error_response` picked its fallback on whether the encoder objected, and it
  never does: a query that failed to decode arrives as an empty message, and an
  empty message encodes perfectly well — into twelve bytes carrying ID zero. The
  header-patching path its own doc comment described was therefore unreachable,
  and every malformed datagram got a reply the client could not match to its
  question, so it waited out the full timeout instead of failing fast.
- **A parsed DoH request pointed into a buffer that could move.** The reader
  hands back views into the buffer it goes on appending to, and the method,
  path, query string and content type were kept as views while the headers and
  then the body were read. That they still read correctly was a property of the
  arena behind the scratch allocator, which carries the old contents forward —
  not of anything the reader did. A test that swaps in an allocator which
  scribbles over a released block reads `0xDD` out of every field.
- **The connection limit drifted once a listener loop was reaped.** The limit is
  `len(threads) - permanent`, and `permanent` only ever grew; reaping a finished
  loop took it off the list without touching the count, so the total goes
  negative and the limit stops holding for as many connections as there were
  loops.
- **An answer nobody checked still claimed to have been checked.** The AD bit
  was only ever touched on the path where validation had run, so with DNSSEC
  switched off — or for a client that set CD, which asks us to leave the
  checking alone — whatever the upstream put in that bit reached the client
  unaltered. It reads as *this resolver* authenticated the data, and on a plain
  UDP upstream that assertion is anyone's to make. It was cached with the answer
  too, so one client's forged AD was replayed to the next. Now settled on every
  path: narrowed to what the client asked about where we validated, cleared
  where we did not.
- **A UDP upstream could not receive a large answer.** The receive buffer was a
  fixed 4096 bytes, while the query forwarded to the upstream carries the
  *client's* EDNS0 payload size — up to 65535. A responder filling the room it
  was offered sent a datagram that would not fit, and Linux reports that rather
  than hiding it, so the answer came back as a failure. Three in a row parked a
  perfectly healthy upstream for the cooldown, which is how "one name does not
  resolve" turns into "this upstream is skipped for ten seconds". The buffer is
  sized from what the query actually advertised now, and a responder that
  overruns even that is retried over TCP the same way the TC bit is.
- **Shutdown released things that were still in use.** The read and accept loops
  freed their own context on the way out, but every job they had queued and
  every connection thread they had started holds that context and outlives them
  — and `pool.destroy` runs what is queued before it joins its workers, so those
  jobs ran against freed memory. The teardown order compounded it: the worker
  pools were deferred first, so they unwound last, and a draining query reached
  for a validator, filter set, cache and upstream group that had all already
  gone. The listeners now hand their contexts to `Listeners` and `main` drains
  the pools between stopping the listeners and releasing them. The loops also
  carry a poll timeout now, since closing a socket does not reliably wake a
  thread already blocked reading or accepting on it, and joining one that never
  returns would have hung the shutdown it was meant to complete. Latent rather
  than live: nothing clears `Server.running` and there is no signal handler, so
  the process has always been stopped by a signal and this path never ran.
- **A verifying TLS client checked the chain but not the name.** `SSL_set1_host`
  is what ties a certificate to the peer you meant to reach, and it was only
  called when a hostname was supplied. A `tls://` upstream written as an IP
  literal has none — config only fills the hostname in when the address is *not*
  an address — while `verify` defaults on, so `tls://1.1.1.1:853` accepted any
  certificate any trusted CA had ever issued, for any name. The whole point of
  DoT, undone by a configuration the README showed one line further up. Now
  refused at load with a message naming the three ways out, and refused again in
  `tlsx` so no caller can ask for it by accident.
- **A chunk size was narrowed before it was bounded.** `strconv.parse_u64_of_base`
  has no overflow check: it wraps and still reports success. A chunked HTTP
  response whose size read `FFFFFFFFFFFFFFFF` therefore parsed cleanly, turned
  negative on the way into `int`, passed a body-size guard written as
  `len(out) + int(size) > MAX`, and asked the reader for a slice ending before it
  started — with the cursor left negative for everything after it. The release
  build compiled bounds checks out at the time, so this was an out-of-bounds
  access at an offset the peer chose, reachable from any DoH upstream speaking
  HTTP/1.1 and from any blocklist served over plain HTTP. It is what decided the
  release build should keep its bounds checks.
- **An algorithm we could not check made a signed RRset unsigned.** Once a zone
  is established as secure, an RRset in it carrying only signatures we cannot
  verify was reported insecure rather than bogus — the verdict was returned
  before the code that asks whether the zone is signed at all. A zone using two
  algorithms publishes an RRSIG for each, so stripping the one we can verify and
  altering the records left an answer that reached the client as merely
  unvalidated. That is the correction in RFC 6840 section 5.11: an unknown
  algorithm makes a *delegation* insecure, at the DS, and nothing below it. An
  algorithm the linked OpenSSL declines to run — SHA-1 under the Fedora and RHEL
  crypto policy — is now a separate verdict, since that is a fact about the
  machine rather than the zone, and refusing it would make zones unresolvable on
  one host that resolve on another.
- **A key tag was treated as a key's identity.** Verifying a zone's DNSKEY set
  against its parent's DS, the code found the key the DS attested and then
  handed the whole key set to the signature check — which picks a key by tag and
  algorithm. A key tag is a 16-bit fold of the RDATA, not an identity, and
  nothing stops an attacker publishing a second key under a colliding one. Any
  zone could therefore have been detached from its parent: keep the real key
  present so the DS still matches, add one of your own with the same tag, sign
  the set with it. The verification now uses the attested key and no other.
  `src/dnssec/forged_test.odin` is a zone built to reproduce it — two Ed25519
  keys sharing a tag — and the test fails against the old code.
- **A denial of existence took its zone from the response.** NXDOMAIN and NODATA
  answers were validated against whichever zone the first RRSIG in the authority
  section named. There is no signature over an absent name to fall back on, so a
  wrong zone yields "nothing verified", which is indistinguishable from "this
  zone is unsigned" — one injected RRSIG naming any unsigned zone was enough to
  have a forged NXDOMAIN served as insecure. The zone is now established by
  walking down to the queried name.
- **One question could provoke unbounded upstream work.** Every distinct owner
  name in a response got its own chain walk, so a response full of them turned a
  single client query into hundreds of upstream lookups with a worker held for
  all of them. Walks now share a budget per query.

- **SIGPIPE killed the process.** A client hanging up mid-answer would take the
  whole server down. Now ignored, so the write reports `EPIPE` normally.
- **`verify: false` never worked.** The TLS client checked
  `SSL_get_verify_result` even with verification disabled, so every self-signed
  upstream was rejected after a successful handshake.
- **Use-after-free on the client label.** TCP, DoT and DoH connection handlers
  reset the scratch allocator after each query, freeing the client address
  string the log lines were still using.
- **Allocator mismatch in `tlsx`.** TLS contexts and connections were allocated
  from a caller-supplied allocator but freed with the default one.
- **Log output was buffered**, so lines surfaced long after the events and would
  be lost entirely if the process were killed. Each line is now flushed.
- **Flow-mapping values could not be collections**, so `{answers: [a, b]}`
  parsed as a literal string.
- **A dropped pooled connection was reported as an upstream failure.** Resolvers
  close connections a client has left idle, and the retry meant to cover that
  never dialled: it looked for another pooled connection, found none, and gave
  up. Every stale connection therefore cost a spurious failure, and three in a
  row parked a perfectly healthy upstream for the cooldown. Affected TCP, DoT
  and DoH alike.
- **Our own CD bit came back to the client.** Validation asks upstream with CD
  set so the upstream's verdict does not pre-empt ours; the answer echoes it,
  and forwarding that told every client its answer had gone unchecked — the
  opposite of what had happened. Found against live DNS, not by either suite.
- **The AD bit was cached for whoever asked first.** The bit was being set from
  the client's question rather than from the verdict, so an answer stored for a
  client that had not asked about DNSSEC came back without it for one that had,
  and the other way round. The verdict now goes into the cache and the bit is
  narrowed per client on the way out. Found the same way, one query later.
- **A heap-corrupting free in the blocklist download path.** `filepath.dir`
  returns a slice of its argument rather than a new string, and freeing it
  aborted the process with `free(): invalid pointer` partway through the second
  list. Found in the field rather than by the suite, because every other case
  runs with `--no-fetch`; the download path now has cases of its own.

Interoperability with a foreign HTTP/2 implementation is checked by hand with
curl (which uses nghttp2): `curl --http2 -k -H 'content-type:
application/dns-message' --data-binary @query.bin https://127.0.0.1:443/dns-query`.
