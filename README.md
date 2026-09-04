# elodin

A filtering DNS forwarder in [Odin](https://odin-lang.org), in the spirit of
Pi-hole and AdGuard Home, minus the web interface. One binary, one YAML file.

- Serves plain DNS (UDP + TCP), DNS-over-TLS and DNS-over-HTTPS (HTTP/2 and HTTP/1.1)
- Forwards to plain, TCP, DoT and DoH upstreams, by failover, round-robin or race
- Per-domain upstreams, so a zone your own network answers goes to the server
  that answers it and nowhere else
- Sink lists in hosts, plain-domain and adblock syntax, with allowlists, matched
  against an answer's CNAME chain as well as the question
- Answer cache with negative caching and optional stale serving
- DNSSEC validation against the root trust anchors, on by default
- Local rewrites (A, AAAA, CNAME, MX, TXT, SRV, or "answer as if blocked"),
  written as a zone file writes them, with the matching PTR synthesised
- The reserved names of RFC 6761/7686 answered here rather than forwarded
- Client allow list (local networks only by default), per-prefix response rate
  limiting, a ceiling on UDP answer size, DNS cookies in both directions, and
  EDNS(0) padding on DoT and DoH — all on by default
- DNS rebinding protection, off by default so split horizon keeps working
- A `.mobileconfig` profile that points Apple devices at the DoH endpoint
- A Prometheus endpoint, off by default
- Ships as a systemd service or a `.deb`, with optional system-resolver takeover

`examples/elodin.yaml` is the annotated configuration reference. The reasoning
behind each default lives in the source beside the code it governs —
`src/config/config.odin` for the settings, and the feature's own package for the
rest — so this file keeps to what an operator needs to run it.

## Build

- [mise](https://mise.jdx.dev) pins the toolchain (Odin, clang, and Go for the
  benchmark) and runs the tasks; `mise install` fetches them
- OpenSSL 3.x with headers (`openssl-devel` / `libssl-dev`) for DoT, DoH and the
  DNSSEC signature checks

Odin shells out to `clang` as its linker driver, so mise pins that too. The
pinned build defaults to conda's own sysroot, so the tasks pass `--sysroot=/
-B/usr/bin` (`ELODIN_LDFLAGS` in `mise.toml`) to send the linker back to the
system OpenSSL; drop the `clang` pin from `[tools]` and those flags become
unnecessary.

```sh
mise trust
mise run build            # bin/elodin, with debug info
mise run release          # bin/elodin, optimised
mise run test             # unit tests
mise run itest            # integration tests against the built binary
mise run leakcheck        # the same suite under AddressSanitizer
mise run verify           # check + test + itest
mise run check            # type-check with -vet -strict-style
mise run fuzz             # build the dns, h2 and yaml libFuzzer targets
mise run fuzz-regression  # replay the committed corpus through each of them
mise run certs            # self-signed certificate for local DoT/DoH testing
mise run bench            # throughput, latency, CPU and memory (see bench/README.md)
mise run deb              # a .deb from this checkout, into dist/
mise run clean            # remove bin/
```

## Running

```sh
mise run run                                            # port 5354, unprivileged
./bin/elodin --config examples/elodin.yaml              # the real thing
./bin/elodin --config examples/elodin.yaml --check      # validate and exit
./bin/elodin --config examples/elodin.yaml --no-fetch   # skip list downloads
```

`mise run run` uses `examples/dev.yaml`, which listens on 5354 and caches under
`.cache/` so it runs as an ordinary user. `examples/elodin.yaml` binds port 53
and caches under `/var/cache/elodin`. Give it the one privilege it needs rather
than starting it as root:

```sh
sudo setcap 'cap_net_bind_service=+ep' ./bin/elodin
```

Starting as root works too, but then set `server.user` — see
[Privileges](#privileges). If the port is already taken it is usually the system
resolver (`sudo systemctl stop systemd-resolved`); elodin says as much when a
bind fails. A cache directory it cannot write is a warning, not an error: the
lists still apply, they just have to be fetched again next start.

The listeners bind `0.0.0.0`, but only the local networks are served by default
— see [Who may ask](#who-may-ask). A minimal configuration:

```yaml
upstream:
  servers:
    - tls://1.1.1.1:853#cloudflare-dns.com
blocking:
  lists:
    - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
```

### As a service

`packaging/elodin.service` expects the binary at `/usr/local/bin/elodin` and the
configuration at `/etc/elodin/elodin.yaml`:

```sh
sudo install -m755 bin/elodin /usr/local/bin/elodin
sudo install -Dm644 examples/elodin.yaml /etc/elodin/elodin.yaml
sudo install -m644 packaging/elodin.service /etc/systemd/system/
sudo systemctl enable --now elodin
```

It binds :53 through `AmbientCapabilities=CAP_NET_BIND_SERVICE` rather than as
root, and runs under `DynamicUser=yes` with `ProtectSystem=strict`.
`Restart=on-failure` with `StartLimitBurst=5` retries a start that fails for a
reason that passes, and gives up in `failed` on one that does not — a port it
cannot have, a certificate it cannot read. `systemctl reset-failed elodin` clears
that.

A published GitHub release carries `linux-amd64` and `linux-arm64` tarballs and a
`.deb` for each, both built natively: elodin binds the system libssl, so
cross-compiling would mean carrying a sysroot per architecture.

### From a .deb

```sh
sudo apt install ./elodin_*_amd64.deb
```

The binary lands at `/usr/bin/elodin`, the unit at
`/usr/lib/systemd/system/elodin.service`, and the example configuration at
`/etc/elodin/elodin.yaml` as a conffile, so dpkg keeps your edits across
upgrades. `apt purge` removes the configuration, the blocklist cache and the
state directory.

The install asks one question, defaulting to yes:

> **Make elodin the system resolver?**

Yes stops, disables and **masks** systemd-resolved — masking too, since a later
systemd upgrade would otherwise switch it back on and take port 53 at the next
boot — replaces `/etc/resolv.conf` with a real file naming `127.0.0.1`, carrying
over any `search` domains, and starts elodin. elodin reaches its blocklists and
upstreams through `upstream.bootstrap`, so it does not depend on the resolver it
is replacing.

Nothing is disabled until `elodin --check` has passed, and if elodin then fails
to stay up the package puts systemd-resolved and the old `/etc/resolv.conf` back
and fails the install. Removing the package restores them the same way, at `apt
remove` rather than waiting for `apt purge`. `sudo dpkg-reconfigure elodin` asks
again; for unattended installs, preseed it:

```sh
echo 'elodin elodin/takeover-dns boolean true' | sudo debconf-set-selections
```

### Privileges

Binding a port below 1024 is the only privileged thing elodin does, and it is
over within a second of starting; everything after that is parsing input that
came off the network. Either of two arrangements keeps it from being root while
it does that.

**Never become root.** Grant the capability, as the systemd unit does, or
`setcap` as above and start as an ordinary user. Leave `server.user` empty —
there is nothing to drop.

**Start as root and put it down.** Name an account and elodin switches to it the
moment the listeners have their ports:

```yaml
server:
  user: elodin        # a name or a numeric uid
  group: elodin       # optional; defaults to the user's primary group
```

Supplementary groups go first, then the gid, then the uid — all three of real,
effective and saved — and the result is read back from the kernel before it is
reported. A drop that was configured and did not happen ends the process. A
misspelt account name fails `--check`; running as root with no `server.user`
logs a warning. `blocking.cache_dir` changes owner along with the process, since
a refresh hours later has to reopen it.

### Signals

`SIGTERM` and `SIGINT` stop the listeners and let the worker pools drain. Open
client connections are waited on, and an idle one is only noticed when its read
times out, so stopping can take up to `server.client_timeout` (ten seconds by
default). A second signal terminates immediately.

`SIGHUP` re-reads the DoT/DoH certificate and key from the paths already in the
configuration and switches the listeners over, with no restart and no dropped
connections: a session in progress keeps the certificate it handshook with. One
that fails to load is logged and left alone, and the listener keeps serving what
it had. Nothing else is reloaded this way — listener addresses, the upstream set
and blocking need a restart.

### Logs

Every line is [logfmt](https://brandur.org/logfmt), with the time and severity as
fields rather than a prefix a collector has to be taught to recognise:

```
ts=2026-08-07T09:12:33Z level=info msg=ready strategy=Round_Robin upstreams=2 cache=true blocking=true dnssec=true rebind=false
ts=2026-08-07T09:12:41Z level=info msg=query client=192.0.2.10:44188 proto=udp qtype=A qname=example.com outcome=forwarded detail=cloudflare-dot ms=11.7
ts=2026-08-07T09:12:44Z level=warn msg="list steven-black: unavailable, skipping it"
```

The lines something is expected to watch — `starting`, `sizing`, `ready`,
`stats`, `query` — keep the same `msg` from one line to the next and carry what
differs in fields beside it; everything else is one human sentence in `msg`. In
Loki that is `| logfmt` and nothing else:

```logql
{job="elodin"} | logfmt | msg="query" | outcome="blocked"
{job="elodin"} | logfmt | msg="stats" | unwrap cache_hits
```

Statistics go to the log every five minutes as `msg=stats`: `queries`,
`blocked`, `cached`, `forwarded`, `failed`, `dropped`, `refused`,
`conn_refused`, `conn_rate_limited`, `conn_failed`, `handshakes`, `limited`,
`truncated`, `secure`, `bogus`,
`rebind` and `special_use`, plus `cache_entries`, `cache_bytes`, `cache_hits`,
`cache_withheld`, `cache_misses`, `cache_stale` and `cache_evictions`.
`log.queries` adds one `msg=query` line per query. A query name is the one field
whose bytes a client chooses; it is escaped like any other value, so a name
holding a quote or a newline cannot forge a field of its own.

Repeated refusals — an unauthorised source, a truncation, a connection past the
limit, a rebinding refusal — are logged once at `warn`, naming the setting, and
at `debug` after that, so whoever is triggering them does not decide how much
this server writes to disk. The stats counters carry the rest.

## Configuration

### Upstreams

```yaml
upstream:
  strategy: failover               # failover | round_robin | race
  timeout: 5s
  attempts: 2
  max_idle: 8                      # pooled connections per upstream
  idle_timeout: 30s
  bootstrap: [1.1.1.1, 9.9.9.9]    # resolves upstream hostnames
  servers:
    - name: cloudflare-dot
      type: tls                    # udp | tcp | tls | https
      address: 1.1.1.1
      port: 853
      hostname: cloudflare-dns.com # SNI and certificate name
    - https://dns.google/dns-query
    - tcp://9.9.9.9
    - 192.168.1.1
  zones: []                        # per-domain routes; see below
```

| `strategy`    | behaviour                                                        |
|---------------|------------------------------------------------------------------|
| `failover`    | try servers in configured order until one answers                |
| `round_robin` | the same, but the starting position advances on every query      |
| `race`        | query every healthy server at once, take the first usable answer |

`race` multiplies upstream traffic by the number of servers.

`bootstrap` matters: elodin resolves upstream hostnames itself rather than
through the system resolver, since on a machine where elodin *is* the system
resolver the latter would come straight back to a server that has not started
listening yet.

An upstream that fails three times in a row is skipped for ten seconds; if every
upstream is in that state they are all tried anyway. A TLS handshake the peer
resets partway through is retried once first, since some public resolvers do that
to a fair share of fresh connections while the very next attempt goes through.
Only a reset is retried.

An `https` upstream picks between HTTP/2 and HTTP/1.1 with ALPN, preferring h2,
since some public resolvers answer HTTP/1.1 only. Concurrent queries against an
h2 upstream multiplex onto one connection; an HTTP/1.1 one uses the same pooled
connections TCP and DoT do. Which it speaks is discovered from its first
connection and not re-checked.

#### Per-domain upstreams

If something on your network answers for a zone of its own — a domain controller
for `corp.example`, a router that answers `home.arpa`, a lab server with an
internal `.test` — name that zone and where it goes, rather than choosing between
a public resolver that has never heard of it and an internal server asked to
recurse the whole Internet:

```yaml
upstream:
  servers: [1.1.1.1, 9.9.9.9]     # everything else
  zones:
    - domains: [corp.example]
      servers: [10.0.0.1]         # the domain controller
    - domains: [home.arpa]
      servers: [192.168.1.1]      # the router
```

This is dnsmasq's `server=/corp.example/10.0.0.1`, unbound's `forward-zone`,
blocky's `conditionalMapping` and AdGuard Home's `[/corp.example/]10.0.0.1`.

A route is a whole upstream in its own right, so it takes anything `upstream`
itself takes — `strategy`, `timeout`, `attempts`, `max_idle`, `idle_timeout`,
`bootstrap`, and servers in every form and transport, DoT and DoH included — and
inherits from the `upstream` block around it whatever it does not say:

```yaml
upstream:
  timeout: 3s
  servers: [1.1.1.1]
  zones:
    - domains: [corp.example, corp.internal]
      strategy: race
      servers:
        - name: dc1
          type: tls
          address: 10.0.0.1
          hostname: dc1.corp.example
        - 10.0.0.2
    - domains: [dev.corp.example]   # longest match wins for names under dev
      servers: [10.1.0.1]
```

`domains` matches on label boundaries and ignores case, so `corp.example` covers
itself and everything under it but not `notcorp.example`, and the longest
matching route wins — a sub-zone can be sent elsewhere without rewriting the
broader entry.

Two things follow from a route, both of which would otherwise have to be
configured separately and both of which break the deployment when forgotten:

- **The zone is not validated.** A local zone holds unsigned data under a public
  parent that delegates nothing to it, so walking the public chain for a name
  inside it finds a missing delegation and calls a good answer bogus. Routed
  names are served insecure, without the AD bit, exactly as the RFC 6303 private
  reverse zones are. A [`trust_anchors`](#dnssec) entry covering the zone stands
  that bypass down — read that as "the bypass is off" rather than "the zone now
  validates", since the chain walk descends by `DS` from the root and reaches an
  internal zone only if the public tree delegates to it. And `trust_anchors`
  *replaces* the built-in root keys rather than adding to them, so list the root
  DS alongside your own.
- **The zone may answer with private addresses.** A route says the zone is
  answered by a local authority, and answering with local addresses is what a
  local authority is for, so [rebind protection](#dns-rebinding-protection)
  exempts a routed zone without it also appearing in `rebind.allow_domains`.

What does *not* follow a route is the DNSSEC chain walk: the `DS` and `DNSKEY`
lookups elodin makes on its own account always go to `upstream.servers`, because
a server authoritative for `corp.example` answers `corp.example DS` out of its
own zone rather than fetching the signed proof from the parent, and that answer
breaks a chain instead of completing it.

A client's own `DS` query at a route's apex is kept off the route for the same
reason, and goes to whatever answers the parent zone — `upstream.servers`, or
the route covering the parent if there is one. It is the one question a routed
zone does not answer for itself: a validating client below elodin asks
`home.arpa DS` on its way down from `arpa`, and the router the route points at
replies out of its own zone with an unsigned "no data" instead of the signed
proof that lives in the parent, which the client reads as a broken chain and
turns into SERVFAIL for the whole zone. RFC 8375 section 4 item 4.B requires
that one query to be forwarded for exactly this reason. Names *below* the apex,
and the apex's own `DNSKEY`, stay on the route — those are the zone's own data.
That one query is also the only part of a routed zone the public upstream hears,
and it names no host: the zone's own name, which its parent already publishes if
the delegation exists.

The parent keeps that question only if it answers the thing it was asked for:
"no data", meaning the delegation exists and carries no DS. That is `home.arpa`'s
answer from `arpa`, and it is the only thing the parent can tell a validating
client that the local authority cannot. Anything else goes back on the route:

- **NXDOMAIN** — nothing in the public tree delegates the zone, the ordinary case
  being an internal `corp.example.com` under a public, signed `example.com`. There
  is no proof to fetch, and passing the NXDOMAIN on would be worse than the answer
  it replaced: an unsigned "no data" from the local server lets a lenient validator
  treat the zone as unsigned and resolve it, while a *signed* proof of
  non-existence takes that away — and a validator implementing RFC 8020 reads it as
  proof that every name under the apex is gone too.
- **A DS record** — the zone is delegated and signed in public and the route points
  at another view of it, which is split horizon. Handing the client the public DS
  makes it demand a `DNSKEY` the internal view has no matching key for, and it gets
  bogus instead of an answer. If you really are routing to a mirror of the signed
  zone, it is served insecure like any other routed zone; a
  [`trust_anchors`](#dnssec) entry over it is how you ask for it to be validated.
- **No answer at all** — a routed zone keeps standing on its own, so
  `upstream.servers` being down, or unreachable from the network the resolver sits
  on, does not take the chain out from under a zone whose own authority is
  answering.

"No data" is also what a parent says about a name that sits in its own zone
without being a delegation — `corp.example.com` published there as an A record,
or existing because `vpn.corp.example.com` is public. elodin does not tell that
apart from an insecure delegation (it would have to read the NS bit out of the
NSEC/NSEC3 bitmap), and passes the proof on either way. For that case the client
is right to act on it: the public tree does cover those names with signed data,
so the local server's unsigned answers below them are bogus, and the zone
resolved before only because the local NODATA hid the parent's proof. Anchor the
zone with [`trust_anchors`](#dnssec), or do not route a name the public tree
publishes.

A reply that says nothing about the name — SERVFAIL, REFUSED — counts as no
answer here rather than as an answer to pass on, which is a departure from how
every other rcode is handled: for a question about a *delegation*, only NOERROR
and NXDOMAIN say anything, so an upstream with an ACL, or a CPE resolver that
mangles every `DS` it meets, must not take an internal zone down with it. The
rest of that group is asked before the route is, so one server in
`upstream.servers` that refuses every `DS` does not hide a proof another one of
them is publishing. A NOERROR whose answer section carries something that is
not a DS is read the same way: "no data" means nothing in the answer at all,
and a resolver that hijacks NXDOMAIN answers this question with NOERROR and a
synthesised address, which is the first case above with the rcode written over.
And if the local server cannot be reached either, the answer is SERVFAIL rather
than whatever the parent said: a signed "this name does not exist" over a zone
that is served locally is the one answer worth withholding, since the client
caches it for the parent's whole negative TTL and a resolver implementing RFC
8020 reads it as covering every name under the apex. A SERVFAIL says what is
true — the delegation could not be established — and nothing keeps it, so the
zone comes back the moment its authority does. A parent whose upstreams are all
in their failure cooldown is not waited for at all; the question goes straight
to the route — so long as the route is out of its own cooldown, since skipping a
parent that may have come back for a server that is also down would only lose
the try that would have proved the delegation.

Where the parent said nothing — no reply, SERVFAIL, REFUSED, a NOERROR with the
wrong thing in it, or its group already in that cooldown — the route's answer
goes to the client and is not cached. It stood in for a fact nothing
established, and keeping it would hold the very broken chain this carve-out
exists to prevent over the zone for [`cache.negative_ttl`](#cache) after a
single lost round trip. The next query asks again. An answer the route gave
because the parent *did* say something — NXDOMAIN, or a DS record — is cached
like any other, that statement about the public tree holding until the public
tree changes.

The answer cache is keyed on the question rather than on which upstream produced
it, which holds because the routing table is built once at startup — restart
after changing a route. `--check` and the startup log say out loud what each
route gives up, one line per route, since nothing at load can tell an internal
zone from a public signed one.

A route into a zone [`special_use`](#reserved-names) already answers is refused
at load: those names are answered from the table before anything is forwarded,
so the route would sit in the file looking like the fix while every name went on
getting the table's NXDOMAIN. Turn the key off in the same edit.

> **Coming from dnsmasq:** `server=/corp.example/10.0.0.1` in `blocking.rules`
> does not route that zone — it *blocks* it, that form meaning a blackhole in the
> downloaded lists the parser was written for. In `blocking.allow` it is
> discarded entirely, which looks exactly like the route not working. `--check`
> warns about either written by hand. Routing lives under `upstream.zones` and
> nowhere else.

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
  # allow: ["||googleadservices.com^"]   # an exception outranks every list
```

| syntax                     | matches                          |
|----------------------------|----------------------------------|
| `0.0.0.0 ads.foo.com`      | `ads.foo.com` exactly            |
| `ads.foo.com`              | `ads.foo.com` and its subdomains |
| `\|\|ads.foo.com^`         | `ads.foo.com` and its subdomains |
| `\|ads.foo.com`            | `ads.foo.com` exactly            |
| `*.foo.com`                | subdomains of `foo.com` only     |
| `address=/foo.com/0.0.0.0` | `foo.com` and its subdomains     |
| `@@\|\|safe.foo.com^`      | never blocked                    |

Hosts entries are exact because hosts-format lists spell out every subdomain they
mean; bare domains and `||` rules cover subtrees, which is how AdGuard Home reads
the same files. Allow rules always win. The `address=/…/` and `server=/…/` forms
are dnsmasq's, accepted because they turn up in lists that are otherwise adblock
syntax; a `$` modifier is dropped and the rest of the rule kept, and a rule that
cannot be expressed as a domain is skipped rather than failing its list.
Downloaded lists are cached under `cache_dir`, and a refresh that fails falls
back to the cached copy, so a network outage cannot silently turn blocking off.

**CNAME chains are matched too** — Pi-hole calls it deep CNAME inspection. The
arrangement to catch is a tracker given a subdomain inside the site's own zone,
`metrics.brand.example` CNAME `tracker.evil.example`, where the question is a
first-party name no list can usefully carry. Every hop is matched, up to sixteen,
logged as `outcome=blocked detail=cname` against `detail=list` for a question
that was listed itself; an answer whose chain runs past the sixteenth name is
withheld rather than served. An allow rule on the *question* exempts the whole
answer — the escape hatch when a first-party name resolves through a listed CDN —
while one matching a hop clears that hop and no other.

Four details name a withheld or failed answer that no list explains, and they are
what to search the query log for when a site breaks and the lists do not account
for it:

| detail | rcode | what happened |
| --- | --- | --- |
| `cname-deep` | the `blocking.response` | the chain ran past the sixteenth name, so where it ends was never checked |
| `cname-unreadable` | SERVFAIL | a CNAME's target could not be parsed |
| `answer-unreadable` | SERVFAIL | the upstream's reply could not be parsed at all |
| `cache-unreadable` | SERVFAIL | a stored answer could not be parsed on the way back out |

The `-unreadable` ones answer SERVFAIL rather than `blocking.response`, since a
record that will not parse is as likely an upstream having a bad day as an
attack, and SERVFAIL is the only answer a stub will retry or fail over from.
`answer-unreadable` is the one worth watching: it is a way for a name to stop
resolving that appears only once blocking is on, since with blocking off nothing
walks the answer and nothing needs to parse it.

### Cache

```yaml
cache:
  enabled: true
  max_entries: 10000
  max_bytes: 64MiB       # a count of entries is not a bound on memory
  min_ttl: 0
  max_ttl: 24h
  negative_ttl: 300      # cap for NXDOMAIN / NODATA (RFC 2308)
  serve_stale: false     # answer from an expired entry if the upstream is down
```

Answers are stored as untouched wire bytes plus the offsets of their TTL fields,
and those TTLs are rewritten in place on each hit, so name compression stays
intact and there is no decode/encode round trip on the hot path.

Both bounds are needed, because an entry's size is decided by whoever answered
the query — the response as it arrived, up to 64 KiB over a stream transport,
plus an offset and a TTL per record. Eviction is from the least recently used end
whenever either bound is passed, and `cache_bytes=` in the stats line reports
what is held.

`max_ttl` caps every answer passed on from an upstream, forwarded or cached, as
well as how long the entry is kept; it does not touch the answers elodin writes
itself, which carry `blocking.block_ttl` or a rewrite's own `ttl`. `min_ttl` is a
floor on the copies served from an entry. Neither is a promise that a client
drops a record when this cache does: an entry lives for the smallest TTL in the
message it holds, a negative one for the SOA's figure capped by `negative_ttl`,
while every record still goes out carrying its own TTL up to the ceiling. A TTL
with its top bit set is taken as zero per RFC 2181 section 8, forwarded answers
included, which leaves it uncacheable unless `min_ttl` raises it.

### DNS-over-HTTPS

```yaml
listeners:
  doh:
    enabled: true
    address: "0.0.0.0"
    port: 443
    path: /dns-query
    cert_file: /etc/elodin/cert.pem
    key_file: /etc/elodin/key.pem
    mobileconfig_path: /apple-doh.mobileconfig
```

The endpoint serves HTTP/2 and HTTP/1.1 and picks between them with ALPN,
preferring h2. That matters because Firefox and Chrome will only use a DoH
resolver over HTTP/2, while curl, `dnscrypt-proxy` and HTTP/1.1 routers keep
working unchanged; a client offering neither gets a clean handshake failure.
Both request forms of RFC 8484 are accepted on either version: `POST` with an
`application/dns-message` body, and `GET` with a base64url `dns` parameter.
Requests on one HTTP/2 connection are answered on the query worker pool rather
than one after another on the connection's reader thread, so the A and AAAA
lookups a browser issues for the same name run at the same time.

`src/h2/` covers the preface and SETTINGS exchange, HPACK with Huffman decoding
and a full dynamic table, HEADERS with CONTINUATION, DATA, connection- and
stream-level flow control, WINDOW_UPDATE, PING, RST_STREAM and GOAWAY. Server
push is refused and stream priority parsed and ignored, which RFC 9113 permits.
What one connection may make this end hold is stated in the SETTINGS frame rather
than left to be discovered: 128 concurrent streams, a 32 KiB header list, a
4096-byte HPACK table — also the ceiling on a peer's table size updates — and at
most 128 CONTINUATION frames per header block, since a block bounded only by its
size never ends if the frames carrying it are empty.

A decoded header list is checked against RFC 9113 sections 8.2 and 8.3 before it
becomes a request, and anything malformed there is a stream error of type
PROTOCOL_ERROR. A conformant `CONNECT` is the one shape that looks malformed by
those rules and is not, so it draws a 404 rather than a stream error. The
HTTP/1.1 side refuses the same shapes.

#### Apple devices (iOS, iPadOS, macOS)

Encrypted DNS on iOS 14 / macOS 11 and later is configured with a profile rather
than an app, and the DoH listener serves one: browse to `mobileconfig_path` on
the device and it downloads a `.mobileconfig` that, installed under **Settings →
General → VPN & Device Management**, sends the device's DNS here over HTTPS
system-wide.

The `ServerURL` inside is built from the host the request arrived on, so it always
matches the name the certificate is for, and a listener answering on several
names hands each device a profile for the one it used. Its identifiers derive
from the URL, so reinstalling replaces the profile rather than stacking a
duplicate. The profile is unsigned, so the device shows it as *Unverified*. Set
`mobileconfig_path: ""` to withhold it; it is served only while DoH is enabled.

### DNSSEC

```yaml
dnssec:
  enabled: true
  max_nsec3_iterations: 100
  trust_anchors: []      # empty uses the built-in root keys
```

elodin checks the signatures on the answers it forwards instead of taking the
upstream's word for them. An answer that does not check out becomes SERVFAIL and
never reaches the client; one that does gets the AD bit; a name in an unsigned
zone is served normally, because unsigned is not the same as forged. Turning it
off is for an upstream that cannot be trusted to return DNSSEC records — an ISP
or captive-portal resolver — against which every signed zone would otherwise stop
resolving rather than merely going unverified.

Being a forwarder rather than a recursor, elodin fetches the material it
validates against: every DS and DNSKEY down from the root, through the configured
upstreams, with DO and CD set. Zone keys are cached, so the cost falls on the
first query into a zone and not the ones after it.

| | |
|---|---|
| chain of trust | root → TLD → zone, DS against DNSKEY at every step |
| algorithms | RSA/SHA-1, RSA/SHA-256, RSA/SHA-512, ECDSA P-256 and P-384, Ed25519, Ed448 |
| DS digests | SHA-1, SHA-256, SHA-384 |
| denial of existence | NSEC and NSEC3, including closest-encloser proofs and opt-out |
| wildcards | a wildcard answer must come with a proof that the name had nothing of its own |
| unsigned zones | insecure: served, no AD bit |
| bounds | 32 DS/DNSKEY lookups and 64 signature checks per question, 24 labels of chain, 8 signatures per RRset, 64 keys per zone, 8 hint targets per answer, 100 NSEC3 iterations |
| an algorithm we cannot check | insecure, not bogus — RFC 4035 treats unverifiable data as unsigned |
| bad signature, broken chain, missing proof | SERVFAIL, with an extended DNS error (RFC 8914) saying which |

A refusal reaches the log as a warning carrying the verdict, the reason and the
server the answer came from, with `outcome=failed detail=dnssec:<upstream>` on
the query line beside it:

```
ts=2026-08-07T09:12:52Z level=warn msg="dnssec: A xc.example.com from 192.0.2.10:44188 did not validate: Bogus (denial of existence not proven); answer came from quad9-dot"
ts=2026-08-07T09:12:52Z level=info msg=query client=192.0.2.10:44188 proto=udp qtype=A qname=xc.example.com outcome=failed detail=dnssec:quad9-dot ms=126.5
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

- The RFC 6303 locally-served reverse zones — the RFC 1918 ranges, IPv4
  link-local and loopback, IPv6 unique-local and link-local. Nobody signs them,
  so validating would turn every LAN PTR lookup into SERVFAIL. Unbound and BIND
  ship the same default. A `trust_anchors` entry covering one turns validation
  back on for it.
- Zones routed under [`upstream.zones`](#per-domain-upstreams), which hold
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
  [`upstream.zones`](#per-domain-upstreams) pointed at it, and if nothing serves
  the zone at all, [`special_use.home_arpa`](#reserved-names) answers those names
  here. Either way the `home.arpa DS` query itself goes to `upstream.servers` —
  not down the route, and not answered from the reserved-name table — RFC 8375
  requiring that proof be fetched rather than invented. If you do run the zone,
  its private addresses trip [rebind
  protection](#dns-rebinding-protection) unless it is routed or named in
  `rebind.allow_domains`.
- `.onion`, whenever it is forwarded at all, since the root publishes a signed
  proof that there is no `onion.` to delegate and a Tor-aware upstream's answer
  therefore reads as forgery. Both `special_use.onion: false` and
  `special_use.enabled: false` forward those names and stand validation down for
  them; see [Reserved names](#reserved-names).

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
  and 7. elodin treats an algorithm it cannot check as unsigned rather than as
  broken, so those zones come back without the AD bit instead of failing — the
  safe direction, but a silent downgrade.
- **NS records in the authority section of a positive answer are not required to
  be signed**, a forwarder being unable to tell the parent's copy of a delegation
  from the child's. The answer section is validated in full; this affects only
  what rides alongside it.

### Who may ask

```yaml
server:
  allow_from:                     # the default, shown in full
    - 127.0.0.0/8
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16
    - 169.254.0.0/16
    - ::1/128
    - fc00::/7
    - fe80::/10
```

The listeners bind `0.0.0.0`, so on a machine with a public address elodin is
reachable from the internet; what keeps it from being an *open* resolver is this
list. BIND's `allow-recursion` and Unbound's `access-control` exist for the same
reason. It is a different bound from [rate limiting](#rate-limiting), not a
weaker version: the rate limiter caps what one victim can be made to receive, and
this is the half that keeps this server out of the attack aimed there.

The check runs before the message is parsed, before the rate limiter and before
the query is queued, so a source not on the list costs a prefix compare and
nothing else. Over UDP the datagram is dropped, a REFUSED to a datagram source
being a reflection of its own; over TCP, DoT and DoH the connection is closed on
accept, without a thread and without a TLS handshake, so the allow list cannot
become a way to exhaust `max_connections`. Refusals are counted as `refused=` — a
datagram each on UDP, a connection each on the stream transports.

A list in the file replaces the default rather than adding to it, so include
loopback if you want it. Entries are CIDR networks in either family; a bare
address is the single host it names, host bits below the length are masked off,
and a v4-mapped entry (`::ffff:192.168.0.0/112`) is the IPv4 network it names,
since that is how a mapped client on an IPv6 socket is compared. An entry that
will not parse fails `--check`. Carrier-grade NAT (`100.64.0.0/10`, which
Tailscale also uses) is deliberately not in the default: a resolver behind one
would be serving an ISP's other customers.

An empty list is no restriction, which is how you ask for a public resolver.
elodin warns about it at every start; before running one, read [rate
limiting](#rate-limiting) and consider `cookies.require`.

```yaml
server:
  allow_from: []
```

Note the `[]`. `allow_from:` with nothing after it is a YAML null and a
configuration error, since the two things it could have meant are the shipped
default and its exact opposite.

#### Recursion only when asked

`allow_from` decides who may ask; the RD bit decides what they are asking for.
RFC 1035 section 4.1.1 makes RD the client's request for a recursive lookup, and
elodin only forwards to an upstream when it is set. A query with RD=0 gets
whatever is already cached and nothing more — REFUSED, not a silent drop, so a
client that meant to ask recursively finds out rather than timing out. It shows
as `outcome=refused detail=rd` in the query log and does not add to `refused=`,
which counts sources turned away before a query exists at all. The refusal still
carries RA=1, which RFC 1035 makes a statement that the server supports recursive
service rather than that this query used it — the same thing BIND and Unbound do.

### How large a UDP answer may be

```yaml
server:
  max_udp_response: 1232          # 512–4096; the DNS Flag Day 2020 figure
```

A client says in its OPT record how large a response it can take, and a resolver
that simply believes it has handed the caller its own amplification factor: the
query arrives on a datagram nobody verified, so an attacker aiming answers at a
victim advertises the largest buffer it can. `max_udp_response` caps that number,
and it is what the per-prefix datagram budget under [rate
limiting](#rate-limiting) is denominated in.

The cost is a TC bit and a retry over TCP on any answer between the ceiling and
what the client asked for; against real traffic that is close to nothing, and the
headroom it removes is only reachable by a zone built to fill it. Raise it, up to
4096, on a network whose path MTU is known to carry large datagrams and where the
resolver is not reachable by anyone who would abuse it. A truncation the setting
caused is logged once at `warn` naming it; a client that asked for *less* than the
ceiling got what it asked for and nothing is said.

The ceiling is also the number the answer's own OPT record reports, RFC 6891
section 6.2.4 making that field the *responder's* maximum rather than a copy of
the requestor's — the counterpart to `max-udp-size` in BIND and Unbound. Coming
from Unbound, note that this is one knob where Unbound has two:
`edns-buffer-size` advertises and `max-udp-size` truncates; `max_udp_response` is
both.

It is UDP only: the stream transports prove the address by handshake, so there is
nothing to reflect and the OPT record goes back as the answer carried it. That
does mean a truncated answer needs somewhere to go — with `listeners.tcp` off, a
client told to retry has nowhere to retry to. Leave TCP on, or raise the ceiling.

### Rate limiting

```yaml
server:
  rate_limit:
    enabled: true                 # on by default
    responses_per_second: 500     # per client prefix (/24 or /64), and per budget: datagrams, queries on a connection, connections opened
    slip: 2                       # answer at most every 2nd query over the budget truncated; 0 drops them all
```

A UDP query carries no proof of where it came from, so the answer goes wherever
the source address said — which is what makes any resolver an amplifier. How
large one datagram can be is capped by
[`max_udp_response`](#how-large-a-udp-answer-may-be); this is the cap on how many
of them.

The budget is on what this server will send *to one place*, not on how fast one
sender asks: with a spoofed address there is nothing of the sender's to measure.
So it is kept per destination prefix, /24 and /64, the granularity an attacker
picks addresses within, in a fixed table allocated once so the limiter is not
itself somewhere to put pressure.

Over-budget queries are not simply dropped. At most every `slip`th one comes back
as a header and a question with the TC bit set: too small to be worth reflecting,
and the standard way of telling a client to ask again over TCP where the
handshake proves the address. A client behind a busy NAT keeps resolving, one
round trip slower; a spoofed source cannot follow it up. `slip: 0` drops them
instead.

Those truncated answers are charged to a budget of their own — **an eighth of
`responses_per_second` per prefix**, so at the default, 62 a second — which makes
`slip` "at most one in N" rather than "one in N of whatever arrives". It has to be
a budget, because before it was one their number was a fixed fraction of the attack
with no ceiling in it: a flood of two million datagrams a second had this server
send half a million truncated answers a second, 19 MB/s, at the address the flood
named, where the same configuration's 500 responses/s implies 0.58 MB/s. Byte for
byte the attacker loses on that exchange, so it is not amplification — what it is
is this server made a source of traffic proportional to somebody else's attack, and
half a million writes a second taken from the one thread reading the UDP socket,
which cost a bystander in an unrelated prefix 44 points of its answer rate. An
eighth and not the whole figure because a truncated answer is an invitation rather
than an answer: a client that acts on one moves to a connection, whose budget a
datagram flood cannot reach, so it needs far fewer of them than it would need
answers. `bench/results/2026-09-03-rate-limit-bystander.md` is where the uncharged
figures were measured and `2026-09-03-slip-budget.md` is the same arms with the
budget in place: 0.54 MB/s at the named address, and the uninvolved bystander back
to 99%.

The cost is that the invitation is worth less to a client inside a flooded prefix:
62 a second spread over the flood's own datagrams, rather than every second
datagram in the bucket. That holds up at the rates a busy NAT produces — a prefix
asking twice its budget has a few hundred over-limit datagrams a second to spread
them across, and one invitation that lands moves that client onto a connection for
good — and not against millions a second, where the client is left with the stream
budget and nothing pointing it there. `src/server/ratelimit.odin` argues the trade
out.

TCP, DoT and DoH are charged too, for the work behind an answer rather than for
amplification — without that, a flood down a handful of long-lived connections is
one the limiter never sees. **Three budgets per prefix, though, not one:**
datagrams charge one, queries read off a connection charge another, and opening a
connection charges a third — each getting the whole of `responses_per_second`, and
none of them spendable from another's side, since a spoofed UDP flood naming a
prefix would otherwise close the connections of the clients who actually live
there, or stop them opening one. The cost is that a client using every way in can
draw three times the figure, two thirds of it only over a completed handshake from
an address that is therefore real. `src/server/ratelimit.odin` argues this out.

**Opening a connection is charged because arriving is the expensive part.** A
client that dials, completes a TLS handshake and hangs up asks nothing, so no
budget of *answers* ever saw it, and it holds each connection too briefly for
[`max_connections_per_prefix`](#how-many-connections-one-client-may-hold) to
notice — 32 such dialers drew 6,032 handshakes a second and 1.25 of four cores
while `conn_refused` and `elodin_rate_limited_total` both read zero, and took 16
points of answer rate and four times the latency from a DoT client in an unrelated
prefix. With the budget the same load gets 462 handshakes a second and costs 0.29
of a core, and that bystander loses 10 points instead of 16.
`bench/results/2026-09-04-handshake-budget.md` is the before and after;
`2026-09-03-handshake-floods.md` is where the load is described.

The whole figure rather than a fraction of it, because a connection is the vehicle
for a query: `dig +tcp`, a `curl` per lookup and every stub that does not keep a
connection open spend one connection per answer, so a prefix entitled to 500
queries over connections has to be able to open 500. A smaller connection budget
would be a quiet reduction of the query budget for exactly the clients that
reconnect.

**So `responses_per_second` is now three bounds, and one of them has a burst to
size.** A prefix banks two seconds of each budget, so it can open
`2 × responses_per_second` connections at once — 1000 at the default — and then
`responses_per_second` a second. Answers arrive spread out and connections do not:
the moment that tests this is every device on a network reconnecting together,
after this resolver restarts or after a link comes back. That burst is bounded by
how many devices share a prefix, so at the default it is not a figure any real
network reaches. An operator who has tuned `responses_per_second` far *below* the
default should check it against that number rather than against their query rate —
`client_timeout` reclaiming an idle connection every 10 seconds is also what sets
the steady arrival rate, at roughly one device in ten per second.

Refusals are counted as `conn_rate_limited=` in the stats line and
`elodin_connections_rate_limited_total` on the endpoint, apart from
`conn_refused=`, which is the connection *table* being full — arrival and occupancy
are different problems with different settings behind them. Completed handshakes
are `handshakes=` and `elodin_tls_handshakes_total`, which is the first counter
here that says anything about what getting clients in the door costs.

What it does not do is stop a botnet, and it does not bring that bystander back to
its quiet baseline: refusing at the accept is cheap but not free, and a peer whose
dials cost it nothing simply dials four times faster. **A publicly reachable
instance wants a per-source connection rate limit in front of it** — see
[below](#a-connection-rate-limit-in-front).

`slip` is a UDP mechanism, so over-budget queries on a connection are refused
instead: TCP and DoT closed, and over DoH — both HTTP/1.1 and HTTP/2 — answered
`429 Too Many Requests` on a connection that stays open unless the client itself
asked for a close. It stays because ending it charges this server a TLS handshake
per refusal and the flooding client nothing, which made refusing dearer than
answering. A connection that is closed with bytes still unread is drained briefly
first, since closing a socket with unread data resets it and the client's kernel
would throw away the answers already sent.

The budget is spent on questions, on every transport: a scanner's 404, a
`.mobileconfig` download or a POST naming the wrong content type reaches no
resolver, cache or upstream. Refusals are not charged either, the budget being
per /24 — charging a denied source would turn a narrowed allow list into a way to
have the clients beside it dropped.

`elodin_rate_limited_total` counts what was withheld;
`elodin_rate_limit_slipped_total` counts truncated answers, so it only ever moves
for UDP. `cookies.require` is the sharper instrument for an attack actually under
way.

What none of this bounds is how much of the server one client *occupies*. Every
budget here is a rate — arriving, and asking — and a client that stays inside them
can still hold every connection it was given for as long as it likes. That is the
next section.

### How many connections one client may hold

```yaml
server:
  max_connections: 512            # TCP, DoT and DoH connections at once, for the whole server
  max_connections_per_prefix: 0   # how many of them one client may hold; 0 derives half
```

`max_connections` is one budget for the whole server, and on its own it says
nothing about how it is shared. Nothing else bounds how long a client keeps what
it was given either — [rate limiting](#rate-limiting) charges opening a connection
and charges the queries asked over it, and both are rates a client can stay inside
while letting go of nothing, while `client_timeout` reclaiming an idle one after
ten seconds is a delay rather than a limit to somebody willing to open another. So
the answer to "how many of my 512 connections can one stranger have" was "all of
them".

The two bounds need each other. A share does not bound arrivals: a flood that
holds each connection only for the length of a handshake never reaches 256 out of
512, which is what the measurement in the previous section is about. An arrival
budget does not bound occupancy: a client opening one connection a second and
closing none fills any table inside any rate.

`max_connections_per_prefix` is the share. It is counted against established
connections, per /24 and per /64 — the same unit the response budget uses, so
the two agree about who a client is — and a connection past a client's share is
closed on accept and counted as `conn_refused=`, like one past the table itself.
The log line under it names which of the two figures refused it, because raising
the wrong one makes the other worse.

`0` derives half of `max_connections`, so the default table of 512 gives any one
prefix 256. Anything at or above `max_connections` is no cap at all — one client
may hold the whole table, which is what elodin did before this setting existed
and what an operator serving a single large NAT should ask for on purpose. Both
figures are in the log at startup, and in
`elodin_connections_max` / `elodin_connections_max_per_prefix`.

**On a private network, note what a prefix is.** Every device on
`192.168.1.0/24` is one client to this setting, sharing 256 connections between
them; a resolver serving more devices than half its table wants the share raised,
or `max_connections` raised underneath it. Half is chosen to be a bound nobody
trips over rather than a tight one: it guarantees that no single client can lock
the rest out, and asks nothing of an operator who has not read this.

On a public instance, consider going much lower. A real client holds one
connection per device and reuses it, so a share in the low tens is generous for
anybody legitimate and leaves a stranger holding a fortieth of the table instead
of half of it.

Note that what it bounds is a *prefix* rather than an actor, and the two are
furthest apart on IPv6: a /48 is 65,536 /64s and a routine allocation from a
hosting provider or a tunnel broker, so a stranger who has one can take a share
from each and fill the table out of as many prefixes as that takes. Two of them
are enough against the default 256. The share is what makes that expensive
rather than impossible — at 16, a table of 512 costs 32 prefixes instead of two
— and it is the same granularity, with the same limitation, as the response
budget above.

UDP is unaffected either way — no connections, no per-client state, nothing to
refuse — which is why a resolver whose table has been taken can look healthy on
datagrams while every TCP, DoT and DoH client gets nothing.
`bench/results/2026-09-03-connection-table-share.md` measures that, and the same
load with a share in place.

### A connection rate limit in front

If this resolver is reachable from the internet, put a per-source limit on *new
connections* in front of it — in nftables or iptables on the same host, or in
whatever terminates TLS if something else does. Not instead of the two bounds
above; as well as them.

The reason is arithmetic. Everything elodin bounds, it bounds per /24 and per /64,
because that is the granularity an attacker picks addresses within. An actor with
addresses in *n* prefixes therefore has *n* copies of every figure here, and on
IPv6 a routine allocation from a hosting provider or a tunnel broker is a /48 —
65,536 /64s. And a refusal, though far cheaper than the handshake it refuses, is
not free: with the arrival budget in place a flood of 32 dialers went from 6,032
handshakes a second to 462, and from 1.25 of four cores to 0.29, but its *dial*
rate rose from 6,032 to 25,129 a second because being refused had become cheap.
The DoT bystander in that run went from 82% of its queries answered to 88%, where
the quiet baseline is 98%. A packet filter is the only place that stops a peer
from making this server refuse it.

```
# nftables: at most 10 new DNS connections a second per /24 and per /64,
# bursting to 40. Keyed on the same prefixes elodin keys its own budgets on.
table inet filter {
  set conn_rate4 {
    type ipv4_addr
    flags dynamic, timeout
    size 65535
    timeout 1m
  }
  set conn_rate6 {
    type ipv6_addr
    flags dynamic, timeout
    size 65535
    timeout 1m
  }
  chain input {
    type filter hook input priority filter
    tcp dport { 53, 443, 853 } ct state new meta nfproto ipv4 \
      add @conn_rate4 { ip saddr and 255.255.255.0 limit rate over 10/second burst 40 packets } \
      counter drop
    tcp dport { 53, 443, 853 } ct state new meta nfproto ipv6 \
      add @conn_rate6 { ip6 saddr and ffff:ffff:ffff:ffff:: limit rate over 10/second burst 40 packets } \
      counter drop
  }
}
```

Trim the port list to the listeners you actually expose — 853 for DoT, 443 for
DoH, 53 for TCP — and check it with `nft --check --file` before loading it, since
a rule in the `input` hook that is wrong about its ports can lock you out of the
host.

Size it above what your clients do and below what a flood does: a stub resolver
opens one connection and keeps it, and even a large NAT reconnecting every device
at once is a burst rather than a rate. Ten a second per prefix is generous for
anything legitimate and two to three orders of magnitude under what a single host
can offer. On a private network, remember that every device on `192.168.1.0/24` is
one source to a rule like this, exactly as it is one client to
`responses_per_second` — size the burst for the whole LAN, or leave this to the
in-server budget, which is what a resolver that is not reachable from outside
wants anyway.

The figures behind this are in `bench/results/2026-09-04-handshake-budget.md` and
`2026-09-03-handshake-floods.md`; `2026-09-03-udp-readers.md` reaches the same
conclusion about datagram floods, where the equivalent advice is
[`listeners.udp.readers`](#how-fast-datagrams-can-be-read) plus a filter.

### How fast datagrams can be read

```yaml
listeners:
  udp:
    readers: 0                # threads reading the socket; 0 derives one per usable CPU, to 8
    receive_buffer: 1MiB      # what each reader asks the kernel to hold for it
```

Everything a datagram costs before the rate limiter can see it — the `recvfrom`,
the [allow-list](#who-may-ask) compare, the siphash of the source prefix —
happens on the thread that read it. So the rate at which this server can *hear*
is the ceiling on every fairness property below it: past what its readers can
drain, the kernel's receive queue overflows and datagrams are dropped by the
socket, which is to say by nobody the configuration can reach. The client whose
queries are lost there is whichever one the queue happened to be full for.

Measured on a four-core aarch64 VM
(`bench/results/2026-09-03-udp-readers.md`): **one reader drains 2.3 million
datagrams a second**, or about 400 ns of one core each, and under a flood of two
million a second the kernel still dropped **4% of arrivals** — 918,000 datagrams
in ten seconds that reached no budget, no counter and no client. Read that as the
ceiling rather than as a disaster: the [rate limiter](#rate-limiting) held the
flood at its budget throughout and a client in an unrelated /24 was answered 98%
of the time.

The 36% that client lost when
[issue #233](https://github.com/jadolg/elodin/issues/233) was filed is gone, and
was mostly not the reader's doing: the slip's truncated answers were charged to
no budget then, so the read loop was also performing half a million sends a
second.
Giving them a pool of their own fixed that (`2026-09-03-slip-budget.md`), and
what is left is the drain rate itself.

Each reader binds the same address and port with `SO_REUSEPORT` and gets its own
receive queue, and the kernel spreads arriving datagrams between them by hashing
the 4-tuple. The drain rate then scales with cores instead of being one of them,
which is how BIND and Unbound scale the same path. Unset derives one reader per
usable CPU up to eight — the same "what can this machine have" reading as the
[worker counts](#sizing) — and the number, with what the kernel actually granted
for a receive buffer, is in the startup line and in `--check`:

**The scaling is the mechanism's, not a measurement of this one.** The bench
above could not demonstrate a speed-up from a second reader, because the load
generator shares the machine with the server it is measuring and loopback
delivery is paid for by the sender: a second box, or a real NIC, is what would
answer it. One reader already drains more than this VM can offer, so what the
extra readers buy here is headroom above a ceiling nothing available could reach
— and `elodin_udp_receive_drops_total` is how an operator finds out whether their
own instance is anywhere near it.

```console
$ elodin --check
  udp: 4 readers, asking for 1MiB of receive buffer each (derived from 4 usable CPUs)
```

Sharing a port is bounded by the kernel to processes running as the same
effective user: elodin binds before it [drops privileges](#privileges), so a
second process would have to be root — or, on an unprivileged high port, whoever
elodin already runs as — to take a share of the datagrams. That is somebody who
could read the traffic off the interface in any case, which is why this is worth
saying rather than worth worrying about. A *second elodin* is the one thing that
would qualify and must not be let in — a stale process, a unit started twice, a
configuration being tried out beside the running one would otherwise be handed
half the queries and answer them from whatever it was given. So the listener
asks for the port with an ordinary bind before the readers share it, and a port
somebody already holds is still refused with `Address_In_Use` exactly as it was
before the readers existed.

`receive_buffer` is what absorbs a burst that arrives while every reader is busy.
Linux clamps it to `net.core.rmem_max`, 208 KiB on a machine nobody has tuned, so
the startup line reports what was granted rather than what was asked for; raise
the sysctl if you raise this. What the kernel dropped anyway is published per
reader as `elodin_udp_receive_drops_total`, beside `elodin_udp_datagrams_total`
for what each reader did read — the two together are the only way to see this
condition from inside the server, since a datagram dropped in the queue never
reaches a read and is indistinguishable from one nobody sent. A rise in it is
also written to the log at the five-minute report, for operators who are not
scraping.

**None of this is a defence, and it is not meant to be read as one.** It is
headroom: it raises the rate at which the limiter's guarantees still hold, and
above that rate they still stop. A flood from a single source port hashes to a
single reader — which is the good case, the other readers being untouched — while
one from many source ports spreads over all of them exactly as legitimate traffic
does. **A publicly reachable instance wants a packet filter in front of it**, or
upstream scrubbing, which is what every public resolver runs anyway.

### DNS cookies

```yaml
cookies:
  enabled: true          # answer clients that send a cookie
  require: false         # demand a valid one from UDP clients that send any
  upstream: true         # present a cookie of our own to plain upstreams
  secret: ""             # 32 hex characters; empty draws a random one at startup
```

A client talking to elodin over UDP has a 16-bit transaction ID and a randomised
source port between it and a forged answer — about 32 bits, both visible to
anyone on the path. Cookies (RFC 7873, RFC 9018) add 64 bits that are not.
Nothing is remembered per client: the token is recomputed on each query from the
client's own cookie, its address and a timestamp, keyed by a secret this process
holds, so there is no table for a flood of clients to fill and a leaked cookie
stops working within the hour. An answer carries one only when the query did.

`require` makes a UDP query that carries a cookie show a valid server one before
it is answered — otherwise BADCOOKIE and a cookie to come back with, before the
name is looked up at all, so an attacker forging queries from someone else's
address never gets an answer sent there. It costs honest clients one extra round
trip the first time each asks, which is why RFC 7873 has it for use while an
attack is under way, and why it is off by default. Queries with no cookie, and
queries over TCP, DoT or DoH, are unaffected. It needs `enabled`, and the two
together are rejected at startup rather than left looking like a protection that
is on.

`secret` matters when more than one elodin answers on the same address: without
it each draws its own at startup and rejects the cookies the others handed out.

`upstream` turns the mechanism the other way round, presenting a random client
cookie per server plus the server cookie that server last issued. A reply
carrying a cookie that is not ours cannot have come from the server we asked, so
it is passed over and the socket keeps waiting for the genuine one — answering a
spoofing attempt with SERVFAIL would hand the attacker most of what it was after.
Once a server has issued a cookie, a reply from it with the option left off is
passed over the same way (RFC 7873 §5.3); a server that has never sent one does
not implement them, and the exchange carries on without. A BADCOOKIE reply
carries a fresh server cookie, so the query is asked once more with it.

Neither side's cookie crosses over: the client's stops at elodin whatever the
settings, its server half having been minted here, and the upstream's is removed
before the answer goes near a client or the cache.

| | client-facing | upstream |
|---|---|---|
| setting | `cookies.enabled` | `cookies.upstream` |
| default | on | on |
| secret | `cookies.secret`, or random at startup | random per upstream |
| server cookie | recomputed per query, nothing stored | learned and held per upstream |
| transports | UDP, TCP, DoT, DoH | UDP and TCP only |
| a cookie that does not check out | answered anyway, or BADCOOKIE with `require` | ignored, and the wait continues |
| a message with no cookie | answered, and given none back | accepted, unless that server has issued one before |

Only queries that already carry an OPT record get a cookie, since adding one
would negotiate EDNS on behalf of a client that never asked — with validation on,
which is the default, every forwarded query carries one. DoT and DoH upstreams
are left out, a certificate establishing more than a cookie can.

### EDNS padding

Encryption hides what a DNS message says, not how long it is, and DNS messages
are distinctive enough by length that an observer holding a list of candidate
names can often tell which one was asked. RFC 7830 defines the mitigation — an
EDNS option carrying nothing but zeroes — and RFC 8467 fixes the block sizes.
elodin does both halves, on DoT and DoH only:

| | client-facing | upstream |
|---|---|---|
| block | 468 octets (RFC 8467 §4.2) | 128 octets (RFC 8467 §4.1) |
| transports | DoT and DoH | DoT and DoH upstreams |
| when | the client's query carried the option | every query that carries an OPT record |
| the other side's padding | replaced with ours | stripped before the answer is cached |

There is no setting. The RFC gives one pair of numbers rather than a knob, and a
deployment padding to a block of its own choosing would be recognisable by it,
which is the opposite of the point.

UDP and plain TCP are left out deliberately (RFC 8467 §5): padding a message
anyone on the path can read hides nothing from them, and on UDP the bytes would
come out of `server.max_udp_response`, enlarging exactly the datagrams the [UDP
answer ceiling](#how-large-a-udp-answer-may-be) exists to bound. A client that
did not send the option gets no padding either (RFC 7830 §4) — it never budgeted
for the bytes. Upstream, only queries that already carry an OPT record are
padded, for the same reason cookies are. An upstream that pads its replies back
has that padding taken off before the answer is stored, so the cache holds the
answer rather than the answer plus a block of zeroes.

### DNS rebinding protection

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
`fe80::/10`), IPv6 unique-local (`fc00::/7`), `0.0.0.0/8` or `::`. It reads A and
AAAA records and the `ipv4hint`/`ipv6hint` parameters of SVCB and HTTPS records,
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
exactly like a name that does not exist. [DNSSEC](#dnssec) defaults the other way
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

A zone with a route under [`upstream.zones`](#per-domain-upstreams) needs no
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
[reserved-name table](#reserved-names) answers those names first anyway.

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

Wildcards match subdomains only, so `*.lan` covers `host.lan` but not `lan`. An
optional `ttl` sets what the answer carries. Rewrites are matched before
everything else, the block lists included.

#### Other record types

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

#### Reverse lookups

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
settles it too, and `answer: block` or the [sink lists](#sink-lists) sink a name
without handing out an address to reverse at all; the key is for when the block
page really does have to be an address.

And the reverse direction makes your local name inventory sweepable: anyone your
[client allow list](#who-may-ask) admits can walk RFC 1918 reverse space and
collect the names, where before they had to guess forward ones. dnsmasq and
AdGuard Home answer the same sweep the same way, and the allow list defaults to
local networks only — but if that list is wide, this is one more thing behind it.

### Reserved names

```yaml
special_use:
  enabled: true    # the table below
  onion: true      # onion.  (RFC 7686 section 2)
  local: false     # local.  (RFC 6762 section 22)
  test: false      # test.   (RFC 6761 section 6.2)
  home_arpa: false # home.arpa. (RFC 8375 sections 3 and 4)
```

Three names are answered here rather than asked about, whatever
`upstream.servers` says:

| name | answer | why |
|---|---|---|
| `localhost.` and below | 127.0.0.1 for A, `::1` for AAAA, NODATA otherwise | RFC 6761 6.3. The only answer it is allowed to have |
| `onion.` and below | NXDOMAIN | RFC 7686 2, unless the upstream is Tor-aware |
| `invalid.` and below | NXDOMAIN | RFC 6761 6.4. It cannot exist |

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
route under [`upstream.zones`](#per-domain-upstreams) pointed at it, alongside
the `local: false` that is already the default.

`home_arpa` is about privacy rather than a wrong answer: those names are your own
network's, and forwarded they name your hardware to a public resolver in exchange
for the blackhole servers' NXDOMAIN. What it does *not* do is send them to your
router instead — that is [`upstream.zones`](#per-domain-upstreams), which is what
a network whose router *does* answer the zone wants, and is why this key cannot
simply default on. The zone is served empty rather than absent,
which is what RFC 8375 section 4 asks for — `printer.home.arpa` is NXDOMAIN,
`home.arpa` itself NODATA with its own SOA and NS. One query still goes out with
the key on, `home.arpa DS`, whose signed proof lives in `arpa` and which a
validating client below elodin needs to conclude "insecure" instead of "broken";
see [DNSSEC](#dnssec).

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

### Metrics

```yaml
metrics:
  enabled: true
  address: "127.0.0.1"   # loopback by default
  port: 9153             # the port CoreDNS uses for the same thing
  path: /metrics
```

Off by default, and nothing is bound until it is turned on. The endpoint speaks
plain HTTP and serves the Prometheus text exposition format.

```
scrape_configs:
  - job_name: elodin
    static_configs:
      - targets: ["127.0.0.1:9153"]
```

**It is not on the path a query takes.** Every number it publishes is a counter
the resolver already maintains for the `msg=stats` line, read at scrape time from
the atomic it already lives in. There is no latency histogram and no per-name
label, because both would mean measuring on the path being measured. The
isolation is structural: one thread of its own, no work queued on either worker
pool, no thread per connection — so nothing reaching this port can spend the
budget `max_connections` keeps for clients, or the per-prefix arrival budget the
DNS listeners charge — and one request per connection before closing, so a scraper
holding a socket open cannot keep the next scrape out.

It binds loopback rather than the `0.0.0.0` the DNS listeners use: nothing here
is a secret in the way an answer is, but together these numbers describe a
network and there is no authentication in front of them. A wider bind is logged
as a warning at startup.

| metric | type | what it is |
|---|---|---|
| `elodin_build_info{version}` | gauge | a constant 1, carrying the version as a label |
| `elodin_uptime_seconds` | gauge | seconds since this process finished starting |
| `elodin_queries_total` | counter | queries accepted, whatever became of them |
| `elodin_answers_total{outcome}` | counter | `forwarded`, `cached`, `blocked`, `rewritten`, `failed` |
| `elodin_queries_dropped_total` | counter | turned away before any work: the backlog was full, or the source could not be answered |
| `elodin_queries_refused_total` | counter | turned away by `server.allow_from` |
| `elodin_connections_refused_total` | counter | refused for want of a slot: `server.max_connections` full, or the client's prefix already holding its share |
| `elodin_connections_rate_limited_total` | counter | refused because the prefix was opening connections faster than `rate_limit.responses_per_second` allows |
| `elodin_connections_failed_total` | counter | refused because the OS would not start a thread |
| `elodin_connections_active` / `_max` | gauge | connection threads in use, and what the limit allows |
| `elodin_connections_max_per_prefix` | gauge | how many of those one client prefix may hold; equal to `_max` when there is no share |
| `elodin_tls_handshakes_total` | counter | TLS handshakes completed on the DoT and DoH listeners |
| `elodin_rate_limited_total` | counter | queries the rate limiter withheld an answer from |
| `elodin_rate_limit_slipped_total` | counter | those answered truncated instead, to send a real client to TCP |
| `elodin_dnssec_answers_total{result}` | counter | `secure` and `bogus` |
| `elodin_rebind_refused_total` | counter | answers withheld because a public name was pointed into private space |
| `elodin_special_use_total` | counter | queries answered from the reserved-name table instead of being forwarded |
| `elodin_cache_entries` / `_bytes` | gauge | what the cache holds, against `max_entries` and `max_bytes` |
| `elodin_cache_hits_total` / `_misses_total` / `_evictions_total` | counter | how it is doing |
| `elodin_cache_stale_total` | counter | expired answers served because no fresh one could be got |
| `elodin_cache_withheld_total` | counter | answers the cache handed over that were then refused rather than served |
| `elodin_filter_rules{list}` | gauge | rules loaded, `block` and `allow` |
| `elodin_upstream_queries_total{upstream}` | counter | queries sent to each upstream, by its configured name |
| `elodin_upstream_failures_total{upstream}` | counter | exchanges that produced no usable answer |
| `elodin_upstream_latency_seconds_total{upstream}` | counter | cumulative round-trip time; divide by the query counter under `rate()` for the mean |
| `elodin_upstream_up{upstream}` | gauge | 0 while an upstream is in its failure cooldown |
| `elodin_udp_datagrams_total{reader}` | counter | datagrams each UDP reader took off its socket |
| `elodin_udp_receive_drops_total{reader}` | counter | datagrams the kernel dropped on that reader's receive queue before they could be read; absent where `/proc` cannot be read |
| `elodin_pool_workers{pool}` / `elodin_pool_pending{pool}` | gauge | the `query` and `upstream` pools; `pending` that does not return to zero is `server.workers` set too low |
| `process_cpu_seconds_total` | counter | user plus system CPU |
| `process_resident_memory_bytes` / `_virtual_memory_bytes` | gauge | from `/proc/self/stat` |
| `process_threads`, `process_open_fds`, `process_max_fds` | gauge | thread and descriptor counts |
| `process_start_time_seconds` | gauge | when this process began serving |

`elodin_answers_total` does not sum to `elodin_queries_total`: queries the
backlog or the allow list turned away never reached an outcome, an answer the
rebinding guard withheld is counted in `elodin_rebind_refused_total`, and of the
`outcome=local` answers only the reserved-name table is counted, in
`elodin_special_use_total`. The `process_` family carries the names every
Prometheus client library uses, so a dashboard written against a Go or Python
service works here unchanged.

```promql
sum(rate(elodin_queries_total[5m]))
sum by (outcome) (rate(elodin_answers_total[5m]))
rate(elodin_cache_hits_total[5m]) / rate(elodin_queries_total[5m])
rate(elodin_upstream_latency_seconds_total[5m]) / rate(elodin_upstream_queries_total[5m])
min by (upstream) (elodin_upstream_up) == 0
```

A Grafana dashboard is in
[`examples/grafana-dashboard.json`](examples/grafana-dashboard.json) — import it
under **Dashboards → New → Import**. It asks for a Prometheus data source and
picks up `job` and `instance` from `elodin_build_info`, so it works against one
instance or a fleet without editing.

## What is implemented

Queries of any type are answered: A, AAAA, CNAME, MX, TXT, SRV, SOA, NS, PTR,
CAA, SVCB/HTTPS, DS, DNSKEY, RRSIG and everything else. Types the codec does not
model natively are carried through as opaque RDATA per RFC 3597, and forwarded
answers are passed back byte for byte, so DNSSEC records survive untouched. With
validation on, an answer for a client that did not ask for DNSSEC records is
rebuilt without them; every other answer goes back verbatim, bar the two bytes of
payload size in the OPT record.

Also handled: EDNS0 — the client's OPT record is forwarded upstream so payload
sizes are negotiated end to end, minus its cookie and its client-subnet option,
which both stop here; a query with two OPT records, or with one whose options
cannot be read, is answered FORMERR rather than forwarded, neither being a
message those two can be taken back out of. Then DNS cookies in both directions,
[EDNS(0) padding](#edns-padding) in both directions on DoT and DoH and on
neither of the clear transports, truncation with the TC bit and the UDP→TCP
retry, `version.bind`/`hostname.bind` in the CHAOS class, local NODATA answers
for `resolver.arpa`, refusal of zone-transfer requests, and the reserved names of
RFC 6761 and RFC 7686 answered here instead of forwarded.

## Sizing

A worker thread is held for the whole of an upstream round trip, so sustained
throughput on cache misses is roughly `server.workers / upstream_rtt`. Two
consequences: **every query shares that pool**, so running short on workers
delays cache hits as much as misses; and **memory scales with workers**, as a
floor rather than a peak, because a worker holds its scratch arena from its first
query onward — `free_all` on Odin's temp allocator keeps and zeroes the first
block instead of returning it.

That second point is why the worker counts are not fixed numbers. Left unset —
which is what `0` means, and what the shipped configuration says — they are
derived at startup from the machine:

```
workers           = clamp(usable_cpus * 4, 16, 128), lowered if the threads
                    that implies would take more than 1/32 of usable memory
upstream_workers  = workers / 2
max_pending       = workers * 8
```

"Usable" is what this process can have rather than what the box holds: the CPU
affinity mask, and a cgroup CPU or memory limit where there is one, so a
container or a unit with `CPUQuota=`/`MemoryMax=` sizes itself for what it was
given. A number in the configuration always wins, and the two worker counts can
be set independently — an unset `upstream_workers` follows a configured
`workers`. What it settled on is logged after startup and printed by `--check`:

```console
$ elodin --check
/etc/elodin/elodin.yaml is valid: 2 upstreams, 0 zone routes, 4 blocklists, 0 rewrites
  workers=16 upstream_workers=8 max_pending=128 (derived from 4 usable CPUs and 7.7 GiB)
  answering queries from 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, ::1/128, fc00::/7, fe80::/10; every other source is refused
  udp: 4 readers, asking for 1MiB of receive buffer each (derived from 4 usable CPUs)
  connections: at most 512 at once across TCP, DoT and DoH, of which one client prefix (/24, /64) may hold 256; connections past a prefix's share are refused and counted as conn_refused=
```

Past `max_pending` the server drops queries rather than queueing them: queueing
past that point only adds latency to answers whose clients have already given up,
and every other client then waits behind them. A dropped query gets no answer at
all, so a client sees a timeout and retries, which is the failure DNS is built
for. A DoH client over HTTP/2 is answered 503 instead, its stream being the other
path that queues and there being a client on an open connection to tell.

Concurrency differs by transport. **UDP** has a reader thread per usable CPU, to
eight, each handing every datagram it reads to the worker pool, with no
per-client state and no connection limit; see [how fast datagrams can be
read](#how-fast-datagrams-can-be-read), which is the ceiling on everything the
rate limiter achieves. **TCP, DoT and DoH** give each connection a thread, capped together by
`server.max_connections` (512) and per client by
[`max_connections_per_prefix`](#how-many-connections-one-client-may-hold) (half
of it); within a connection TCP, DoT and HTTP/1.1 answer one query at a time
while **HTTP/2 multiplexes**. Connections are reused, so the cap bounds
concurrent *clients* rather than queries per second.

HTTP/2 costs more CPU per query than HTTP/1.1 on cache hits — framing, HPACK, the
hand-off to the worker pool — and earns it back when queries are slow, which is
when a browser is actually waiting: its concurrent requests overlap instead of
queueing, so latency settles at one upstream round trip rather than accumulating
one per request. TLS handshakes are the expensive thing on the encrypted
transports, orders of magnitude more CPU than answering on an established
connection, and ECDSA P-256 costs about half what RSA-2048 does — which is why
`mise run certs` generates ECDSA, and why you should use it in production too.

**How often a client may ask for a handshake is bounded by the rate limiter, and
only per prefix.** A response budget is spent by answers and the connection share
by connections *held*, so a client that connects, handshakes and hangs up spent
neither, and `bench/results/2026-09-03-handshake-floods.md` measures what that
cost: 7,000 handshakes a second out of a 4-core machine, 205 µs of CPU each, 1.4
cores in total, with `conn_refused` at zero throughout because the shipped table
was never reached. A DoT client already running its one connection at capacity
lost 16 points of its answer rate and six times its latency. So opening a
connection is charged to the prefix's own budget now — see [rate
limiting](#rate-limiting) — which on the shipped 500 held the same flood to 462
handshakes a second and 0.29 of a core, and gave that DoT client back a good third
of what it had lost. It is per prefix like everything else, and a refusal is cheap rather
than free, so **if you expose DoT or DoH to the internet, rate-limit connections
per source in front of the resolver as well**: see [a connection rate limit in
front](#a-connection-rate-limit-in-front).

Past `max_connections`, or past one client's share of it, DoT and DoH refuse
cleanly during the handshake. Plain TCP cannot: the kernel completes the
handshake from the listen backlog before the server sees it, so a refused client
gets a reset on first use and has to reconnect. Either way it is counted as
`conn_refused=`, kept apart from `refused=` because this is a client elodin would
serve and has no room for; which of the two limits refused it is in the `warn`
line beside it. A connection refused *below* both, when the OS will not give the
process another thread — `RLIMIT_NPROC`, a cgroup `pids.max`, memory — is `conn_failed=`,
where raising `max_connections` cannot help and would make it worse.

`mise run bench` measures all of this; the harness is documented in
[`bench/README.md`](bench/README.md) and its committed runs are under
`bench/results/`. Read those as the shape of the thing rather than as a
specification, and re-take them rather than quoting an old run against a change.

One thing to watch on disk: `log.queries` writes a line per query and wants
rotation. Nothing else is written in steady state, and the blocklist cache is the
size of the lists.

## Known limitations

- DNSSEC validation is on by default, and where a distribution's crypto policy
  forbids SHA-1 signatures the two RSA/SHA-1 algorithms degrade to insecure
  rather than validating. See [DNSSEC](#dnssec).
- [Rebinding protection](#dns-rebinding-protection) runs only for A, AAAA, ANY,
  SVCB and HTTPS questions — the ones a browser can be made to ask. Addresses in
  the additional section are left alone unless the answer carried an SVCB or
  HTTPS record.
- **Connection-oriented transports get a thread per connection**, capped for TCP,
  DoT and DoH together by `server.max_connections` and per client prefix by
  `server.max_connections_per_prefix`. That suits clients that hold a connection
  open and pipeline over it, not tens of thousands of concurrent connections. UDP
  is the exception: a reader thread per core and no per-client state.
- **Past what the UDP readers can drain, the kernel decides who is served.**
  Datagrams that overflow a receive queue are dropped by the socket, so no budget
  in this server applies to them; `listeners.udp.readers` raises the rate at which
  that starts and does not remove it. A publicly reachable instance wants a packet
  filter in front of it. See [how fast datagrams can be
  read](#how-fast-datagrams-can-be-read) for the measured figure.
- **The bound on TLS handshakes is per prefix, and a refusal is cheap rather than
  free.** Opening a connection is charged to
  `server.rate_limit.responses_per_second`, which held a 32-worker flood to 462
  handshakes a second and 0.29 of four cores against 6,032 and 1.25 uncharged. But
  it is keyed on the /24 and /64 like every other budget here, so an actor with
  addresses in several prefixes has several copies of it, and the flood's *dial*
  rate rose four times once being refused was cheap — the DoT bystander in that run
  recovers to 88% of its queries answered where the quiet baseline is 98%. A UDP
  bystander is untouched either way, which the same report measures. A publicly
  reachable instance wants a per-source connection rate limit in front of it: see
  [a connection rate limit in front](#a-connection-rate-limit-in-front), and
  `bench/results/2026-09-04-handshake-budget.md` for the figures.
- **Upstream I/O is synchronous**, so concurrency is bounded by thread count
  rather than by in-flight queries. The h2 upstream client multiplexes onto one
  connection, but a worker is still held for the round trip. Async upstream I/O
  would lift this and the connection item above; the UDP half of it is done, the
  readers being behind `SO_REUSEPORT` since #233.
- **DNS cookies do not cover every query.** Only queries that already carry an
  OPT record are given one upstream, so a non-EDNS client behind elodin gets no
  cookie protection unless DNSSEC validation is on — which it is by default.
  Cookie secrets are drawn once at startup and never rotated: restarting costs
  each client and each upstream one extra round trip.
- **elodin does not advertise its own DoT or DoH endpoints over DDR.**
  `resolver.arpa` is answered NODATA rather than forwarded, which keeps clients
  here, but nothing designates its encrypted listeners automatically: point
  clients at them by configuration, by the [Apple
  profile](#apple-devices-ios-ipados-macos), or by a `rewrites` rule.
- **EDNS Client Subnet is not implemented, and a client's option is dropped on
  the way upstream** (RFC 7871). Forwarding one is only correct alongside the
  per-network caching of section 7.3, which this cache does not do — its key is
  the question plus the DO and CD bits — so a subnet a client named would steer
  the answer every other client behind elodin is then given, and would tell a
  public upstream where that client claims to be. Nothing is sent in its place,
  and there is no setting to turn forwarding back on, because there is nowhere
  honest to file the answers yet.
- No per-client rules, no query log database, no web or API surface. Statistics
  go to the log every five minutes, and to a Prometheus endpoint when
  [`metrics.enabled`](#metrics) is set — counters only.
- Configuration is read once at startup, with one exception: `SIGHUP` reloads the
  DoT/DoH certificates. Listener addresses, the upstream set and blocking need a
  restart.

## Layout

```
src/main/      entry point: arguments, startup order, signals, maintenance loop
src/dns/       message codec: names, compression, records, EDNS, TTL patching
src/yaml/      YAML subset parser and typed accessors
src/config/    configuration schema, loading, validation and worker sizing
src/filter/    sink-list matching and list-format parsers
src/cache/     LRU answer cache
src/dnssec/    validation: canonical form, signatures, NSEC/NSEC3, chain of trust
src/upstream/  transports (UDP/TCP/DoT/DoH), pooling, strategies, cookies, HTTP/1.1 and h2 clients
src/server/    resolver, listeners, DoH endpoint, cookies, local zones, list refresh
src/h2/        HTTP/2 framing, HPACK, and the server connection state machine
src/tlsx/      OpenSSL bindings and a small TLS wrapper
src/pool/      worker pool
src/logx/      logging, in logfmt
src/metrics/   Prometheus exposition format, and process figures out of /proc
src/privdrop/  giving up root once the listeners hold their ports
src/itest/     integration suite: harness, mock upstreams (DNS, HTTP, DoH/h2), clients, fixtures
src/fuzz/      libFuzzer targets for the DNS, HPACK and YAML parsers, and their shared arena
testdata/      fuzz corpus and dictionary, committed so a found crash stays
               found, plus gen/ - the generator behind the DNSSEC fixtures
bench/         benchmark harness and DNSSEC survey, in Go, with committed results
examples/      the shipped configuration, a development one, and a Grafana dashboard
packaging/     systemd unit and the .deb build script
```

Two worker pools run underneath: one answering queries, one dedicated to racing
upstreams. They are separate on purpose — a race job is submitted *by* a query
handler and waited on by it, so one pool could deadlock once every worker was
blocked on jobs nobody was left to run.

## Testing

`mise run verify` runs the first two layers. A third watches what those two do to
memory, fuzzing runs on its own schedule, and `mise run bench` measures rather
than asserts.

**Unit tests** (`mise run test`) cover the message codec — round trips for every
modelled RDATA type, compression, truncation, EDNS, pointer loops, hostile record
counts — plus the YAML parser, configuration loading, list parsing and matching,
the cache, and the HTTP/2 codec, whose HPACK cases run the worked examples from
RFC 7541 appendix C so the codec is checked against the specification's own
vectors rather than against itself. They run per package, so a failure names one.
Much of `tlsx`, `upstream`, `h2` and `server` is the suite grown around bugs
found some other way that had to stay found.

The DNSSEC cases work from real signed traffic captured from a public resolver
(`src/dnssec/fixtures_test.odin`): the root and `com` with RSA/SHA-256,
`example.com` and `www.cloudflare.com` with ECDSA P-256, `ed25519.nl` with
Ed25519, a real NSEC denial from the root, a real NSEC3 denial from `com`, and a
real unsigned delegation. The validator walks those chains the whole distance,
and the same fixtures are then tampered with — a flipped address byte, a stripped
signature, a corrupted DS digest, a mismatched anchor, a clock a year later — and
every one has to come back bogus. Signatures expire, so the tests pin the moment
they are judged against rather than reading the clock. Three cases hold specific
attacks down: a DNSKEY set signed by a key sharing the attested key's tag, an
injected RRSIG naming the zone a denial is checked against, and a response built
to make one question cost as many upstream lookups as possible — each checked
against the code as it stood before its fix, so they are known to fail when the
property they guard does.

**Integration tests** (`mise run itest`) start the built binary as a separate
process against scripted mock upstreams, so what is exercised is the artefact
that ships rather than the library it was compiled from. The suite is hermetic:
no public resolver is contacted, ports come from a private range, and the
certificate for the TLS cases is generated by the suite itself.

```
mise run itest              # summary
./bin/itest -v              # one line per case
./bin/itest --keep          # keep the working directory and server logs
./bin/itest --binary <path> # test a specific build
```

It covers the command line and `--check`, orderly shutdown, that every line of a
real run parses as logfmt, the wire format (captured fixtures replayed and
compared byte for byte, EDNS forwarding, 0x20 case preservation, truncation,
FORMERR/NOTIMP handling), forwarded transaction ids per RFC 5452, `allow_from`,
the UDP answer-size ceiling, every listener including DoH over both HTTP versions
and the Apple profile end to end, h2 upstreams, blocking and rewrites in every
mode — the new record types from their zone-file form, additive rules falling
through, and the PTR synthesis in both families with each of the cases that gets
none — rate limiting on every budget, including the share of the connection table
one client may hold and the rate at which it may open them, the rebinding guard on
and off, the cache,
all three upstream strategies with health cooldown and pooling, per-domain
routes including nested ones and an anchor that puts validation back, blocklist
downloads and their cache directory, DNSSEC refusal and the CD bypass, the
reserved-name table with each key, cookies in both directions, certificate
reload over `SIGHUP`, and the metrics endpoint.

`src/itest/fixtures.odin` holds real DNS responses captured from a public
resolver, including compression pointers, DNSSEC records and types the codec does
not model. The mock replays them verbatim and the suite compares the bytes the
client receives against the bytes the upstream sent — generating the fixtures
with elodin's own encoder would let a codec bug agree with itself and still pass.

**Memory** is checked in two places, because no one place can see all of it.
`odin test` wraps every test in a tracking allocator, and
`ODIN_TEST_FAIL_ON_BAD_MEMORY` — set for `mise run test` — turns what it finds
into a failing test rather than a warning line among the passes. That catches a
procedure which keeps what it was lent, and nothing else: nearly every allocation
on the query path comes from a per-request arena that is reset whole, so a leak
there is invisible by construction, and the memory that is *not* arena-backed
belongs to the running server rather than to any procedure a test calls.

So `mise run leakcheck` builds the binary with `-sanitize:address` and runs the
integration suite against it, asking each server to exit rather than killing it —
a sanitizer reports on its way out, and a killed process never gets there. This
is the layer that reaches the configuration, the listeners' TLS contexts, and the
answers a race worker allocates on the heap because it may outlive the caller's
arena; every one of those has leaked at some point, and none is reachable from a
unit test. Being ASan rather than LSan alone, it also catches a use-after-free —
which is how the certificate reload was found to be freeing a context a
connection was still about to read. It is not part of `mise run verify`, which is
the fast local gate; CI runs it on every change.

**Fuzzing** covers the three parsers that read bytes somebody else chose: the DNS
wire codec (`dns.decode_message`, plus `dns.truncated_response`, which the UDP
read loop reaches for a rate-limited query without decoding it first), the HPACK
decoder, and the YAML parser, which reads the configuration file. The blocklist
formats are not covered: a downloaded list goes to `filter.parse_list` rather
than through the YAML parser, and has no target of its own. Odin has no
`-fsanitize=fuzzer`, so
`mise run fuzz` emits LLVM IR per target and has clang instrument and link it
into a libFuzzer binary at `bin/fuzz_*`, with ASan on and bounds checks still in.
Running one is open-ended, so `.github/workflows/fuzz.yml` does it nightly
against a corpus cached between runs, and `workflow_dispatch` runs it on demand
after a parser is touched. What CI runs on every change is
`mise run fuzz-regression`, which replays `testdata/fuzz-corpus/` through each
target once and generates nothing new, so a crash fuzzing has already found stays
found.

**Against live DNS**, because none of the layers above can prove the absence of
false failures: they work from fixtures and generated input, so they can show
that a forged answer is refused and cannot show that validation leaves working
names working — a validator that refused everything would pass the entire suite.
From `bench/`, `go run ./cmd/bench -survey 9.9.9.9:53` asks every name in
`bench/domains.txt` through elodin with validation on, asks a reference
validating resolver the same thing, and compares the rcode and the AD bit: the
deliberately broken zones in that list have to be refused and everything else has
to resolve. Names served without the AD bit are the SHA-1 downgrade described
under [DNSSEC](#dnssec) — a fact about the host's crypto policy rather than about
the zone.

Interoperability with a foreign HTTP/2 implementation is checked by hand with
curl, which uses nghttp2: `curl --http2 -k -H 'content-type:
application/dns-message' --data-binary @query.bin
https://127.0.0.1:443/dns-query`.

CI (`.github/workflows/ci.yml`) runs on every pull request and every push to
`main`: `mise run check` once, `mise run test` and `mise run itest` on both
architectures, `mise run fuzz-regression` and `mise run leakcheck` once,
`mise run build` on both, and —
on both — a `mise run deb` that is then installed on the runner, asked to resolve
a handful of names through the takeover it just performed, and removed again with
a check that the runner got its own resolver back.

## License

MIT — see [LICENSE](LICENSE). Release tarballs and the .deb carry it too, the
latter at `/usr/share/doc/elodin/copyright`.
