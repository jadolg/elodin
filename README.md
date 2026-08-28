# elodin

A filtering DNS forwarder in [Odin](https://odin-lang.org), in the spirit of
Pi-hole and AdGuard Home, minus the web interface. One binary, one YAML file.

- Serves plain DNS (UDP + TCP), DNS-over-TLS and DNS-over-HTTPS (HTTP/2 and HTTP/1.1)
- Hands Apple devices a `.mobileconfig` profile to point themselves at the DoH endpoint
- Forwards to plain, TCP, DoT and DoH upstreams
- Three upstream strategies: failover, round-robin and race
- Sink lists in hosts, plain-domain and adblock syntax, with allowlists
- Answer cache with negative caching and optional stale serving
- Response rate limiting per client prefix, on every transport and with a separate budget for datagrams and for connections, on by default (see `server.rate_limit`)
- Client allow list restricting who may query, defaulting to local networks only
- A ceiling on UDP answer size to bound reflection amplification, on by default
- Local rewrites (A, AAAA, CNAME, or "answer as if blocked")
- DNSSEC validation against the root trust anchors, on by default
- DNS rebinding protection: an upstream answer pointing a public name at loopback, RFC 1918 or link-local space is refused, off by default so split horizon keeps working, one line to turn on (see `rebind`)
- DNS cookies in both directions (RFC 7873/9018), on by default
- Ships as a systemd service or a `.deb`, with optional automatic system-resolver takeover

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
mise run build            # bin/elodin, with debug info
mise run release          # bin/elodin, optimised
mise run test             # unit tests
mise run itest            # integration tests against the built binary
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

The listeners bind `0.0.0.0`, but by default only the local networks are served
— loopback, RFC 1918, IPv6 loopback, unique local and link-local. Clients on
another network need adding to `server.allow_from`; see
[Who may ask](#who-may-ask).

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

`Restart=on-failure` covers a start that fails for a reason that passes, but
`StartLimitBurst=5` over five minutes stops it retrying one that does not — a
port it cannot have, a certificate it cannot read. The unit gives up in
`failed`, where `systemctl status` and anything watching it will say so, rather
than reporting `activating` forever and reloading the blocklists once every few
seconds against a machine that has no resolver. `systemctl reset-failed elodin`
clears that once the cause is dealt with.

A published GitHub release carries a `linux-amd64` and a `linux-arm64` tarball
built by `.github/workflows/release.yml`, each holding the optimised binary, the
unit file, the example configuration, this README and the licence, and a `.deb`
of the same binary for each architecture. Both are built natively, on a runner
of the architecture they target, because elodin binds the system libssl and
libcrypto and cross-compiling would mean carrying a sysroot for each.

CI (`.github/workflows/ci.yml`) runs on every pull request and on every push to
`main`: `mise run check` once, `mise run test` and `mise run itest` on both
architectures, `mise run fuzz-regression` once, `mise run build` on both, and —
also on both — a `mise run deb` that is then installed on the runner, asked to
resolve a handful of names through the takeover it just performed, and removed
again with a check that the runner got its own resolver back.

### From a .deb

```sh
sudo apt install ./elodin_0.8.0-1_amd64.deb
```

The binary lands at `/usr/bin/elodin`, the unit at
`/usr/lib/systemd/system/elodin.service`, and `examples/elodin.yaml` at
`/etc/elodin/elodin.yaml` as a conffile — dpkg keeps your edits across upgrades
and asks before replacing them. This README and the licence go to
`/usr/share/doc/elodin/`, the latter as `copyright`. `apt purge` removes the
configuration, the blocklist cache and the state directory.

The install asks one question, and it defaults to yes:

> **Make elodin the system resolver?**

Answering yes stops, disables and **masks** systemd-resolved, replaces
`/etc/resolv.conf` with a real file naming `127.0.0.1` (carrying over any
`search` domains from the old one), and enables and starts elodin. Masking as
well as disabling matters: a later systemd upgrade would otherwise switch
resolved back on and take port 53 at the next boot. elodin reaches its
blocklists and upstreams through the `upstream.bootstrap` addresses rather than
through the system resolver, so it does not depend on the resolver it is in the
middle of replacing.

Answering no installs elodin and leaves everything alone. `sudo dpkg-reconfigure
elodin` asks again, so the decision is not one-way. For unattended installs,
preseed it:

```sh
echo 'elodin elodin/takeover-dns boolean true' | sudo debconf-set-selections
```

Nothing is disabled until `elodin --check` has passed on the configuration the
service will use, and if elodin then fails to stay up — a certificate it cannot
read, a port it cannot have — the package puts systemd-resolved and the old
`/etc/resolv.conf` back and fails the install rather than leaving a machine
pointed at a resolver that is not answering. Removing the package restores them
the same way, whichever answer was given, and `apt remove` is enough: it does
not wait for `apt purge`, because a machine that has just lost its resolver
needs the old one back immediately.

`mise run deb` builds one from a checkout into `dist/`, for the architecture of
the machine that runs it. The script behind it, `packaging/build-deb.sh`,
assembles the archive with `dpkg-deb` instead of debhelper and a `debian/`
directory: the package is a binary, a unit file and a configuration file, and it
is published to a personal apt repository rather than to Debian, so nothing
downstream reads what that machinery produces. The one unit file serves both
routes — the script rewrites `ExecStart` to `/usr/bin`, since a package may not
write to `/usr/local`.

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

### Reloading

`SIGHUP` re-reads the DoT/DoH certificate and key files from the paths already
in the configuration and switches the listeners over to what they now contain
— `systemctl reload elodin`, or `kill -HUP` directly, with no restart and no
dropped connections: a session already in progress keeps using the
certificate it handshook with until it closes. A certificate that fails to
load, the wrong key or a renewal caught mid-write, is logged and left alone;
the listener keeps serving whatever it already had.

Nothing else about the configuration is reloaded this way — listener
addresses, the upstream set, blocking — those still need a restart.

### Observing it

Every line is [logfmt](https://brandur.org/logfmt): `key=value` pairs, quoted
only where a value needs it, with the time and the severity as fields rather
than as a prefix a collector has to be taught to recognise.

```
ts=2026-08-07T09:12:33Z level=info msg=ready strategy=Round_Robin upstreams=2 cache=true blocking=true dnssec=true rebind=false
ts=2026-08-07T09:12:41Z level=info msg=query client=192.0.2.10:44188 proto=udp qtype=A qname=example.com outcome=forwarded detail=cloudflare-dot ms=11.7
ts=2026-08-07T09:12:44Z level=warn msg="list steven-black: unavailable, skipping it"
```

`ts` is RFC 3339 in UTC, and `msg` names the event: the lines something is
expected to watch — `starting`, `sizing`, `ready`, `stats`, `query` — keep the
same `msg` from one line to the next and carry what differs in fields beside
it. Everything else is one human sentence in `msg`, quoted because it has
spaces in it. In Loki that is `| logfmt` and nothing else:

```logql
{job="elodin"} | logfmt | msg="query" | outcome="blocked"
{job="elodin"} | logfmt | msg="stats" | unwrap cache_hits
```

Statistics go to the log every five minutes, as `msg=stats` — `queries`,
`blocked`, `cached`, `forwarded`, `failed`, `dropped`, `refused`,
`conn_refused`, `conn_failed`, `limited`, `truncated`, `secure`, `bogus` and
`rebind`, plus `cache_entries`, `cache_bytes`, `cache_hits`, `cache_withheld`,
`cache_misses`, `cache_stale`
and `cache_evictions` — and `log.queries` adds one `msg=query` line per query, at
the cost noted under [Resource use](#resource-use).

The same numbers, and what the kernel knows about the process besides, are
available to a scraper once [`metrics.enabled`](#metrics) is set. It is off by
default, and it is the same counters either way: the endpoint adds nothing to
the path a query takes.

A query name is the one field in that line whose bytes a client chooses. It is
escaped like any other value, so a label holding a quote or a newline stays
inside its own value and cannot forge a field of its own.

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
  # allow: ["||googleadservices.com^"]   # an exception outranks every list
```

What each list format matches:

| syntax                     | matches                          |
|----------------------------|----------------------------------|
| `0.0.0.0 ads.foo.com`      | `ads.foo.com` exactly            |
| `ads.foo.com`              | `ads.foo.com` and its subdomains |
| `\|\|ads.foo.com^`         | `ads.foo.com` and its subdomains |
| `\|ads.foo.com`            | `ads.foo.com` exactly            |
| `*.foo.com`                | subdomains of `foo.com` only     |
| `address=/foo.com/0.0.0.0` | `foo.com` and its subdomains     |
| `@@\|\|safe.foo.com^`      | never blocked                    |

Hosts entries are exact because hosts-format lists spell out every subdomain
they mean; bare domains and `||` rules cover subtrees. This matches how AdGuard
Home reads the same files. Allow rules always win over block rules.

The rules are matched against the answer as well as the question. An answer
whose CNAME chain lands on a listed name is blocked as though that name had been
asked for: the arrangement to catch is a tracker given a subdomain inside the
site's own zone — `metrics.brand.example` CNAME `tracker.evil.example` — where
the question is a first-party name no list can usefully carry and the address the
browser connects to is the tracker's, with the site's own cookies attached.
Pi-hole calls this deep CNAME inspection and AdGuard Home does the same thing to
CNAME targets. Every hop is matched rather than only the last, up to sixteen of
them. An allow rule exempts the whole answer only when it matches the
*question* — that is the escape hatch when a first-party name resolves through a
CDN somebody has listed, so name the first-party lookup rather than the CDN. An
allow rule matching a hop clears that hop and no other: the party writing the
answer is the party this feature is aimed at, and if any allowlisted name
appearing anywhere in an answer excused the rest of it, every allowlist entry
would be a key for turning the check off. These show in the query log as `outcome=blocked
detail=cname`, against `detail=list` for a question that was on a list itself,
and the name that matched is logged at debug level.

An answer whose chain runs past that sixteenth name is **withheld**, not served.
Bounding the walk and then handing over whatever it did not reach would not be a
bound at all — it would be a length to exceed, and exceeding it is free for
whoever writes the answer, so a listed name one hop past the end would go
straight through. Real chains are one or two names and no zone publishes
seventeen, so what this turns away is answers built to be turned away. They are
counted as blocked and logged as `outcome=blocked detail=cname-deep`; an allow
rule on the *question* skips the walk entirely and is the way out. Note that an
allow rule on a hop past the sixteenth cannot help, because the walk stops
before reaching it.

Four details name a withheld or failed answer that no list explains, and
they are what to search the query log for when a site breaks and nothing in the
lists accounts for it:

| detail | rcode | what happened |
| --- | --- | --- |
| `cname-deep` | the `blocking.response` | the chain ran past the sixteenth name, so where it ends was never checked |
| `cname-unreadable` | SERVFAIL | a CNAME's target could not be parsed, so where it leads could not be checked |
| `answer-unreadable` | SERVFAIL | the upstream's reply could not be parsed at all, so it could not be walked |
| `cache-unreadable` | SERVFAIL | a stored answer could not be parsed on the way back out |

The two `-unreadable` ones answer SERVFAIL rather than what `blocking.response`
says, and the split is deliberate: a listed name and an over-long chain are
answers somebody built, so the operator's chosen refusal fits them, while a
record that will not parse is as likely to be an upstream or a middlebox having
a bad day. Reporting that as NXDOMAIN would tell a client a name it asked for
does not exist, with no rule behind it, and the stub would cache that for
`blocking.block_ttl`; SERVFAIL is the only one of the answers a stub will retry
or fail over from.

`answer-unreadable` is the one worth knowing about, because it is a way for a
name to stop resolving that appears only once blocking is on: with blocking off
nothing walks the answer, so nothing needs to parse it, and the same reply is
forwarded. Every case of it is a name or a length that ran outside the message,
which a client would have to reject too — but if an upstream produces them
routinely, that is the line that says so.

The `address=/…/` and `server=/…/` forms are dnsmasq's, accepted because they
turn up in lists that are otherwise adblock syntax. A `$` modifier
(`$third-party`, `$important`) is dropped and the rest of the rule kept: none of
the modifiers change which *name* a rule matches, and the ones that would need
something a DNS answer cannot express.

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
    mobileconfig_path: /apple-doh.mobileconfig
```

Both request forms of RFC 8484 are accepted on either version: `POST` with an
`application/dns-message` body, and `GET` with a base64url `dns` parameter.

#### Apple devices (iOS, iPadOS, macOS)

Encrypted DNS on iOS 14 / macOS 11 and later is configured with a profile rather
than an app. The DoH listener serves one: browse to `mobileconfig_path` on the
device — `https://dns.example.com/apple-doh.mobileconfig` — and it downloads a
`.mobileconfig` that, once installed under **Settings → General → VPN & Device
Management**, sends the device's DNS to this resolver over HTTPS system-wide.

The `ServerURL` inside the profile is built from the host the request arrived on,
so it always matches the name the certificate is for and the port the listener
is on; a listener answering on several names hands each device a profile for the
one it used. The profile is unsigned, so the device shows it as *Unverified* on
install, which is expected for a self-hosted resolver. Reinstalling replaces the
profile rather than stacking a duplicate — its identifiers are derived from the
URL, so the same endpoint always yields the same profile. Set
`mobileconfig_path: ""` to withhold it; it is served only while DoH is enabled.

Requests arriving on one HTTP/2 connection are answered on the query worker pool
rather than one after another on the connection's reader thread, so the A and
AAAA lookups a browser issues for the same name run at the same time. Responses
are written under the connection's write lock and may complete in any order.

The implementation (`src/h2/`) covers what a DoH endpoint needs: the connection
preface and SETTINGS exchange, HPACK with Huffman decoding and a full dynamic
table, HEADERS with CONTINUATION, DATA, connection- and stream-level flow
control, WINDOW_UPDATE, PING, RST_STREAM and GOAWAY. Server push is refused in
SETTINGS and stream priority is parsed and ignored, which RFC 9113 permits.

A decoded header list is checked against RFC 9113 sections 8.2 and 8.3 before it
becomes a request: connection-specific fields (`connection`,
`transfer-encoding`, `keep-alive`, `proxy-connection`, `upgrade`, and any `te`
other than `trailers`), uppercase or non-token field names, values carrying NUL,
CR, LF or edge whitespace, repeated, unknown or late pseudo-headers, an empty
`:method` or `:scheme`, and a missing or non-origin-form `:path` each make the
request malformed, which is a stream error of type PROTOCOL_ERROR. The one
shape that looks malformed by that list and is not is a conformant `CONNECT`
(RFC 9113 8.5): `:authority` and neither `:scheme` nor `:path`. This endpoint
does not implement it, but turning it away is the handler's job — it draws a
404, not a stream error, because a request that keeps to the specification
should not be told it broke it. Nothing here is proxied onward, so none of this
is a request-smuggling primitive on its own; it becomes one as soon as another
hop sits in front of or behind this endpoint, and the HTTP/1.1 side already
refuses the same shapes.

What one connection may make this end hold is stated in that SETTINGS frame
rather than left to be discovered: 128 concurrent streams, a 32 KiB header list,
and a 4096-byte HPACK table, which is also the ceiling on the dynamic table size
updates a peer may send (RFC 7541 6.3). A header block may arrive in at most 128
CONTINUATION frames, since a block bounded only by its size never ends if the
frames carrying it are empty.

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

Reverse lookups for private space are served, not refused. The reverse trees for
the RFC 1918 ranges, IPv4 link-local and loopback, and IPv6 unique-local and
link-local — `10.in-addr.arpa`, `168.192.in-addr.arpa`, the sixteen `172.16/12`
zones, `169.254`, `d.f.ip6.arpa`, and the rest — are the RFC 6303 locally-served
zones. Nothing on the public Internet signs them, so a local answer for one has
no chain to check; validating it would turn every LAN PTR lookup into SERVFAIL,
so those names are served insecure, without the AD bit — the same default Unbound
and BIND ship. Configuring a `trust_anchors` entry that covers one of these zones
turns that off for it: an operator who signs their own reverse space and anchors
it is asking for it to be validated, and elodin then does.

Queries for `resolver.arpa` are answered here rather than forwarded. That name
is where a client looks for the encrypted endpoints of the resolver it is
already using — RFC 9462's Discovery of Designated Resolvers, an SVCB lookup for
`_dns.resolver.arpa`. Forwarded, the answer would be the *upstream's*
designation, and a client that took it would move its traffic to Quad9 or
Cloudflare directly, leaving the block lists, the rewrites and the query log
behind; the TLS certificate would not name elodin's address either. RFC 9462
section 6.1 says a forwarder should not forward these, so elodin answers NODATA
and the client stays on the resolver it was already talking to. That also
settles a DNSSEC warning worth recognising: `resolver.arpa` does not exist in
the signed `arpa` zone, so an upstream's synthesised, unsigned answer for it is
indistinguishable from a forgery and used to be logged as `dnssec: SVCB
_dns.resolver.arpa ... did not validate: Bogus`. A `rewrites` rule for the name
still wins, for an operator who does want to advertise this server's own DoT or
DoH endpoints.

`special_use.onion: false` stands validation down the same way, on the forward
side. That key says the upstream is a Tor-aware resolver, and what such an
upstream answers for a `.onion` name cannot be signed — the root publishes a
signed proof that there is no `onion.` to delegate — so validating it would
turn every `.onion` lookup into SERVFAIL. Those names are served insecure,
without the AD bit, exactly as the reverse zones above are. It is the only other
place validation is skipped, it applies to nothing but `onion.`, and it is off
until an operator writes the key down; see [Names that are never
forwarded](#names-that-are-never-forwarded).

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

The listeners bind `0.0.0.0` by default, so on a machine with a public address
elodin is reachable from the internet. What keeps it from being an *open*
resolver is this list: queries are accepted from the local networks — loopback,
the RFC 1918 ranges, IPv6 loopback, unique local and link-local — and from
nowhere else. It sits between what the two obvious comparisons ship: BIND's
`allow-recursion` defaults to `localnets` plus `localhost`, and Unbound's
`access-control` is stricter still, starting at `0.0.0.0/0 refuse` with only
`127.0.0.0/8` allowed. (BIND's `allow-query` is a different setting and does
default to `any` — it is recursion, not the query, that it holds back.) The
reason all three have one is the same: an installation nobody has configured
should serve the machine and the network it is on.

This is a different bound from [rate limiting](#rate-limiting), not a weaker
version of it. The rate limiter caps what one victim can be made to receive; it
does not stop this server from taking part in the attack that aims it there. The
allow list is the half that does.

The check runs before the message is parsed, before the rate limiter and before
the query is queued, so a source that is not on the list costs a prefix compare
and nothing else. Over UDP it is dropped: a REFUSED sent to a datagram source is
a reflection of its own, small but free to whoever asked for it. Over TCP, DoT
and DoH the connection is closed on accept, without a thread and without a TLS
handshake — answering REFUSED there would mean a source we have already decided
not to serve costing more than one we do, and would make the allow list a way to
exhaust `max_connections`. Refusals are counted as `refused=` in the stats line
— a datagram each on UDP and a connection each on the stream transports, so the
number is a sum of the two units rather than a count of queries.

Neither refusal tells the client anything, so the log does. The first refusal
since start is a `warn` naming the source, the transport and the setting; every
one after it is `debug`, and the `refused=` counter carries the rest. Without
that line the first symptom of a network nobody added is a client that stopped
working with nothing to grep for; with a line per datagram, whoever is sending
them decides how much this server writes to disk.

```
ts=… level=warn msg="udp: refused a query from 198.51.100.7:41234: it is not in server.allow_from, so nothing was sent back"
ts=… level=warn msg="add its network to server.allow_from if that client should be served; refusals are counted as refused= in the stats line, and further ones are logged at debug level"
```

The line says what was refused. Over UDP that is a query — the datagram is in
hand when the check runs. Over TCP, DoT and DoH the check runs on accept, before
a byte has been read, so it reads `refused a connection from`: there was never a
query to refuse.

A list in the file replaces the default rather than adding to it, so include
loopback if you want it. Entries are CIDR networks in either family; a bare
address is the single host it names, and host bits below the length are masked
off, so `127.0.0.1/8` and `127.0.0.0/8` are the same network. A v4-mapped entry
(`::ffff:192.168.0.0/112`) is the IPv4 network it names, since that is how a
mapped client arriving on an IPv6 socket is compared. An entry that will not
parse fails `--check` rather than starting a resolver that refuses everyone.

Carrier-grade NAT (`100.64.0.0/10`, which Tailscale also uses) is deliberately
not in the default: a resolver behind one would be serving an ISP's other
customers. Add it explicitly if that is your network.

An empty list is no restriction:

```yaml
server:
  allow_from: []
```

That is how you ask for a public resolver, and it is a thing to write down on
purpose. elodin warns about it at every start. Before running one, read
[rate limiting](#rate-limiting) below and consider `cookies.require`.

Note the `[]`. Writing `allow_from:` with nothing after it is a configuration
error rather than either reading of it: YAML makes that a null, and the two
things it could have meant here are the shipped default and its exact opposite.

### Recursion only when asked

`allow_from` decides who may ask; the RD bit in the query decides what they are
asking for. RFC 1035 section 4.1.1 makes RD the client's request for a
recursive lookup, and elodin only forwards to an upstream when it is set. A
query with RD=0 gets whatever this server already has cached, and nothing
more — REFUSED, not a silent drop, so a client that meant to ask recursively
finds out rather than timing out:

```
ts=… level=info msg="query client=198.51.100.7:41234 proto=udp qtype=A qname=\"example.com\" outcome=refused detail=\"rd\" ms=0.1"
```

It does not add to `refused=` in the stats line — that counter is `allow_from`
turning away a source before a query exists at all, and this is a source
already on the list asking a question this server answered, just not by
recursing. An operator graphing `refused=` as an unexpected-traffic signal
will not see RD=0 probes there; the query log, with `log.queries` on, is where
they show up.

There is no setting for this; it is not a policy an operator tunes, only a bit
a client sends. The refusal still comes back with RA=1: RFC 1035 section 4.1.1
makes RA a statement that the server supports recursive service, not that this
particular query used it, and that is also what BIND and Unbound do with a
query their own ACL declines to recurse for. The capability is on offer; this
one request just did not draw on it.

### How large a UDP answer may be

```yaml
server:
  max_udp_response: 1232          # 512–4096; the DNS Flag Day 2020 figure
```

A client says in its OPT record how large a response it can take, and a
resolver that simply believes it has handed the caller its own amplification
factor: the query arrives on a datagram nobody verified, so an attacker aiming
answers at a victim advertises the largest buffer it can and gets a hundredfold
out of forty bytes. `max_udp_response` is the ceiling on that number, applied on
top of whatever the client asked for. It is also what the per-prefix datagram
budget under [Rate limiting](#rate-limiting) is denominated in — 500 responses a second
is about 600 KB/s at 1232 and about 2 MB/s at 4096.

The cost is a TC bit, and a retry over TCP, on any answer between the ceiling
and what the client asked for. Measured across the 129 names of the DNSSEC
survey asked with `DO=1`, that is **no A or AAAA answer at all** — the largest
is 743 bytes — and five DNSKEY answers, the largest 1793. Nothing in the survey
reaches 4096; that ceiling is only reached by a zone built to fill it, which is
what reflection uses. The measurement is in
[`bench/results/2026-08-06-edns-response-sizes.md`](bench/results/2026-08-06-edns-response-sizes.md).

Raise it, up to 4096, on a network whose path MTU is known to carry large
datagrams and where the resolver is not reachable by anyone who would abuse it.
When the ceiling does truncate an answer, elodin says so and names the setting:

```
ts=… level=warn msg="a 2720-byte answer for big.example. was truncated to 1232 bytes and the client told to retry over TCP: it asked for 4096, and server.max_udp_response is 1232"
ts=… level=warn msg="to send it over UDP instead, raise server.max_udp_response in the configuration (up to 4096); the cost is that a spoofed query can make this server send that much to an address it did not verify"
```

Once, at `warn`; every truncation after that at `debug`, so one large signed
zone does not fill the log. A client that asked for *less* than the ceiling and
got a truncated answer got what it asked for, and nothing is said — the setting
had no part in it.

The ceiling is also the number the answer's own OPT record reports. RFC 6891
section 6.2.4 makes that field the *responder's* maximum, not a copy of the
requestor's — the counterpart to `max-udp-size` in BIND and Unbound, both of
which report their own figure regardless of what was asked for. So a client that
advertises 4096 against the 1232 default is told **1232**, and against
`max_udp_response: 4096` is told 4096; a client that advertised only 512 is told
1232 as well, because that is what this server can deliver, and the 512 it asked
for still bounds the reply it gets. A stub mostly ignores the field; a forwarder
chaining through elodin does not, and one told a number this server will never
send sizes its buffers for an answer that cannot arrive and then pays for a TC
bit and a TCP round trip it was told it would not need. It holds on every path —
locally built answers, forwarded ones, cache hits, and answers re-encoded to
carry a DNS cookie.

Coming from Unbound, note that this is one knob where Unbound has two:
`edns-buffer-size`, which is the figure it advertises, and `max-udp-size`, which
is the bound it truncates at. `max_udp_response` is both.

The ceiling is UDP only. TCP, DoT and DoH establish a connection before a query
arrives, so the address is proven, there is nothing to reflect, and an answer
that fits is sent whole. The OPT record on those goes back exactly as the answer
carried it — the client's own figure on a locally built answer, the upstream's on
a forwarded or cached one — because the field bounds a datagram and nothing on a
stream is bounded by it.

That does mean a truncated answer needs somewhere to go: if you have turned
`listeners.tcp` off, a client told to retry has nowhere to retry to, and the
answer is unreachable rather than slow. Either leave TCP on — it is on by
default — or raise the ceiling to cover the largest answer your clients ask
for.

### Rate limiting

```yaml
server:
  rate_limit:
    enabled: true                 # on by default
    responses_per_second: 500     # per client prefix (/24 for IPv4, /64 for IPv6), and per transport class
    slip: 2                       # answer every 2nd query over the budget truncated; 0 drops them all
```

A UDP query carries no proof of where it came from, so the answer goes wherever
the source address said. That is what makes any resolver an amplifier: a 40-byte
query with an OPT record advertising 4096 buys the sender two orders of magnitude
of traffic aimed at whoever they named, and DNSSEC and `ANY` answers are the
usual way to get the most of it. A spoofed source port of 53 pointed at another
resolver is the same trick made into a loop between the two. How much one
datagram can be is capped separately, by
[`server.max_udp_response`](#how-large-a-udp-answer-may-be); this is the cap on
how many of them.

What bounds it is a budget on how much this server will send *to one place*. The
sender's own rate is not worth measuring — they are not the ones receiving it,
and with a spoofed address there is nothing of theirs to measure — so the budget
is kept per destination prefix, /24 and /64, which is the granularity an attacker
picks addresses within.

Over-budget queries are not simply dropped. Every `slip`th one comes back as a
header and a question with the TC bit set: thirty-odd bytes, too small to be
worth reflecting, and the standard way of telling a client to ask again over TCP
where the handshake proves the address. A client behind a genuinely busy NAT
therefore keeps resolving, one round trip slower; a spoofed source cannot follow
it up. Set `slip: 0` to drop them instead and answer nothing.

500 responses a second to one /24 — about 600 KB/s at the 1232-byte response
ceiling — is far past what a household or an office behind one NAT asks for and
far below what makes reflection worth an attacker's bandwidth, which is why it
is on by default. The accounting is a fixed table of
16,384 buckets — 640 KB, allocated once — so the limiter is not itself somewhere to
put pressure, and which prefixes share a bucket is decided by a key drawn at
startup rather than by anything an attacker can work out.

Two source addresses are refused outright before any of this: port 0, which
nothing receives on, and this server's own listening endpoint, which is a query
that would make it answer itself forever. A source outside `server.allow_from`
is refused earlier still — see [Who may ask](#who-may-ask), which is the bound
on *whether* this server takes part in a reflection attack rather than on how
much one gets out of it.

Refusals are not charged to the budget, though the check sits right beside it.
The budget is kept per /24, so a denied source in the same /24 as an allowed one
would be spending its neighbour's: charging them would turn a narrowed allow
list into a way to have the clients beside it dropped. Nothing is sent to a
refused source, so there is nothing for a response budget to bound.

TCP, DoT and DoH are charged too, for the other half of what
a flood costs. Amplification is not their problem — a connection is established
before a query arrives on one, so the address is proven and nothing is reflected
— but the work behind an answer is the same wherever the query came from, and
that is the upstream round trips and the cache churn. All three pipeline: one
connection carries as many queries as the socket will take, and
`server.max_connections` bounds how many clients are here at once rather than how
fast one of them asks. Without the budget, a flood delivered over a handful of
long-lived connections is one the limiter never sees.

Two budgets per prefix, though, not one: datagrams are charged to one and
connections to the other, each getting `responses_per_second`, and neither can be
spent from the other side. The reason is that the budget is keyed on the query's
source address, and on a datagram that field is written by whoever sent it. Under
one shared budget, anybody able to send UDP could empty the budget of any prefix
they liked — a spoofed flood naming sources in a /24, above the configured rate,
keeps that /24's bucket empty for as long as it runs — and every genuine TCP, DoT
or DoH connection from that /24 would then have its first query refused and its
connection closed. Somebody who cannot receive a byte at the address, and who is
asking none of that network's questions, would be deciding what this server does
for the clients who actually live there, on a default configuration. It would also
empty the budget a slip's own advice sends a client to.

The cost of the separation is that a client willing to ask both ways can draw
twice `responses_per_second` — a factor of two on the work behind an answer, on a
figure you chose, and half of it only reachable over a completed handshake from an
address that is therefore real. That is the trade, taken deliberately; the
alternative was letting anyone with a raw socket switch off a stranger's TCP.

What differs besides the budget is the answer an over-budget query gets. `slip` is
a UDP mechanism — the TC bit tells a client to ask again over TCP, and a client
that is already there can do nothing with it — so on a connection everything over
the budget is refused: TCP and DoT are closed, and DoH is answered `429 Too Many
Requests` and then closed, HTTP having a way to say it. Over HTTP/2 the stream is
refused with a 429 and the connection stays, since one over-budget request is no
reason to take the requests in flight beside it down as well.

What the budget is spent on is a question, on every transport. Over HTTP that
means a request has to be one before it is charged: a scanner's 404, a
`.mobileconfig` download, a POST naming the wrong content type and a `dns=`
parameter that is not a DNS message reach no resolver, no cache and no upstream,
and charging them would let anything that can address the endpoint spend the
budget of the clients sharing its prefix.

A connection cut off this way is drained before it closes. A client that
pipelines has queries in flight that were never read when the budget ran out, and
closing a socket in that state resets it rather than ending it — which would have
the client's kernel throw away the answers that went out before the budget was
gone. So what is left unread is read and discarded first, briefly and up to a
bound, and then the connection ends.

The TCP retry a slip invites is charged to the stream budget, which is the one the
datagram flood cannot reach — so a client sent to TCP by a flood in its prefix
arrives at a budget that flood has not spent. It is still a budget: a client that
has emptied the stream side itself is refused there like anything else, and a slip
says the address is worth proving rather than reserving anything for the proof.

Both counters cover every transport. `elodin_rate_limited_total` counts what was
withheld wherever it came from; `elodin_rate_limit_slipped_total` counts truncated
answers, so it only ever moves for UDP.

`cookies.require` is the sharper instrument for an attack actually under way:
it makes a UDP client prove it can receive at the address it claims before any
answer is sent at all. See [DNS cookies](#dns-cookies).

### DNS cookies

```yaml
cookies:
  enabled: true          # answer clients that send a cookie
  require: false         # demand a valid one from UDP clients that send any
  upstream: true         # present a cookie of our own to plain upstreams
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
over TCP, DoT or DoH, are unaffected either way. It needs `enabled`, since what
it demands is a cookie this server issued; the two together are rejected at
startup rather than left looking like a protection that is on.

`secret` matters when more than one elodin answers on the same address: without
it each draws its own at startup and rejects the cookies the others handed out.
A single instance can leave it empty.

The client's cookie stops at elodin and is never forwarded upstream, whatever
either setting is on or off. It is a secret between that client and this server —
a stable identifier an upstream has no business seeing — and its server half was
minted here, so an upstream that implements cookies would read it as a forgery
and answer BADCOOKIE instead of the question.

`upstream` turns the same mechanism the other way round, and is also on by
default. elodin presents a cookie of its own to plain UDP and TCP upstreams:
a random client cookie per server, and the server cookie that server last issued.
A reply carrying a cookie that is not ours cannot have come from the server we
asked, so it is passed over and the socket keeps waiting for the genuine one —
which is the point, since answering a spoofing attempt with SERVFAIL would hand
the attacker most of what it was after. Once a server has issued a cookie, a
reply from it with the option left off is passed over the same way: a check an
attacker can decline to take is not a check at all, and RFC 7873 §5.3 has the
response discarded. A server that has never sent one is a server that does not
implement them, and the exchange carries on without. The cookie the upstream sends back is
removed before the answer goes anywhere near a client or the cache: it belongs
to that conversation and to no other. A BADCOOKIE reply carries a fresh server
cookie, so the query is asked once more with it.

Two things bound what that covers. Only queries that already carry an OPT record
get a cookie, since adding one would negotiate EDNS on behalf of a client that
never asked — with DNSSEC validation on, which is the default, every forwarded
query carries one. And DoT and DoH upstreams are left out, because a certificate
already establishes more than a cookie can.

| | client-facing | upstream |
|---|---|---|
| setting | `cookies.enabled` | `cookies.upstream` |
| default | on | on |
| secret | `cookies.secret`, or random at startup | random per upstream |
| server cookie | recomputed per query, nothing stored | learned and held per upstream |
| transports | UDP, TCP, DoT, DoH | UDP and TCP only |
| a cookie that does not check out | answered anyway, or BADCOOKIE with `require` | ignored, and the wait continues |
| a message with no cookie | answered, and given none back | accepted, unless that server has issued one before |

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
lookup with `192.168.1.1` — and the page is now allowed, by the browser's own
rules, to read the router's admin interface. Nothing was broken into: the
same-origin policy is keyed on a name, the attacker owns the name, and the
attacker also decides what it means. The victim's browser is the proxy and the
victim's LAN is the vantage point.

The browser cannot see this happening; it asked a resolver and believed the
answer. The resolver can, which is why this is a resolver's job and why every
comparable product does it — dnsmasq's `--stop-dns-rebind`, Unbound's
`private-address`, AdGuard Home's rebinding protection.

elodin checks the answer section of an upstream reply for addresses in loopback
(`127.0.0.0/8`, `::1`), the RFC 1918 ranges, link-local (`169.254.0.0/16`,
`fe80::/10`), IPv6 unique-local (`fc00::/7`), `0.0.0.0/8` and `::`. It reads A
and AAAA records and the `ipv4hint`/`ipv6hint` parameters of SVCB and HTTPS
records, which are addresses a browser connects to without ever asking for the A
record. `169.254.169.254` is worth naming on its own: it is the cloud instance
metadata endpoint, it answers unauthenticated to anything that can reach it, and
what it hands back is credentials. `0.0.0.0` is in the set for a similar reason
rather than as tidiness: browsers on Linux and macOS reach services bound to
`127.0.0.1` by connecting to `0.0.0.0`, which is what the "0.0.0.0 Day"
disclosure was about, so it is a working bypass and not merely an odd answer.

Beside an SVCB or HTTPS answer it reads the additional section too, since RFC
9460 section 5 has the client take the target's address from there without
issuing a second query. Everywhere else the additional section is left alone: it
is glue for names other than the one asked about, which a stub does not connect
to.

One offending record refuses the whole answer rather than being filtered out of
it, so a mixed answer cannot be used to sneak one through and the guard does not
have to be exhaustive over every way an address can be written into a message.

An answer elodin cannot decode is refused too, for those same five question
types. That was the way round the whole guard and it was free: the attacker owns
the authoritative server, so a truthful answer section carrying `192.168.1.1`
with an `ARCOUNT` of 100 and nothing behind it is rejected by the decoder, was
forwarded verbatim, and glibc's resolver — which only ever walks the answer
section — handed it to the browser. The cost of closing it is that a name whose
upstream emits something elodin's decoder rejects now returns NODATA for A and
AAAA where it used to be forwarded; such an answer was already not cacheable and
not re-encodable. Every other question type is forwarded exactly as before. In
the query log this one reads `outcome=blocked detail="unreadable"`, against
`detail="rebind"` for an answer that named a private address.
The client gets NODATA — NOERROR with an empty answer section, an SOA so it knows
how long to remember, and RFC 8914 extended error 15 saying why:

```
ts=… level=warn msg="refused an answer for rebind.attacker.example carrying the private address 192.168.1.1: a public name resolving into private space is how a DNS rebinding attack reaches a service on this network, so the client was told NODATA"
ts=… level=info msg="query client=192.168.1.20:41234 proto=udp qtype=A qname=\"rebind.attacker.example\" outcome=blocked detail=\"rebind\" ms=12.4"
```

NODATA rather than SERVFAIL, deliberately. A stub resolver configured with two
servers treats SERVFAIL as *this* server having failed and asks the other one,
which on a home network is the router — and the router answers `192.168.1.1`
quite happily. The refusal would route the attack around itself. NODATA is an
answer, so the stub stops. It is the same reasoning that has blocklist hits
answer NXDOMAIN rather than REFUSED.

The check runs before the answer is cached, which is the ordering the whole thing
rests on: cached first, the first client's private answer is stored and every
later client is served it without the check ever running again. The refusal is
not cached either — what elodin saw was one answer, not a property of the name.

Refusals are counted as `rebind=` in the stats line and as
`elodin_rebind_refused_total` on the metrics endpoint. The first since start is a
`warn` naming the address and both settings that would allow it; every one after
is `debug`, so that whoever is triggering it does not decide how much this server
writes to disk.

#### Why it is off by default, and why to turn it on

dnsmasq, AdGuard Home and Unbound all ship their version of this **off**, and
elodin follows them. The reason is not deference — it is who runs this. elodin is
a forwarder for a box on a LAN that every device points at, and that box is
commonly the one running **split horizon**: a public zone whose names answer with
a LAN address, an upstream that is the operator's own internal server, a homelab
whose `nas.example.com` is `192.168.1.50` by design. On by default, every one of
those names would become NODATA the moment the operator upgraded — not degraded,
gone, and looking exactly like a name that does not exist — for a configuration
that was never wrong. A security default that breaks working resolution for a
large share of the people it ships to is one they turn off in a hurry; off by
default, and turned on deliberately, is the honest arrangement.

This is a different trade from [DNSSEC validation](#dnssec), which *is* on by
default here. An upstream that cannot return DNSSEC records is a misconfiguration
to fix. A public name answering with a private address is, for this program's
audience, an ordinary and supported thing to be doing — so the two do not default
the same way.

**Turn it on if you are not running split horizon.** The failure it prevents is
silent — a page reaching your router's admin interface produces no line anywhere
— while the guard itself is loud: a `warn` at the first refusal naming the
address and both settings that would allow it, a `rebind=` counter, a query-log
line. It is one line:

```yaml
rebind:
  enabled: true
```

And if you *do* run split horizon, you can still turn it on: name the zones that
are allowed to answer with private addresses in `rebind.allow_domains`, described
below, which `--check` reads.

#### What turning it on makes unresolvable

- **Split horizon through an internal upstream.** A site whose upstream is its
  own DNS server, resolving `nas.corp.example` to an RFC 1918 address through the
  public name space, gets NODATA for every such name once the guard is on. This
  is the case `allow_domains` exists for; name the zones and they work again:

  ```yaml
  rebind:
    allow_domains: [corp.example, home.arpa]
  ```

  Each entry covers itself and everything below it, the way
  `--rebind-domain-ok=/corp.example/` does in dnsmasq — so write the zone rather
  than a wildcard, and a `*.corp.example` copied from [`rewrites`](#rewrites) is
  refused at load rather than kept as an entry that matches nothing. Matching is
  against the name that was asked for, not the owner name of the offending
  record, so a CNAME from an attacker's name into an exempt zone exempts nothing.

- **Names that legitimately resolve to loopback**, such as a development host
  pointed at `127.0.0.1` by a public zone. `allow_loopback: true` covers all of
  them at once; `allow_domains` covers the one you meant. Prefer the second:
  loopback is the address a rebinding attack most wants, because a service bound
  to `127.0.0.1` is the one its author most believed only local processes could
  reach, and so the one least likely to authenticate.

- **A chained sinkhole.** If elodin forwards to another filtering resolver that
  answers blocked names with `0.0.0.0` or `127.0.0.1` — a Pi-hole, or dnsmasq
  with `--address=/ads.example/0.0.0.0` — those answers become NODATA here. The
  name is blocked either way, so nothing an operator wanted stops resolving, but
  `rebind=` will climb in proportion to how much that upstream is filtering. **If
  you see `rebind=` rising, check whether your upstream sinkholes before
  concluding you are being attacked**: a counter that tracks your own ad blocking
  says nothing about an attacker. Moving the filtering into elodin's own
  [sink lists](#sink-lists) settles it, and `allow_loopback` settles the
  `127.0.0.1` half.

  `0.0.0.0` is not dropped from the set to make that counter tidier. It is a
  working bypass — see above — and leaving the most interesting target in the set
  open in order to keep a number clean is the wrong trade.

Four things that look like they would break and do not. `rewrites` need no
exemption: a rewritten name is answered out of the configuration long before
anything is forwarded, so `nas.home` pointing at `192.168.1.50` never reaches an
upstream and never reaches this check. Reverse lookups are unaffected — a PTR
answer is a name, not an address, and the RFC 6303 reverse zones are handled
separately (see [DNSSEC](#dnssec)). elodin's own blocking, whatever
`blocking.response` is set to, builds its answer locally rather than forwarding
for one — including `zeroip`, whose `0.0.0.0` and `::` are in the refused set but
never travel the path this check sits on. And `localhost.`, with everything under
it, may be answered with `127.0.0.1` or `::1` with nothing configured: RFC 6761
section 6.3 makes those the only answers that name can have, so a loopback answer
for it is legitimate by definition rather than by anybody's policy. Only as far
as loopback, though — `evil.localhost` answered with `192.168.1.1` gets no
latitude from that, since it is not an answer the RFC permits either.

That exemption is not what you meet first, though. With `special_use.enabled` at
its default, the table under [Names that are never
forwarded](#names-that-are-never-forwarded) answers everything below `localhost.`
before anything is forwarded, so the guard is never asked about those names at
all — `evil.localhost` comes back as `127.0.0.1` rather than as a refusal. The
exemption is what keeps `localhost.` resolvable in the one configuration where
that table is off, and is deliberately the guard's own rather than deferred to
it.

`enabled: false` is the default, so none of the above happens until you turn the
guard on; the same line turns it back off if you do.

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

### Names that are never forwarded

```yaml
special_use:
  enabled: true    # the table below
  onion: true      # onion.  (RFC 7686 section 2)
  local: false     # local.  (RFC 6762 section 22)
  test: false      # test.   (RFC 6761 section 6.2)
```

Three names are answered here rather than asked about, whatever `upstream.servers`
says:

| name | answer | why |
|---|---|---|
| `localhost.` and below | 127.0.0.1 for A, `::1` for AAAA, NODATA otherwise | RFC 6761 6.3. The only answer it is allowed to have |
| `onion.` and below | NXDOMAIN | RFC 7686 2, unless the upstream is Tor-aware |
| `invalid.` and below | NXDOMAIN | RFC 6761 6.4. It cannot exist |

`.onion` is the one this exists for. The query is the disclosure: forwarding it
tells the upstream operator — and anyone on the path to a plain-UDP upstream —
that somebody on this network is reaching for one specific hidden service, which
is what Tor was being used not to publish. `localhost.` is a correctness problem
rather than a privacy one: forwarded, the name resolves to whatever the upstream
says, which is a rebinding primitive given away for free.

**`local.` and `test.` are off by default**, though RFC 6762 and RFC 6761 ask for
the same handling. They are the two reserved names that networks really do serve
— an Active Directory domain under `.local` older than the reservation, an
internal `.test` zone that RFC 6761 explicitly permits — and answering them with
NXDOMAIN on an upgrade would take those hostnames away from a network that had
them. Turn them on if nothing here serves them; against a public upstream the
only thing that changes is that the NXDOMAIN arrives without the round trip and
without the hostname having left the building.

Note that such a site may not have working `.local` names in the first place.
With `dnssec.enabled` on — the default — the unsigned answer its upstream gives
is checked against a root that publishes a signed proof there is no `local.` to
delegate, and SERVFAIL is the likely verdict; the sites this default protects
are the ones running with validation off. If `.local` is SERVFAILing for you,
`local: true` at least turns that into a clean NXDOMAIN, and a `rewrites` rule
turns it into an answer.

A rewrite outranks all of this, since `rewrites` are matched first: a site that
knows what its own `.local` names resolve to can say so and keep that answer.
What a rewrite cannot do is send the query somewhere — there is no per-domain
upstream here — so a network whose router answers `.local` dynamically wants
`local: false`, which is the default.

There is one upstream for which `.onion` really is the right question to ask: a
local `tor` with `DNSPort` and `AutomapHostsOnResolve`, which answers those names
with mapped addresses. That setup wants `onion: false`, and keeps everything else
in the table. RFC 7686 2 addresses a caching server "where not explicitly adapted
to interoperate with Tor", so this is the adapted case the RFC leaves room for
rather than a departure from it. It is warned about at startup, since the setting
is a claim about the upstream and not about this resolver.

What that upstream answers is unsigned, and cannot be anything else: the root
publishes a signed proof that there is no `onion.` to delegate, so a validator
reads a mapped address under it as unsigned data inside the root zone and calls
it forgery. `onion: false` therefore also takes those names out of DNSSEC
validation, exactly as the RFC 6303 reverse zones are — they come back as
insecure, without the AD bit, rather than as SERVFAIL. Nothing else moves:
validation is untouched for every other name, and for `.onion` too unless the
key is written down.

`localhost.` and `invalid.` have no key of their own, and are not going to grow
one. Neither has a deployment that wants them forwarded — no upstream is
authoritative for either, and RFC 6761 6.3 and 6.4 leave a resolver nothing to
defer to about them — so a key would only ever be set by somebody working around
a symptom. `enabled: false` is still there for an operator who wants none of
this, and says so in the log.

`example.` is deliberately not in the table. It is reserved, but RFC 6761 6.5 is
the one entry in that document that asks for the opposite: caching servers should
*not* treat example names as special, `example.com` and its siblings being
delegated names that resolve.

These answers carry a 10-minute TTL and a synthesised SOA so a resolver
downstream can cache the negative, and they are not put in elodin's own cache —
they are built from a table already in memory, and an entry would only outlive
the reload meant to change it. They show in the query log as `outcome=local
detail="special-use"`.

### Metrics

```yaml
metrics:
  enabled: true
  address: "127.0.0.1"   # loopback by default
  port: 9153             # the port CoreDNS uses for the same thing
  path: /metrics
```

Off by default, and nothing is bound until it is turned on: a resolver that
opens a port nobody wrote in a file has widened an operator's exposure on their
behalf. The endpoint speaks plain HTTP and serves the Prometheus text exposition
format, version 0.0.4.

```
scrape_configs:
  - job_name: elodin
    static_configs:
      - targets: ["127.0.0.1:9153"]
```

**It is not on the path a query takes.** Every number it publishes is a counter
the resolver already maintains for the `msg=stats` line, read at scrape time
from the atomic it already lives in, so turning the endpoint on adds no work per
query and turning it off removes none. There is no latency histogram and no
per-name label, because both would mean measuring on the path being measured.
The isolation is structural rather than a promise: the endpoint has one thread
of its own, never queues work on either worker pool, never spawns a thread per
connection — so nothing reaching this port can spend the budget
`server.max_connections` keeps for clients — and answers one request per
connection before closing, so a scraper holding a socket open cannot keep the
next scrape out. Two scrapers at once are served one after the other.

It binds loopback by default rather than the `0.0.0.0` the DNS listeners use.
Nothing here is a secret in the way an answer is, but together these numbers
describe a network — how much it queries, how much of that is blocked, which
upstreams are reachable — and there is no authentication in front of them. A
bind beyond loopback is logged as a warning at startup, once.

| metric | type | what it is |
|---|---|---|
| `elodin_build_info{version}` | gauge | a constant 1, carrying the version as a label |
| `elodin_uptime_seconds` | gauge | seconds since this process finished starting |
| `elodin_queries_total` | counter | queries accepted, whatever became of them |
| `elodin_answers_total{outcome}` | counter | `forwarded`, `cached`, `blocked`, `rewritten`, `failed` — the same words the `msg=query` line uses, except that an answer the rebinding guard withheld is logged as `blocked` and counted in `elodin_rebind_refused_total` instead of here |
| `elodin_queries_dropped_total` | counter | turned away before any work: the backlog was full, or the source could not be answered |
| `elodin_queries_refused_total` | counter | turned away by `server.allow_from` |
| `elodin_connections_refused_total` | counter | refused because `server.max_connections` was full |
| `elodin_connections_failed_total` | counter | refused because the OS would not start a thread |
| `elodin_connections_active` / `_max` | gauge | connection threads in use, and what the limit allows |
| `elodin_rate_limited_total` | counter | queries the rate limiter withheld an answer from |
| `elodin_rate_limit_slipped_total` | counter | those answered truncated instead, to send a real client to TCP |
| `elodin_dnssec_answers_total{result}` | counter | `secure` and `bogus` |
| `elodin_rebind_refused_total` | counter | answers withheld because a public name was pointed into private address space |
| `elodin_cache_entries` / `_bytes` | gauge | what the cache holds, against `max_entries` and `max_bytes` |
| `elodin_cache_hits_total` / `_misses_total` / `_evictions_total` | counter | how it is doing |
| `elodin_cache_stale_total` | counter | expired answers served because no fresh one could be got, with `cache.serve_stale` on |
| `elodin_cache_withheld_total` | counter | answers the cache handed over that were then refused rather than served, so `_hits_total` counts them and the query log does not |
| `elodin_filter_rules{list}` | gauge | rules loaded, `block` and `allow` |
| `elodin_upstream_queries_total{upstream}` | counter | queries sent to each upstream, by its configured name |
| `elodin_upstream_failures_total{upstream}` | counter | exchanges that produced no usable answer |
| `elodin_upstream_latency_seconds_total{upstream}` | counter | cumulative round-trip time; divide by the query counter under `rate()` for the mean over a window |
| `elodin_upstream_up{upstream}` | gauge | 0 while an upstream is in its failure cooldown |
| `elodin_pool_workers{pool}` / `elodin_pool_pending{pool}` | gauge | the `query` and `upstream` pools; `pending` that does not return to zero is `server.workers` set too low |
| `process_cpu_seconds_total` | counter | user plus system CPU |
| `process_resident_memory_bytes` / `_virtual_memory_bytes` | gauge | from `/proc/self/stat` |
| `process_threads`, `process_open_fds`, `process_max_fds` | gauge | thread and descriptor counts |
| `process_start_time_seconds` | gauge | when this process began serving |

The `process_` family carries the names every Prometheus client library uses for
these, deliberately: a dashboard or an alert written against a Go or a Python
service works here without being told it is looking at something else.

`elodin_answers_total` does not sum to `elodin_queries_total`. A query the
backlog or the allow list turned away never reached an outcome — that is
`dropped` and `refused` — and one answered from a local zone is not counted
apart from the rest.

Useful starting points:

```promql
sum(rate(elodin_queries_total[5m]))
sum by (outcome) (rate(elodin_answers_total[5m]))
rate(elodin_cache_hits_total[5m]) / rate(elodin_queries_total[5m])
rate(elodin_upstream_latency_seconds_total[5m]) / rate(elodin_upstream_queries_total[5m])
min by (upstream) (elodin_upstream_up) == 0
```

A Grafana dashboard over those metrics is in
[`examples/grafana-dashboard.json`](examples/grafana-dashboard.json) — import it
under **Dashboards → New → Import**. It asks for a Prometheus data source and
picks up `job` and `instance` from `elodin_build_info`, so it works against one
instance or a fleet without editing. Five rows: an overview of headline rates,
queries by outcome and by what turned them away, the cache, per-upstream traffic
and health, and the process against its limits. Restarts are annotated from
`process_start_time_seconds`.

## What is implemented

Queries of any type are answered: A, AAAA, CNAME, MX, TXT, SRV, SOA, NS, PTR,
CAA, SVCB/HTTPS, DS, DNSKEY, RRSIG and everything else. Types the codec does not
model natively are carried through as opaque RDATA per RFC 3597, and forwarded
answers are passed back byte for byte, so DNSSEC records survive untouched. With
validation on, an answer for a client that did not ask for DNSSEC records is
rebuilt without them; every other answer still goes back verbatim, bar the two
bytes of payload size in the OPT record — see [How large a UDP answer may
be](#how-large-a-udp-answer-may-be).

Also handled: EDNS0 (the client's OPT record is forwarded upstream so payload
sizes are negotiated end to end, minus its cookie, which stops here; over UDP the
OPT that comes back to the client carries *this* server's payload size, per RFC
6891 section 6.2.4, while on the stream transports it is passed through as it
stands — see [How large a UDP answer may
be](#how-large-a-udp-answer-may-be)), DNS
cookies in both directions (RFC 7873, RFC 9018) — answered for clients, and
presented to plain upstreams with the reply checked against what we sent —
truncation with the TC bit and the UDP→TCP retry, `version.bind`/`hostname.bind`
in the CHAOS class, local NODATA answers for `resolver.arpa` (RFC 9462 section
6.1), refusal of zone-transfer requests, and the reserved names of RFC 6761 and
RFC 7686 answered here instead of being forwarded — see [Names that are never
forwarded](#names-that-are-never-forwarded).

The cache stores upstream answers as untouched wire bytes plus the offsets of
their TTL fields, and rewrites those TTLs in place on each hit. That keeps the
original name compression intact and avoids a decode/encode round trip on the
hot path. It is bounded by `cache.max_bytes` as well as `cache.max_entries`,
because an entry's size is decided by whoever answered the query: see
[Resource use](#resource-use).

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
has to reconnect. Either way the first refusal since start is a `warn` naming
the setting and every one after it is `debug` — the same shape as an
`allow_from` refusal, and for the same reason: how many of them there are is
decided by whoever is opening the connections.

```
ts=… level=warn msg="tcp: refusing a connection, server.max_connections (512) is reached"
ts=… level=warn msg="raise server.max_connections if this server should hold more clients at once; these are counted as conn_refused= in the stats line, and further ones are logged at debug level"
```

The counting does not stop with the logging: every one of them is a
`conn_refused=` in the stats line, so a server that has been sitting at its limit
since long after that `warn` scrolled away still says so. It is kept apart from
`refused=`, which is the allow list turning a source away — this is a client
elodin would serve and has no room for, and the setting to reach for is a
different one.

A connection can also be refused *below* the limit, when the OS will not give
the process another thread — `RLIMIT_NPROC`, a cgroup `pids.max`, or memory.
Raising `max_connections` there cannot help and would make it worse, so it is
counted and named separately:

```
ts=… level=warn msg="tcp: refusing a connection, the OS would not start a thread for it - this is below server.max_connections (512), so raising that will not help"
ts=… level=warn msg="check the process thread and memory limits (RLIMIT_NPROC, cgroup pids.max); these are counted as conn_failed= in the stats line, and further ones are logged at debug level"
```

The number that governs sizing is the sustained cache-miss row. A worker thread is occupied for
the whole of an upstream round trip, so

```
sustained cache-miss throughput  ≈  server.workers / upstream_rtt
```

which is about 50 qps per worker against a 20 ms upstream, so a 128-worker pool
carries roughly 6,000 misses per second. Two consequences worth knowing:

- **Every query shares that pool**, so running short on workers delays cache
  hits as much as misses. At a pool of 8 workers, answers that take 60 µs to
  produce from cache were coming back after 413 ms because the workers were all
  parked on upstream I/O.
- **Memory scales with workers**, at roughly 0.3 MB of scratch arena each — and
  it is a floor rather than a peak. A worker holds its arena from its first
  query onward, because `free_all` on Odin's temp allocator keeps and zeroes the
  first block instead of returning it.

That second point is why `server.workers` and `server.upstream_workers` are not
fixed numbers any more. Left unset — which is what `0` means, and what the
shipped configuration says — they are worked out at startup from the machine:

```
workers           = clamp(usable_cpus * 4, 16, 128), lowered if the threads
                    that implies would take more than 1/32 of usable memory
upstream_workers  = workers / 2
```

"Usable" is what this process can have rather than what the box holds: the CPU
affinity mask, and a cgroup CPU or memory limit where there is one, so a
container or a systemd unit with `CPUQuota=`/`MemoryMax=` sizes itself for what
it was given. A two-core home box lands on 16 workers and 8 racers rather than
the 128 and 64 every installation used to get, and a 32-core resolver still gets
those 128. Whatever the machine says, a number in the configuration wins — and
the two can be set independently, since an unset `upstream_workers` follows a
configured `workers`.

The numbers it settled on, and what it read them from, are logged on the second
line after startup and printed by `--check`:

```
ts=… level=info msg=sizing workers=16 upstream_workers=8 max_pending=128 origin="derived from 4 usable CPUs and 7.7 GiB"
```

```console
$ elodin --check
/etc/elodin/elodin.yaml is valid: 2 upstreams, 1 blocklists, 0 rewrites
  workers=16 upstream_workers=8 max_pending=128 (derived from 4 usable CPUs and 7.7 GiB)
  answering queries from 127.0.0.0/8, ::1/128; every other source is refused
```

Past capacity the server drops queries rather than queueing them
(`server.max_pending`, derived as `workers * 8`). With 6,000 clients all asking
for cache misses at once — a thousandfold more demand than a 128-worker pool can
carry against a 20 ms upstream — that is 4,900 qps served at a bounded 166 ms,
and about 25,000 queries dropped over twenty seconds. Given an effectively
unbounded queue the same load serves a comparable 5,900 qps but at 978 ms,
because the backlog rather than the work becomes the latency, and every client
waits behind queries whose own clients have already given up. A dropped query
gets no answer at all, so a client sees it as a timeout and retries, which is
the failure DNS is built for. A DoH client over HTTP/2 is told instead: its
stream is the other path that queues, and past the limit it is answered 503
rather than left to wait on a connection that is already open.

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
| worker scratch arenas | ~0.26 MB per worker (34 MB at a 128-worker pool) |
| blocklists | ~129 B per rule (31 MB for 250,000 rules) |
| answer cache | ~463 B per entry (4 MB at the default 10,000) |
| **realistic total under load** | **154 MB** with 250,000 rules and 180,000 cached answers |

Each row but the first is a difference between two runs that vary in one thing,
so the cache is not charged for the worker arenas that the same load brings up.
The worker row is measured against a pinned 128-worker pool, which the
benchmarks name explicitly rather than derive; a machine that derives 16 pays
4 MB there instead of 34, and the total below moves with it.

The cache row is a *typical* entry, not a bound. An entry holds the response as
it arrived — up to 64 KiB, since a query over TCP, DoT or DoH is answered with
the whole message rather than a 512-byte UDP one — plus an offset and a TTL for
each of its records, which for a response packed with minimal records is about
twice the wire size again. So `cache.max_entries` alone would stand for
something near 640 MB at its default, reachable by anyone who can serve maximal
answers from a zone they control and walk elodin through enough distinct names.
`cache.max_bytes` is the bound that holds: 64 MiB by default, evicting from the
least recently used end whenever either bound is passed. `cache_bytes=` in the
five-minute stats line reports what is held against it.

Disk is negligible: a binary under a megabyte, and a blocklist cache the size of
the lists themselves (6.5 MB for two large ones). Nothing is written in steady
state — with one exception.

That exception is `log.queries`, which writes 32 MB/s at 185k qps, about 183
bytes per query. It wants rotation. The line was 104 bytes before it became
logfmt; the keys are most of the difference, and they are disk rather than work.
The committed run predates logfmt, so its own logging section still reports the
104-byte line rather than this one — re-take it with `mise run bench -only
logging` before quoting either figure against a change.

The `race` strategy is the other setting with a real price: it multiplies
upstream traffic by the number of servers.

## Known limitations

- DNSSEC validation is **on by default**, and where a distribution's crypto
  policy forbids SHA-1 signatures the two RSA/SHA-1 algorithms degrade to
  insecure rather than validating. See the DNSSEC section above.
- [Rebinding protection](#dns-rebinding-protection) runs only for A, AAAA, ANY,
  SVCB and HTTPS questions — the ones a browser can be made to ask. Addresses in
  the additional section are left alone unless the answer carried an SVCB or
  HTTPS record: ordinarily they are glue for names other than the one asked
  about, a stub does not resolve a hostname out of them, and elodin stores and
  serves a response as a whole under the question's key, so there is no way to
  retrieve one on its own. SVCB is the exception because RFC 9460 section 5 has
  the client use them directly. An answer the codec cannot decode is refused for
  those five question types rather than forwarded unchecked — see the section
  above — and forwarded as before for every other type.
- **Connection-oriented transports get a thread per connection**, capped for
  TCP, DoT and DoH together by `server.max_connections` (512). That is fine for
  clients that hold a connection open and pipeline over it, but it does not suit
  tens of thousands of concurrent connections. UDP is the exception: one reader
  thread and no per-client state, bounded instead by the per-prefix datagram
  budget described under [Rate limiting](#rate-limiting).
- Upstream I/O is synchronous, so concurrency is bounded by thread count rather
  than by in-flight queries. The h2 upstream client is the exception — its
  queries multiplex onto one connection — but a worker is still held for the
  round trip. Async upstream I/O, or several UDP reader threads behind
  `SO_REUSEPORT`, would lift both this and the item above; neither is needed at
  the scale measured in the previous section. A second UDP reader is no longer
  blocked on the rate limiter: its bucket table is behind a mutex, which every
  stream connection's thread already takes for the queries it reads.
- **DNS cookies do not cover every query.** Only queries that already carry an
  OPT record are given one on the way upstream, so a non-EDNS client behind
  elodin gets no cookie protection unless DNSSEC validation is on — which it is
  by default, and which puts an OPT record on every forwarded query. Cookie
  secrets, both the client-facing one and the client cookies held per upstream,
  are drawn once at startup and never rotated: restarting costs each client and
  each upstream one extra round trip.
- **elodin does not advertise its own DoT or DoH endpoints over DDR.** Queries
  for `resolver.arpa` are answered NODATA rather than forwarded, which keeps
  clients on this server, but nothing designates its encrypted listeners
  automatically: a client that should use them is pointed at them by
  configuration, by the [Apple mobileconfig
  profile](#apple-devices-ios-ipados-macos), or by a `rewrites` rule.
- No per-client rules, no query log database, no web or API surface. Statistics
  go to the log every five minutes, and to a Prometheus endpoint when
  [`metrics.enabled`](#metrics) is set — but that endpoint is counters only,
  with no latency histogram and no per-name label, for the reason given there.
- Configuration is read once at startup, with one exception: `SIGHUP` reloads
  the DoT/DoH certificates (see [Reloading](#reloading)). Nothing else -
  listener addresses, the upstream set, blocking - can be changed without a
  restart yet.

## Layout

```
src/main/      entry point: arguments, startup order, signals, maintenance loop
src/dns/       message codec: names, compression, records, EDNS, TTL patching
src/yaml/      YAML subset parser and typed accessors
src/config/    configuration schema, loading and validation
src/filter/    sink-list matching and list-format parsers
src/cache/     LRU answer cache
src/dnssec/    validation: canonical form, signatures, NSEC/NSEC3, chain of trust
src/upstream/  transports (UDP/TCP/DoT/DoH), pooling, strategies, cookies, HTTP/1.1 and h2 clients
src/server/    resolver, listeners, DoH endpoint, cookies, list refresh
src/h2/        HTTP/2 framing, HPACK, and the server connection state machine
src/tlsx/      OpenSSL bindings and a small TLS wrapper
src/pool/      worker pool
src/logx/      logging, in logfmt
src/metrics/   Prometheus exposition format, and process figures out of /proc
src/privdrop/  giving up root once the listeners hold their ports
src/itest/     integration suite: harness, mock upstreams (DNS, HTTP, DoH/h2), clients, fixtures
src/fuzz/      libFuzzer targets for the DNS, HPACK and YAML parsers, and their shared arena
testdata/      fuzz corpus and dictionary, committed so a found crash stays found
bench/         benchmark harness and DNSSEC survey, in Go, with committed results
examples/      the shipped configuration, a development one, and a Grafana dashboard
packaging/     systemd unit and the .deb build script
```

Two worker pools run underneath: one answering queries, one dedicated to racing
upstreams. They are kept separate on purpose — a race job is submitted *by* a
query handler and waited on by it, so sharing a pool could deadlock once every
worker was blocked on jobs nobody was left to run. TCP, DoT and DoH connections
get a thread each instead, capped by `server.max_connections`.

## Testing

Two layers, both run by `mise run verify`, and a third — fuzzing — that runs on
its own schedule. A fourth, `mise run bench`, measures rather than asserts: it
is where every number in [Capacity](#capacity) comes from, and it is documented
in [`bench/README.md`](bench/README.md).

**Unit tests** (`mise run test`, 433 cases) cover the message codec — round trips
for every modelled RDATA type, compression, truncation, EDNS, pointer loops,
hostile record counts — plus the YAML parser, configuration loading, list
parsing and matching, the cache, and the HTTP/2 codec — the HPACK cases run the
worked examples from RFC 7541 appendix C, so the codec is checked against the
specification's own vectors rather than against itself.

They run per package, so a failure names one: `dns` 47, `yaml` 34, `config` 55,
`filter` 8, `logx` 1, `metrics` 9, `privdrop` 9, `cache` 16, `dnssec` 39,
`tlsx` 5, `upstream` 31, `h2` 69, `server` 110. Much of `tlsx`, `upstream`, `h2`
and `server` is what the suite grew around bugs that were found some other way
and had to stay found — the HTTP reader's framing and body limits, the TLS
handshake retry, the HTTP/2 stream table under RST_STREAM, and the DoH request
parser read against an allocator that scribbles over what it releases.

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

**Integration tests** (`mise run itest`, 191 cases, ~50s) start the built binary
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
| logging | every line a real start-to-shutdown wrote parses as logfmt, a query is fields rather than a sentence, and a name a client chose cannot forge a field of its own |
| wire format | all 23 captured fixtures replayed and compared byte for byte, EDNS forwarding, 0x20 case preservation, truncation and the TC bit, FORMERR / NOTIMP / silent-drop handling |
| transaction ids | a forwarded query does not carry the client's id, over enough forwards that a fixed or counting one could not pass by chance (RFC 5452) |
| who may ask | a source outside `allow_from` gets nothing over UDP and no connection over TCP, one inside is answered, an empty list serves everybody, the shipped default answers loopback, the first refusal is logged once and names the setting, an unparseable entry fails `--check` |
| UDP answer size | the default holds a client asking for 4096 to 1232, a raised ceiling sends the whole answer, the ceiling does not apply over TCP, the answer's own OPT reports the ceiling rather than the client's figure, and a client's own small buffer is not blamed on the setting |
| listeners | UDP, TCP (single and pipelined), DoT, DoH POST and GET, keep-alive, two pipelined requests in one segment, 404 / 405 / 415 / 400 / 505, a request line that is not three tokens and a mandatory single `Host`, a refusal read back over a body the server never read |
| Apple profile | the `.mobileconfig` downloaded end to end over HTTP/1.1 and HTTP/2, its `ServerURL` built from the request host / `:authority`, the managed-DNS payload and Apple content type, GET-only |
| DoH over HTTP/2 | ALPN selection, POST and GET, Huffman-coded headers, CONTINUATION, a dynamic table size update at and past the advertised limit, concurrent streams proved parallel by timing, flow control with a tiny window, DATA splitting for a 27 KiB answer, PING, RST_STREAM, malformed requests reset with PROTOCOL_ERROR while the connection carries on, error statuses, HTTP/1.1 fallback |
| DoH upstreams | a query resolved over an h2 upstream, one connection multiplexed across queries rather than reopened, fallback to HTTP/1.1 when the upstream does not offer h2 |
| blocking | all five response modes, hosts vs domains vs adblock semantics, allow precedence, wildcards, modifiers, dnsmasq syntax, unusable rules, case folding |
| rewrites | A, AAAA, CNAME, wildcard scope, `block`, NODATA for unmatched types |
| rate limiting | a flood from one source answered in full with the limiter off and cut to the budget with it on, truncated answers over the budget, the bytes one address can be made to receive compared between the two, the same flood pipelined down one TCP connection cut to its budget with nothing truncated, and a TCP client still answered after a datagram flood has spent the prefix's UDP budget |
| cache | hits avoid the upstream, TTL countdown, cross-transport reuse, question re-casing, negative caching, key separation by type |
| upstreams | failover, round-robin, race, health cooldown, TCP and DoT clients, connection pooling, UDP→TCP retry, total outage → SERVFAIL |
| blocklist downloads | two lists fetched over HTTP and both applied, written to the cache directory, reused on restart without re-fetching, unwritable cache directory degrades to a warning |
| DNSSEC | an answer with no chain of trust is refused rather than served, the forwarded query carries DO and CD, a CD client is served unvalidated, the refusal carries an extended DNS error, and none of it happens unless it is configured |
| DNS cookies | a client cookie comes back with a server cookie behind it and works again, the client's own cookie never reaches the upstream and the upstream's never reaches the client, an impossible length is FORMERR, a query with no EDNS goes upstream without one, upstream BADCOOKIE is retried invisibly, each side turns off independently, and `require` turns an unproven UDP client away while leaving cookieless and TCP clients alone |
| certificate reload | the listener serves what it started with, `SIGHUP` swaps in a certificate renewed on disk, and a bad one on disk leaves the working one in place |
| metrics | no port is open unless the configuration asks for one, a scrape reports the queries that actually went through and the process figures out of `/proc`, the configured path is the only one served, and anything else is a 404 or a 405 |

`src/itest/fixtures.odin` holds real DNS responses captured from a public
resolver, including compression pointers, DNSSEC records and types the codec
does not model. The mock replays them verbatim and the suite compares the bytes
the client receives against the bytes the upstream sent. Generating the fixtures
with elodin's own encoder instead would let a codec bug agree with itself and
still pass.

**Fuzzing** covers the three parsers that read bytes somebody else chose: the
DNS wire codec (`dns.decode_message`, plus `dns.truncated_response`, which the
UDP read loop reaches for a rate-limited query without decoding it first), the
HPACK decoder, and the YAML parser — the last of which reads not only the
configuration but every blocklist downloaded at runtime. Odin has no
`-fsanitize=fuzzer` of its own, so `mise run fuzz` emits LLVM IR for each target
and has clang instrument and link it into a libFuzzer binary at `bin/fuzz_*`,
with ASan on and bounds checks still in.

Running one is open-ended, so it is not part of `mise run verify`.
`.github/workflows/fuzz.yml` does it nightly instead, twenty minutes per target
against a corpus cached between runs so coverage compounds rather than
restarting each night, and `workflow_dispatch` runs it on demand after a parser
is touched. What CI runs on every change is the bounded half:
`mise run fuzz-regression` replays `testdata/fuzz-corpus/` — eighteen seeds and
one committed crash — through each target once, generating nothing new, so a
crash fuzzing has already found stays found instead of only living in whoever's
corpus turned it up.

**Against live DNS**, because none of the layers above can prove the absence of
false failures — they work from fixtures and generated input, so they can show
that a forged answer is refused and cannot show that validation leaves working
names working. A validator that refused everything would pass the entire suite.

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

Interoperability with a foreign HTTP/2 implementation is checked by hand with
curl (which uses nghttp2): `curl --http2 -k -H 'content-type:
application/dns-message' --data-binary @query.bin https://127.0.0.1:443/dns-query`.

## License

MIT — see [LICENSE](LICENSE). Release tarballs and the .deb carry it too, the
latter at `/usr/share/doc/elodin/copyright`.
