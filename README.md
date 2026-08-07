# elodin

A filtering DNS forwarder in [Odin](https://odin-lang.org), in the spirit of
Pi-hole and AdGuard Home, minus the web interface. One binary, one YAML file.

- Serves plain DNS (UDP + TCP), DNS-over-TLS and DNS-over-HTTPS (HTTP/2 and HTTP/1.1)
- Forwards to plain, TCP, DoT and DoH upstreams
- Three upstream strategies: failover, round-robin and race
- Sink lists in hosts, plain-domain and adblock syntax, with allowlists
- Answer cache with negative caching and optional stale serving
- Response rate limiting per client prefix on UDP, on by default (see `server.rate_limit`)
- Client allow list restricting who may query, defaulting to local networks only
- A ceiling on UDP answer size to bound reflection amplification, on by default
- Local rewrites (A, AAAA, CNAME, or "answer as if blocked")
- DNSSEC validation against the root trust anchors, on by default
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
unit file and the example configuration, and a `.deb` of the same binary for
each architecture. Both are built natively, on a runner of the architecture they
target, because elodin binds the system libssl and libcrypto and
cross-compiling would mean carrying a sysroot for each. CI runs `mise run check`
once and `mise run test` and `mise run itest` on both architectures, on every
push and pull request.

### From a .deb

```sh
sudo apt install ./elodin_0.2.0-1_amd64.deb
```

The binary lands at `/usr/bin/elodin`, the unit at
`/usr/lib/systemd/system/elodin.service`, and `examples/elodin.yaml` at
`/etc/elodin/elodin.yaml` as a conffile — dpkg keeps your edits across upgrades
and asks before replacing them. `apt purge` removes the configuration, the
blocklist cache and the state directory.

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
ts=2026-08-07T09:12:33Z level=info msg=ready strategy=Round_Robin upstreams=2 cache=true blocking=true dnssec=true
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

There is no metrics endpoint. Statistics go to the log every five minutes, as
`msg=stats` — `queries`, `blocked`, `cached`, `forwarded`, `failed`, `dropped`,
`refused`, `conn_refused`, `conn_failed`, `limited`, `truncated`, `secure` and
`bogus`, plus `cache_entries`, `cache_bytes`, `cache_hits`, `cache_misses` and
`cache_evictions` — and `log.queries` adds one `msg=query` line per query, at
the cost noted under [Resource use](#resource-use).

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

There is no setting for this; it is not a policy an operator tunes, only a bit
a client sends. The RA bit follows RD back on every answer this server builds
itself — a refusal, a CHAOS reply, a blocked or rewritten one — so RA says
whether *this* answer had recursion behind it, not whether elodin offers the
service in general. A cached or forwarded answer is the one exception: its OPT
and flags are the upstream's own, RA included, passed through rather than
rebuilt — see [UDP payload size](#how-large-a-udp-answer-may-be) for the same
rule applied to the OPT record.

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
top of whatever the client asked for. It is also what the per-prefix budget
under [Rate limiting](#rate-limiting) is denominated in — 500 responses a second
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
    responses_per_second: 500     # per client prefix: /24 for IPv4, /64 for IPv6
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
16,384 buckets — half a megabyte, allocated once — so the limiter is not itself
somewhere to put pressure, and which prefixes share a bucket is decided by a key
drawn at startup rather than by anything an attacker can work out.

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

TCP, DoT and DoH are not rate limited. A connection is established before a
query arrives on one, so the address is already proven and there is nothing to
reflect off. What bounds them is `server.allow_from` (see [Who may
ask](#who-may-ask)), which refuses the connection at accept time, and
`server.max_connections`, which caps how many connections at once — there is no
per-client query budget for the stream transports to tune.

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
answers are passed back byte for byte, so DNSSEC records survive untouched. With
validation on, an answer for a client that did not ask for DNSSEC records is
rebuilt without them; every other answer still goes back verbatim, bar the two
bytes of payload size described below.

Also handled: EDNS0 (the client's OPT record is forwarded upstream so payload
sizes are negotiated end to end, minus its cookie, which stops here; over UDP the
OPT that comes back to the client carries *this* server's payload size, per RFC
6891 section 6.2.4, while on the stream transports it is passed through as it
stands — see [How large a UDP answer may
be](#how-large-a-udp-answer-may-be)), DNS
cookies in both directions (RFC 7873, RFC 9018) — answered for clients, and
presented to plain upstreams with the reply checked against what we sent —
truncation with the TC bit and the UDP→TCP retry, `version.bind`/`hostname.bind`
in the CHAOS class, and refusal of zone-transfer requests.

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

Disk is negligible: an 840 KB binary, and a blocklist cache the size of the
lists themselves (6.5 MB for two large ones). Nothing is written in steady
state — with one exception.

That exception is `log.queries`, which writes 32 MB/s at 185k qps, about 183
bytes per query. It wants rotation. The line was 104 bytes before it became
logfmt; the keys are most of the difference, and they are disk rather than work.

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
  thread and no per-client state, bounded instead by the per-prefix response
  budget described under [Rate limiting](#rate-limiting).
- Upstream I/O is synchronous, so concurrency is bounded by thread count rather
  than by in-flight queries. The h2 upstream client is the exception — its
  queries multiplex onto one connection — but a worker is still held for the
  round trip. Async upstream I/O, or several UDP reader threads behind
  `SO_REUSEPORT`, would lift both this and the item above; neither is needed at
  the scale measured in the previous section. A second UDP reader would have to
  lock or shard the rate limiter's bucket table first — it is unlocked because
  there is one reader, and a debug build asserts that rather than leaving it as
  a comment for the change to quietly break.
- **DNS cookies do not cover every query.** Only queries that already carry an
  OPT record are given one on the way upstream, so a non-EDNS client behind
  elodin gets no cookie protection unless DNSSEC validation is on — which it is
  by default, and which puts an OPT record on every forwarded query. Cookie
  secrets, both the client-facing one and the client cookies held per upstream,
  are drawn once at startup and never rotated: restarting costs each client and
  each upstream one extra round trip.
- No per-client rules, no query log database, no web or API surface. Statistics
  go to the log every five minutes; there is no metrics endpoint to scrape.
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
src/privdrop/  giving up root once the listeners hold their ports
src/itest/     integration suite: harness, mock upstreams (DNS, HTTP, DoH/h2), clients, fixtures
bench/         benchmark harness and DNSSEC survey, in Go, with committed results
packaging/     systemd unit and the .deb build script
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
| DoH over HTTP/2 | ALPN selection, POST and GET, Huffman-coded headers, CONTINUATION, a dynamic table size update at and past the advertised limit, concurrent streams proved parallel by timing, flow control with a tiny window, DATA splitting for a 27 KiB answer, PING, RST_STREAM, error statuses, HTTP/1.1 fallback |
| DoH upstreams | a query resolved over an h2 upstream, one connection multiplexed across queries rather than reopened, fallback to HTTP/1.1 when the upstream does not offer h2 |
| blocking | all five response modes, hosts vs domains vs adblock semantics, allow precedence, wildcards, modifiers, dnsmasq syntax, unusable rules, case folding |
| rewrites | A, AAAA, CNAME, wildcard scope, `block`, NODATA for unmatched types |
| rate limiting | a flood from one source answered in full with the limiter off and cut to the budget with it on, truncated answers over the budget, and the bytes one address can be made to receive compared between the two |
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

Interoperability with a foreign HTTP/2 implementation is checked by hand with
curl (which uses nghttp2): `curl --http2 -k -H 'content-type:
application/dns-message' --data-binary @query.bin https://127.0.0.1:443/dns-query`.

## License

MIT — see [LICENSE](LICENSE). Release tarballs and the .deb carry it too, the
latter at `/usr/share/doc/elodin/copyright`.
