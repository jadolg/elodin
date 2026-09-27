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
- Reserved names answered here rather than forwarded: `localhost`, `.invalid`,
  `.onion` and the private reverse zones by default, `.local`, `.test` and
  `home.arpa` on request
- Client allow list (local networks only by default), per-prefix response rate
  limiting, a ceiling on UDP answer size, DNS cookies in both directions, and
  EDNS(0) padding on DoT and DoH — all on by default
- DNS rebinding protection, off by default so split horizon keeps working
- A `.mobileconfig` profile that points Apple devices at the DoH endpoint
- A Prometheus endpoint, off by default
- Ships as a systemd service or a `.deb`, with optional system-resolver takeover

[`examples/elodin.yaml`](examples/elodin.yaml) is the
annotated configuration reference, and [`examples/`](examples/) carries a
configuration per deployment — see [Example configurations](docs/examples.md).
Everything else is under [`docs/`](docs/).

## Quick start

You need [mise](https://mise.jdx.dev), which pins the toolchain, and OpenSSL 3.x
with headers (`openssl-devel` / `libssl-dev`).

```sh
mise trust && mise install
mise run build            # bin/elodin
mise run test             # unit tests
```

[Developing elodin](docs/development.md) has the rest of the tasks, the layout of
the source and how it is tested.

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
[Privileges](docs/install.md#privileges). If the port is already taken it is usually the system
resolver (`sudo systemctl stop systemd-resolved`); elodin says as much when a
bind fails. A cache directory it cannot write is a warning, not an error: the
lists still apply, they just have to be fetched again next start.

The listeners bind `0.0.0.0`, but only the local networks are served by default
— see [Who may ask](docs/access-control.md#who-may-ask). A minimal configuration:

```yaml
upstream:
  servers:
    - tls://1.1.1.1:853#cloudflare-dns.com
blocking:
  lists:
    - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
```


To install it as a systemd service or from a `.deb` — which can also take over
as the system resolver — see [Installing and running](docs/install.md).

## Documentation

| page | what it covers |
|---|---|
| [Installing and running](docs/install.md) | the systemd unit, the `.deb` and resolver takeover, dropping privileges, signals |
| [Example configurations](docs/examples.md) | which settings a loopback, LAN, small-device, public or container deployment changes, and why |
| [Logs](docs/logging.md) | the logfmt format, the stats line, the query log |
| [Upstreams](docs/upstreams.md) | strategies, timeouts, failover, bootstrap, and per-domain routes |
| [Sink lists](docs/blocking.md) | list formats, allow rules, CNAME inspection |
| [Cache](docs/cache.md) | bounds, TTL handling, coalescing, serve-stale |
| [DNS-over-HTTPS](docs/doh.md) | the DoH endpoint and the Apple `.mobileconfig` profile |
| [DNSSEC](docs/dnssec.md) | validation, its bounds, trust anchors, names served insecure |
| [Who may ask](docs/access-control.md) | the client allow list and the RD bit |
| [Rate limiting and answer size](docs/rate-limiting.md) | the UDP answer ceiling, per-prefix budgets, overrides |
| [Connections and datagrams](docs/connections.md) | the per-client connection share, UDP readers |
| [DNS cookies, padding and keepalive](docs/edns.md) | the EDNS options elodin speaks |
| [DNS rebinding protection](docs/rebinding.md) | the guard, and why it is off by default |
| [Rewrites](docs/rewrites.md) | local answers of every type, and the PTRs they imply |
| [Reserved names](docs/reserved-names.md) | `localhost`, `.onion`, `home.arpa`, the private reverse zones |
| [Metrics](docs/metrics.md) | the Prometheus endpoint and the Grafana dashboard |
| [Running a public resolver](docs/public-resolver.md) | the checklist for `allow_from: []`, and the packet filter in front |
| [Sizing](docs/sizing.md) | worker counts, memory, transports, what the benchmarks say |
| [What is implemented, and what is not](docs/protocol-support.md) | protocol coverage and known limitations |

The reasoning behind each default lives in the source beside the code it governs
— `src/config/config.odin` for the settings, and the feature's own package for
the rest.

## License

MIT — see [LICENSE](LICENSE). Release tarballs and the .deb carry it too, the
latter at `/usr/share/doc/elodin/copyright`.
