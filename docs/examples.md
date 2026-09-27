# Example configurations

`examples/elodin.yaml` is the annotated reference: every setting, with its
default and the reasoning behind it. The files beside it are not variations on
it but answers to a question it cannot answer — *which* settings a particular
deployment should change, and why. Each one writes out the settings that
deployment cares about, and says in a comment why; anything it leaves out is the
shipped default.

| file | deployment |
|---|---|
| [`local-only.yaml`](../examples/local-only.yaml) | one machine resolving for itself, bound to loopback |
| [`lan.yaml`](../examples/lan.yaml) | the resolver a home or small-office network points at |
| [`small-device.yaml`](../examples/small-device.yaml) | a router or a small board, where memory and CPU are the constraint |
| [`public.yaml`](../examples/public.yaml) | a resolver on the internet that anybody may query |
| [`container.yaml`](../examples/container.yaml) | a container or DaemonSet in front of a cluster's own DNS |
| [`dev.yaml`](../examples/dev.yaml) | working on elodin itself: unprivileged ports, debug logging |

```sh
./bin/elodin --config examples/lan.yaml --check
```

`--check` is how to read one of these against your own machine: it prints the
worker counts it derived, who may ask, the connection table and its per-client
share, and a warning for anything a route gives up. `public.yaml` fails it
until the certificate and key it names exist.

**`local-only.yaml`** binds `127.0.0.1` rather than `0.0.0.0`, so nothing off
the machine can reach it at all, and cuts the worker pool to 8, the
[UDP readers](connections.md#how-fast-datagrams-can-be-read) to 1 and the cache to 5,000
entries — one client's working set rather than a network's. It is the one file
here that turns [rate limiting](rate-limiting.md#rate-limiting) *off*: the budget bounds what one
victim can be made to receive, and with the socket on loopback the only place an
answer can be delivered is this machine. `serve_stale` is on, for a laptop whose
upstream comes and goes.

**`lan.yaml`** narrows [`allow_from`](access-control.md#who-may-ask) to the one network it
serves, raises the response budget to 1,000 because every device on a
`192.168.1.0/24` shares one prefix's budget, and hands the whole connection
table to that prefix for the same reason — the clients are already bounded by
the allow list, so a per-client share would only ration the LAN against itself.
It turns [rebinding protection](rebinding.md#dns-rebinding-protection) on, answers the
network's own names from `rewrites`, and turns `special_use.home_arpa` on so
those names stop leaking to the public DNS.

**`small-device.yaml`** is the same deployment with the memory counted. It pins
4 workers, 1 racer and 1 reader with a 256 KiB receive buffer, carries one
blocklist rather than four (measured: 331,075 rules across the four in
`lan.yaml` is 58 MB resident, one list about 10 MB), keeps the blocklist cache on
tmpfs so a refresh is not a write to flash, and leaves DoT and DoH off — a TLS
handshake is about 1,100 µs of CPU against 37 µs to answer a query. Its local
names come from a `home.arpa` route to the dnsmasq the box is probably still
running for DHCP.

**`public.yaml`** is `allow_from: []` — the one setting that makes a resolver
open — and then everything that has to be true around it: the UDP answer ceiling
written out as the amplification factor it is, a per-prefix connection share of
24 instead of half the table, the [reader count](connections.md#how-fast-datagrams-can-be-read)
named as the ceiling every other bound sits under, `rebind` on, DNSSEC on, DoT
and DoH with a real certificate, and the three reserved-name zones (`local.`,
`test.`, `home.arpa.`) answered here, since a public resolver is nobody's local
authority. Filtering is narrowed to malware, on the argument that a stranger
cannot see your configuration.

**`container.yaml`** leaves the worker counts to the derivation, because in a
container the derivation reads your cgroup limits rather than the host's — a pod
limited to one CPU and 512 MiB derives 16 workers, at 256 MiB it derives 10.
It routes `cluster.local` and the reverse zone to kube-dns and forwards
everything else over DoT, writes nothing to disk (blocking off, so no list cache
to keep), and is the one file here that binds the metrics endpoint wide, because
the thing that scrapes it is outside the pod.

Two interactions the files point at, because both are refused at load rather
than discovered later: an `upstream.zones` route for a zone that
`special_use.local`, `test` or `home_arpa` answers would never fire, and
`cookies.require` without `cookies.enabled` demands a cookie nothing issues.
