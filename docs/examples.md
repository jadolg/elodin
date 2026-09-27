# Example configurations

`examples/elodin.yaml` is the annotated reference: every setting with its
default. The files beside it show which settings a particular deployment
changes, with a comment on why; anything they leave out is the shipped default.

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

`--check` shows what a file means on your machine: the derived worker counts,
who may ask, the connection table and its per-client share, and a warning for
anything a route gives up. `public.yaml` fails it until the certificate and key
it names exist.

**`local-only.yaml`** binds `127.0.0.1`, so nothing off the machine can reach
it. It cuts the worker pool to 8, the
[UDP readers](connections.md#how-fast-datagrams-can-be-read) to 1 and the cache
to 5,000 entries, sized for one client. It is the only file that turns
[rate limiting](rate-limiting.md#rate-limiting) off: on loopback, the only
possible victim is this machine. `serve_stale` is on, for a laptop whose
upstream comes and goes.

**`lan.yaml`** narrows [`allow_from`](access-control.md#who-may-ask) to the
network it serves. It raises the response budget to 1,000 and gives the whole
connection table to one prefix, because every device on `192.168.1.0/24` shares
one prefix's budget and the allow list already bounds the clients. It turns
[rebinding protection](rebinding.md#dns-rebinding-protection) on, answers the
network's own names from `rewrites`, and turns `special_use.home_arpa` on so
those names stop leaking to the public DNS.

**`small-device.yaml`** is the LAN setup sized for memory. It pins 4 workers, 1
racer and 1 reader with a 256 KiB receive buffer, and carries one blocklist
instead of four (the four in `lan.yaml`, 331,075 rules, measured 58 MB resident;
one list about 10 MB). The blocklist cache is on tmpfs so a refresh does not
write to flash. DoT and DoH are off: a TLS handshake costs about 1,100 µs of CPU
against 37 µs to answer a query. Local names come from a `home.arpa` route to
the dnsmasq the box likely runs for DHCP.

**`public.yaml`** sets `allow_from: []`, which makes the resolver open, plus
what has to hold around it:

- the UDP answer ceiling, commented as the amplification factor it sets
- a per-prefix connection share of 24 instead of half the table
- the [reader count](connections.md#how-fast-datagrams-can-be-read), the ceiling
  every other bound sits under
- `rebind` on, DNSSEC on, DoT and DoH with a real certificate
- the reserved-name zones `local.`, `test.` and `home.arpa.` answered locally,
  since a public resolver is nobody's local authority
- filtering narrowed to malware

**`container.yaml`** leaves worker counts to the derivation, which reads the
container's cgroup limits: a pod limited to one CPU and 512 MiB derives 16
workers, at 256 MiB 10. It routes `cluster.local` and the reverse zone to
kube-dns and forwards everything else over DoT. It writes nothing to disk
(blocking off, so no list cache). It is the only file that binds the metrics
endpoint wide, because the scraper is outside the pod.

Two combinations are refused at load:

- an `upstream.zones` route for a zone that `special_use.local`, `test` or
  `home_arpa` answers, since the route would never fire
- `cookies.require` without `cookies.enabled`, which demands a cookie nothing
  issues
