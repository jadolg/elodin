# Example configurations

`examples/elodin.yaml` is the annotated reference: every setting with its
default. The files beside it show which settings a particular deployment
changes, with a comment on why; anything they leave out is the shipped default.

| file | deployment |
|---|---|
| [`local-only.yaml`](../examples/local-only.yaml) | one machine resolving for itself, bound to loopback |
| [`lan.yaml`](../examples/lan.yaml) | the resolver a home or small-office network points at |
| [`docker.yaml`](../examples/docker.yaml) | the same, in the container image, where it is the configuration the image ships with; [`compose.yaml`](../examples/compose.yaml) runs it |
| [`small-device.yaml`](../examples/small-device.yaml) | a small arm64 or amd64 board, where memory and CPU are the constraint |
| [`public.yaml`](../examples/public.yaml) | a resolver on the internet that anybody may query |
| [`docker-public.yaml`](../examples/docker-public.yaml) | the same in the container image, DoT and DoH only; [`compose-public.yaml`](../examples/compose-public.yaml) runs it with a Let's Encrypt certificate |
| [`container.yaml`](../examples/container.yaml) | a container or DaemonSet in front of a cluster's own DNS |
| [`dev.yaml`](../examples/dev.yaml) | working on elodin itself: unprivileged ports, debug logging |

```sh
./bin/elodin --config examples/lan.yaml --check
```

The file is YAML 1.2, read with its core schema: a boolean is `true`, `True`,
`TRUE`, `false`, `False` or `FALSE`, and an integer is plain digits with an
optional sign, `0x` hex or `0o` octal, unquoted. YAML 1.1's `yes`, `no`, `on`,
`off`, `3_000` and `0b1010`, and a quoted number or boolean, are strings, so a
boolean or integer setting refuses them, naming the value and why. A TTL also
takes a duration such as `5m`, quoted or not. A byte order mark at the start of
the file, or of a document after `---`, is ignored.

An upgrade of the `.deb` runs `--check` on `/etc/elodin/elodin.yaml` before it
restarts a running elodin, and leaves the running one alone if the check fails.

`--check` shows what a file means on your machine: the derived sizes,
who may ask, the connection table and its per-client share, and a warning for
anything a route gives up. `public.yaml` fails it until the certificate and key
it names exist.

**`local-only.yaml`** binds `127.0.0.1`, so nothing off the machine can reach
it. It cuts the queries in flight to 64, the
[UDP readers](connections.md#how-fast-datagrams-can-be-read) - one event loop - to 1 and the cache
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

**`docker.yaml`** is `lan.yaml` for the [container image](install.md#container-image),
and what the image runs when no configuration is mounted. Its `allow_from` keeps
every private range rather than one `/24`: a query from the Docker host, every
query under Docker Desktop and IPv6 through Docker's userland proxy arrive from
the bridge's gateway rather than from the device that asked. `server.user` is
empty, since the image never runs as root. The metrics endpoint is bound wide
inside the container, whose loopback nothing else can reach, so publishing
9153 is what decides who can scrape it. The blocklist cache is
`/var/cache/elodin`, which the image's account owns, for a volume.
`compose.yaml` runs it with a read-only root, no capabilities, the cache volume
and a descriptor limit above Docker's default of 1,024.

**`small-device.yaml`** is the LAN setup sized for memory. It pins 32 queries in
flight and 1 reader - one event loop - with a 256 KiB receive buffer, and carries one blocklist
instead of four (the four in `lan.yaml`, 350,929 rules, measured 12 MB resident;
one list about 3 MB). The blocklist cache is on tmpfs so a refresh does not
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

**`docker-public.yaml`** is `public.yaml` for the container image, with plain
DNS turned off: DoT on 853 and DoH on 443 only, so there is no UDP to reflect
and the datagram settings drop out. `compose-public.yaml` runs it beside
certbot. certbot starts first, obtains the certificate over HTTP-01 on port 80,
and writes it with its key as one file, `pair.pem`, owned by the image's
account, into a volume elodin mounts read-only; elodin waits for that. If the
first issue fails, `up` starts elodin anyway after about 5 minutes and it
restarts until the certificate arrives. One file replaced by one rename means
elodin never loads a new key beside an old certificate. certbot then tries a
renewal twice a day, writes a new file and sends elodin `SIGHUP`. The two share
a PID namespace held by a `pause` container, so the signal needs no Docker
socket and certbot exiting leaves elodin running. With no certificate and a
failed issue, certbot waits 15 minutes before trying again, under Let's
Encrypt's limit of 5 failed validations per name an hour. The compose network
has IPv6 enabled (Docker Engine 27 or later) and the listeners are on `::`, so
IPv6 clients reach elodin under their own addresses rather than the bridge
gateway's, and the per-prefix rate limit and connection share apply to each of
them.

**`container.yaml`** leaves the sizes to the derivation, which reads the
container's cgroup limits: a pod limited to one CPU and 512 MiB derives one loop
and 204 queries in flight, at 256 MiB 102. It routes `cluster.local` and the
reverse zone to kube-dns and forwards everything else over DoT. It writes nothing to disk
(blocking off, so no list cache). It is the only file that binds the metrics
endpoint wide, because the scraper is outside the pod.

Two combinations are refused at load:

- an `upstream.zones` route for a zone that `special_use.local`, `test` or
  `home_arpa` answers, since the route would never fire
- `cookies.require` without `cookies.enabled`, which demands a cookie nothing
  issues
