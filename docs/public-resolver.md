# Running a public resolver

`allow_from: []` (see [Who may ask](access-control.md#who-may-ask)) opens the
resolver to anybody, and every default elodin ships is sized for a household.
[`examples/public.yaml`](../examples/public.yaml) is a configuration that already
makes the choices below. The measured figures behind every bound in these docs
live on this page; each names its report under `bench/results/`.

## Checklist

**Put in front of it:**

- A packet filter, or upstream scrubbing, for the datagram rate. Past what the
  UDP readers can drain, the kernel's receive queue decides who is served, not the
  limiter — see [how fast datagrams can be
  read](connections.md#how-fast-datagrams-can-be-read) and the
  [drain-rate figures](#datagrams-the-readers-can-drain).
- A per-source connection rate limit: see [a connection rate limit in
  front](#a-connection-rate-limit-in-front).

**Tune in the kernel:**

- `net.core.rmem_max` — 208 KiB untuned, which clamps
  `listeners.udp.receive_buffer`. Raise it if you raise the setting; the startup
  line reports what was granted.
- `listeners.udp.readers` against your core count. `0` derives one reader per
  usable CPU, up to eight, which `--check` prints.
- The descriptor limit, if you raise `server.max_connections`. Every held
  connection is a descriptor. systemd leaves the soft limit at 1024 unless the
  unit says otherwise; the shipped unit sets `LimitNOFILE=8192`. Past `RLIMIT_NOFILE`,
  accepts fail and the listener waits between attempts: `elodin_accept_backoffs_total`
  climbs. Startup warns when the limit cannot cover the table; `--check` does not,
  since it would read its own process's limit, not the service's.

## What elodin bounds on its own

- The response budget: 500 responses/s per /24 or /64 by default, so at most
  about 0.6 MB/s of 1232-byte answers aimed at one victim, plus the slip's 62
  small truncated replies a second ([rate
  limiting](rate-limiting.md#rate-limiting)).
- A per-prefix share of the connection table ([how many connections one client
  may hold](connections.md#how-many-connections-one-client-may-hold)).
- Opening a connection, charged to a per-prefix budget of its own.

It does **not** bound a packet flood above the readers' drain rate, or how often
a source may be *refused*. A refusal is cheap, not free, and a source that pays
nothing to dial again dials faster. That is what the packet filter and the
connection rate limit are for.

All figures below were measured on a 4-core aarch64 VM with 7 GB of RAM, with the
limiter at its shipped defaults unless stated. Scale them to your own machine;
each report names the command that re-takes it (most are `go run ./cmd/rrlexp`
in `bench/`, which `mise run bench` does not run; see
[`bench/README.md`](../bench/README.md)).

### Datagrams the readers can drain

`bench/results/2026-09-03-udp-readers.md`, with the server confined to two CPUs:

- One reader drains 2.3 million datagrams a second, about 400 ns of one core each.
- Under a flood of two million a second the kernel still dropped 4% of arrivals
  (918,000 datagrams in ten seconds) with that reader not saturated. Those reached
  no budget, no counter and no client.
- The limiter held the flood to its budget, and a client in an unrelated /24 was
  answered 98% of the time.
- A second reader showed no speed-up there: the load generator shares the machine
  and pays for loopback delivery, so a second box or a real NIC is needed to
  measure the scaling. `elodin_udp_receive_drops_total` shows whether your own
  instance is near the ceiling.

### Truncated answers (`slip`)

`bench/results/2026-09-03-rate-limit-bystander.md` (uncharged) and
`2026-09-03-slip-budget.md` (with the slip's own budget), under a two-million
datagram/s flood of one cached name:

| | truncated/s | MB/s at the named address | bystander in another /24 answered |
|---|---:|---:|---:|
| slip uncharged | 497,131 | 18.97 | 55% |
| slip budget (62/s) | 58 | 0.54 | 99% |
| `slip: 0` | 0 | 0.53 | 99% |

The cost: under this flood, about 40 times the budget, a client *inside* the
flooded /24 gets its invitation to TCP about once in 500 queries instead of half
the time. At a busy NAT's rate, around twice the budget, the 62 a second still
land, and one that lands moves the client to TCP for good.

### Handshake floods

`bench/results/2026-09-04-handshake-budget.md` (before and after charging
connections) and `2026-09-03-handshake-floods.md` (the load): 32 workers dialling,
completing a DoT handshake and hanging up, beside a DoT client holding one
connection at 50 q/s in another /24.

| | handshakes/s | dials/s | server CPU (of 4 cores) | DoT bystander answered |
|---|---:|---:|---:|---:|
| quiet baseline | — | — | — | 98% |
| connections uncharged | 6,032 | 6,032 | 1.25 | 82% |
| connections charged | 462 | 25,129 | 0.29 | 88% |

- Uncharged, `conn_refused` and `elodin_rate_limited_total` both read zero: the
  shipped table is never reached and the flood asks nothing.
- The dial rate rises fourfold once being refused is cheap; that remaining cost is
  why the bystander does not return to the baseline.
- A client opening one connection per query during the flood was answered 100%
  both before and after.

### Connection table share

`bench/results/2026-09-03-connection-table-share.md`: one client opening 96 idle
TCP connections against `max_connections: 64`, and a victim in another /24
opening a connection per query.

| share | held by the one client | victim answered |
|---|---:|---:|
| none | 64 | 0% (0/400) |
| 32 | 32 | 100% (235/235) |

With the share, a normal client holding one connection beside a 20,000 q/s UDP
flood from the holder's /24 was answered 100%. UDP clients are unaffected by a
full table either way.

### One-hour soak

`bench/results/2026-09-03-soak-one-hour.md`, a 20,000 q/s flood held for an hour:
74–75 MB resident, 103 threads, the cache pinned at `max_entries` after turning
over about 187 times, and the connection table lending and reclaiming a slot
174,176 times without leaking or refusing one. Nothing measured drifts with
uptime.

## A connection rate limit in front

If the resolver is reachable from the internet, limit *new connections* per
source in front of it — in nftables or iptables on the same host, or in whatever
terminates TLS. This is as well as the [arrival
budget](rate-limiting.md#rate-limiting) and the [per-client
share](connections.md#how-many-connections-one-client-may-hold), not instead.

Every bound elodin keeps is per /24 and per /64, so an actor with addresses in
*n* prefixes has *n* copies of it; on IPv6 a routine /48 is 65,536 /64s. And
refusing a connection still costs the server (see the [handshake
figures](#handshake-floods)). A packet filter is the only place that stops a peer
from making the server refuse it.

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

- Trim the port list to the listeners you expose: 853 DoT, 443 DoH, 53 TCP.
- Check it with `nft --check --file` before loading: a wrong rule in the `input`
  hook can lock you out of the host.
- Size it above what clients do and below what a flood does. A stub opens one
  connection and keeps it, and a NAT reconnecting every device at once is a burst,
  not a rate. Ten a second per prefix is generous for anything legitimate.
- On a private network every device on `192.168.1.0/24` is one source to this
  rule, as it is to `responses_per_second`. Size the burst for the whole LAN, or
  leave it to the in-server budget.
