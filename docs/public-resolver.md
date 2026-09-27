# Running a public resolver

`allow_from: []` (see [Who may ask](access-control.md#who-may-ask)) is the one setting that turns
this from a LAN resolver into one anybody can reach, and every default elodin
ships is sized for a household rather than for that. This is the checklist for
the difference and the figures behind it, rather than a repeat of them —
[`examples/public.yaml`](../examples/public.yaml) is the configuration that
already makes these choices.

**What has to be in front of it, because nothing behind it can be:**

- A packet filter, or upstream scrubbing, for the datagram rate. Past what the
  UDP readers can drain, the kernel's own receive queue decides who is served,
  not the limiter — see [how fast datagrams can be
  read](connections.md#how-fast-datagrams-can-be-read). Measured on a 4-core aarch64 VM: one
  reader drains 2.3 million datagrams a second, and a flood of two million a
  second still cost the queue 4% of arrivals with that reader nowhere near
  saturated. Scale the figure to your own cores, and watch
  `elodin_udp_receive_drops_total` to see whether your instance is anywhere
  near it.
- A per-source connection rate limit. Nothing bounds how many TLS handshakes a
  source can *start*, only how many connections it can *hold* at once — see
  [a connection rate limit in front](#a-connection-rate-limit-in-front) for the
  nftables rule and the figures behind it.

**What to tune in the kernel:**

- `net.core.rmem_max` — 208 KiB on a machine nobody has tuned, which clamps
  `listeners.udp.receive_buffer` regardless of what is configured. Raise the
  sysctl if you raise the setting; the startup line reports what was actually
  granted.
- `listeners.udp.readers` against your core count. Left at `0` it derives one
  reader per usable CPU, up to eight, which `--check` prints.
- The descriptor limit, if you raise `server.max_connections`. Every held
  connection is a descriptor, and `RLIMIT_NOFILE` is the one bound on this
  server that is not in its configuration file — systemd leaves the soft limit
  at 1024 unless a unit says otherwise, which the shipped one does
  (`LimitNOFILE=8192`). Raise the table past it and the listener stops
  accepting rather than the table filling: accepts fail, the loop waits between
  attempts, and `elodin_accept_backoffs_total` climbs while it does. Startup warns when the limit cannot cover the
  table and says nothing when it can — `--check` does not, because it would be
  reading its own process's limit rather than the service's.

**What elodin bounds on its own,** measured and holding for an hour of
flooding (`bench/results/2026-09-03-soak-one-hour.md`):

- The response budget: 500 responses/s per /24 or /64 by default, so at most
  about 0.58 MB/s aimed at one victim ([rate limiting](rate-limiting.md#rate-limiting)).
- A per-prefix share of the connection table ([how many connections one client
  may hold](connections.md#how-many-connections-one-client-may-hold)).
- Steady state under a 20,000 q/s flood held for an hour: 74–75 MB resident,
  103 threads, the cache pinned at `max_entries` after turning over 187 times,
  and the connection table lending and reclaiming a slot 174,176 times without
  leaking one or refusing one. Nothing measured there drifts with uptime.

**What it does not bound:** a packet flood above the readers' drain rate, or a
handshake flood — the accept refuses both, but a refusal is cheap rather than
free, and a source paying nothing to dial again simply dials faster. That gap
is what the packet filter and the connection rate limit above are for; none of
this is a defence on its own, and the sections it links to say so again where
the figures are.

## A connection rate limit in front

If this resolver is reachable from the internet, put a per-source limit on *new
connections* in front of it — in nftables or iptables on the same host, or in
whatever terminates TLS if something else does. Not instead of the [arrival
budget](rate-limiting.md#rate-limiting) and the [per-client
share](connections.md#how-many-connections-one-client-may-hold); as well as them.

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
[`listeners.udp.readers`](connections.md#how-fast-datagrams-can-be-read) plus a filter.
