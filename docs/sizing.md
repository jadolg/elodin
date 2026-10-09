# Sizing

Left unset (`0`, as the shipped configuration has them), the worker counts are
derived at startup from the machine:

```
workers           = clamp(usable_cpus * 4, 16, 128), lowered if the threads
                    that implies would take more than 1/32 of usable memory
upstream_workers  = workers / 2
max_pending       = workers * 8
```

- "Usable" is what this process can have: the CPU affinity mask, and a cgroup CPU
  or memory limit where there is one (`CPUQuota=`/`MemoryMax=` in a unit, or a
  container's limits).
- A number in the configuration always wins. The two worker counts can be set
  independently; an unset `upstream_workers` follows a configured `workers`.
- What it settled on is logged after startup and printed by `--check`:

```console
$ elodin --check
/etc/elodin/elodin.yaml is valid: 2 upstreams, 0 zone routes, 4 blocklists, 0 rewrites
  workers=16 upstream_workers=8 max_pending=128 chain_walks=12 connection_walks=384 (derived from 4 usable CPUs and 7.7 GiB)
  answering queries from 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, ::1/128, fc00::/7, fe80::/10; every other source is refused
  udp: 4 readers, asking for 1MiB of receive buffer each (derived from 4 usable CPUs)
  connections: at most 512 at once across TCP, DoT and DoH, of which one client prefix (/24, /64) may hold 256; connections past a prefix's share are refused and counted as conn_refused=
```

A worker is held for the whole upstream round trip, so sustained cache-miss
throughput is roughly `server.workers / upstream_rtt`.

- **Every query shares the pool**, so running short on workers delays cache hits
  as much as misses.
- **Memory scales with workers**, as a floor: each worker keeps its scratch arena
  from its first query on (Odin's temp allocator `free_all` keeps the first
  block).

Past `max_pending` queries are dropped, not queued: the client times out and
retries. A DoH client over HTTP/2 is answered `503` instead.

## Transports

- **UDP**: a reader thread per usable CPU, to eight, handing each datagram to the
  worker pool; no per-client state, no connection limit. See [how fast datagrams
  can be read](connections.md#how-fast-datagrams-can-be-read).
- **TCP, DoT and DoH**: a thread per connection, capped together by
  `server.max_connections` (512) and per client by
  [`max_connections_per_prefix`](connections.md#how-many-connections-one-client-may-hold)
  (half of it). TCP, DoT and HTTP/1.1 answer one query at a time per connection;
  **HTTP/2 multiplexes**. Connections are reused, so the cap bounds concurrent
  clients, not queries per second.

HTTP/2 costs more CPU per query than HTTP/1.1 on cache hits, and wins when queries
are slow: a browser's concurrent requests overlap instead of queueing.

TLS handshakes are the expensive part of the encrypted transports, orders of
magnitude more CPU than answering on an open connection. ECDSA P-256 costs about
half what RSA-2048 does; `mise run certs` generates ECDSA, and production should
use it too.

Opening a connection is charged to the prefix's [rate
limit](rate-limiting.md#rate-limiting), per /24 and /64 only, and a refusal is
cheap rather than free. **If you expose DoT or DoH to the internet, rate-limit new
connections per source in front of the resolver**: see [a connection rate limit in
front](public-resolver.md#a-connection-rate-limit-in-front). The handshake-flood
figures are on [the same page](public-resolver.md#handshake-floods).

## Refused and failed connections

| counter | cause | what the client sees |
|---|---|---|
| `conn_refused=` | past `max_connections` or the client's share; the `warn` line says which | DoT/DoH: refused during the handshake. TCP: the kernel already completed it, so a reset on first use |
| `conn_rate_limited=` | the prefix opened connections faster than `rate_limit.responses_per_second` allows | closed on accept, before TLS |
| `conn_failed=` | the OS gave no thread (`RLIMIT_NPROC`, cgroup `pids.max`, memory); raising `max_connections` makes it worse | the same as `conn_refused=` |
| `accept_backoff=` | no file descriptor for the accept (`RLIMIT_NOFILE`) | nothing yet: the peer stays queued |

`conn_refused=` is kept apart from `refused=`: this is a client elodin would serve
and has no room for. A connection accepted as shutdown begins is closed and
counted under none of these.

A failing accept is retried at once three times in a row, with no wait and no
count. Past that the listener waits between attempts: up to 50 ms for errors on
individual connections, and up to a second on a descriptor shortage, where it
stops accepting; each wait is one
`accept_backoff=`, so a rate near one a second per listener is a listener taking
nothing. The `warn` naming the listener and `RLIMIT_NOFILE` is logged only once
it has spent about a second not accepting, so a burst that clears by itself is
silent.

## Measuring and disk

`mise run bench` measures all of this; see [`bench/README.md`](../bench/README.md).
Committed runs are under `bench/results/`: read them as the shape of the thing,
and re-take them rather than quoting an old run against a change.

On disk, `log.queries` writes a line per query and wants rotation. Nothing else
is written in steady state; the blocklist cache is the size of the lists.
