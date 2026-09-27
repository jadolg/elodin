# Sizing

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
  workers=16 upstream_workers=8 max_pending=128 chain_walks=12 connection_walks=384 (derived from 4 usable CPUs and 7.7 GiB)
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
read](connections.md#how-fast-datagrams-can-be-read), which is the ceiling on everything the
rate limiter achieves. **TCP, DoT and DoH** give each connection a thread, capped together by
`server.max_connections` (512) and per client by
[`max_connections_per_prefix`](connections.md#how-many-connections-one-client-may-hold) (half
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
limiting](rate-limiting.md#rate-limiting) — which on the shipped 500 held the same flood to 462
handshakes a second and 0.29 of a core, and gave that DoT client back a good third
of what it had lost. It is per prefix like everything else, and a refusal is cheap rather
than free, so **if you expose DoT or DoH to the internet, rate-limit connections
per source in front of the resolver as well**: see [a connection rate limit in
front](public-resolver.md#a-connection-rate-limit-in-front).

Past `max_connections`, or past one client's share of it, DoT and DoH refuse
cleanly during the handshake. Plain TCP cannot: the kernel completes the
handshake from the listen backlog before the server sees it, so a refused client
gets a reset on first use and has to reconnect. Either way it is counted as
`conn_refused=`, kept apart from `refused=` because this is a client elodin would
serve and has no room for; which of the two limits refused it is in the `warn`
line beside it. A connection refused *below* both, when the OS will not give the
process another thread — `RLIMIT_NPROC`, a cgroup `pids.max`, memory — is
`conn_failed=`, where raising `max_connections` cannot help and would make it
worse.

A shortage of **file descriptors** is the one failure here that turns no client
away, and it is counted separately for that reason. An accept that cannot
allocate a descriptor leaves the peer on the queue, so nothing was refused; what
happened is that the listener stopped accepting. It waits between attempts rather than
retrying into the same shortage, escalating from a millisecond to a second so
that an error which clears by itself — `accept(2)` passes pending network errors
through, and says to retry those at once — costs nothing measurable, while one
that does not clear settles at a second. Each wait is `accept_backoff=`, so a
rate sitting near one per listener is a listener taking no connections at all.
The `warn` beside it names the listener and `RLIMIT_NOFILE`, and is said only
once that listener has spent about a second not accepting — so a burst that
clears by itself never spends it.

`mise run bench` measures all of this; the harness is documented in
[`bench/README.md`](../bench/README.md) and its committed runs are under
`bench/results/`. Read those as the shape of the thing rather than as a
specification, and re-take them rather than quoting an old run against a change.

One thing to watch on disk: `log.queries` writes a line per query and wants
rotation. Nothing else is written in steady state, and the blocklist cache is the
size of the lists.
