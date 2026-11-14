# Sizing

Left unset (`0`, as the shipped configuration has them), the sizes are derived at
startup from the machine:

```
loops            = listeners.udp.readers = usable_cpus, at most 8
max_pending      = (usable memory / 8) / 320 KiB, between 64 and 4096
                   (409 on a 1 GiB machine; 1024 where memory cannot be read)
heavy_decodes    = (usable memory / 32) / 8 MiB, between 2 and 128 (not a key)
chain_walks      = max_pending less a reserved quarter
connection_walks = max_connections less a reserved quarter
```

- "Usable" is what this process can have: the CPU affinity mask, and a cgroup CPU
  or memory limit where there is one (`CPUQuota=`/`MemoryMax=` in a unit, or a
  container's limits).
- A number in the configuration always wins: `listeners.udp.readers`,
  `server.max_pending`, `dnssec.max_chain_walks` and `dnssec.max_connection_walks`
  can each be set on its own.
- What it settled on is logged after startup and printed by `--check`:

```console
$ elodin --check
/etc/elodin/elodin.yaml is valid: 2 upstreams, 0 zone routes, 4 blocklists, 0 rewrites
  loops=2 max_pending=3164 heavy_decodes=30 chain_walks=2373 connection_walks=384 (derived from 2 usable CPUs and 7.7 GiB)
  answering queries from 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, ::1/128, fc00::/7, fe80::/10; every other source is refused
  udp: 2 readers, asking for 1MiB of receive buffer each (derived from 2 usable CPUs)
  connections: at most 512 at once across TCP, DoT and DoH, of which one client prefix (/24, /64) may hold 256; connections past a prefix's share are refused and counted as conn_refused=
```

`server.workers`, `server.running_workers` and `server.upstream_workers` are
refused as unknown keys. Remove them.

## Event loops

elodin answers everything on a few event loops, one thread each. A query or a
connection that waits - on an upstream, on another client's identical query, on
a DoH client's flow-control window - parks and costs no thread while it waits, so
how many cache misses can be in flight is not a thread count: one loop carries
thousands. The loops are sized by the cores because a loop is either running or
asleep in `epoll_wait`, and one past the core count adds contention rather than
throughput.

Each loop takes one UDP socket of its own (`SO_REUSEPORT`, so the kernel spreads
datagrams between them by a hash of the source) and a share of the TCP, DoT and
DoH connections, which one accept loop hands out in turn. A query is answered on
the loop it arrived on.

What a loop does with the CPU between waits - decoding, the cache, DNSSEC
signature checks, TLS handshakes - is done inline, so a loop at 100% of its core
is the ceiling, and adding loops past the cores does not raise it. Nothing
preempts a fiber the way the kernel preempts a thread, so the long stretches of
CPU give the loop a turn as they go: DNSSEC validation every fourth signature
check and every ~100 µs of NSEC3 hashing, decoding every 64 KiB of names a query
expands (an answer built to expand is ~2 ms of decoding; an ordinary one never
reaches 64 KiB), and a reader every 64 messages it reads without waiting.
Between turns a validating query holds its loop for a few hundred microseconds
at most, where the whole of its DNSSEC allowance is a few milliseconds.

### Pinning the loops

```yaml
server:
  pin_loops: false   # true holds loop i to the i-th CPU the process may use
```

A loop that goes idle in `epoll_wait` gives up its CPU. When it wakes, the
scheduler can queue it on a CPU where another loop is running, and it then
waits out that loop's slice, about 3 ms, with all its connections waiting
behind it. That happens between idle and saturated. A saturated loop never goes
idle, and an idle server has nothing queued. `pin_loops: true` holds each loop
to a CPU of its own, so no loop ever queues behind another. Measured with DoT
cache hits at 200,000 a second on two cores, it took p99.5 from 0.56–0.88 ms to
0.47–0.67 ms.

It is off by default because a pinned loop can't move. If another process keeps
that CPU busy, the loop's connections wait for it. Turn it on where the CPUs are
elodin's.

- The CPUs are the ones the process may run on: its affinity, as `taskset`, a
  cpuset or systemd's `CPUAffinity=` sets it. Loop i takes the i-th of them, and
  startup logs the plan (`server.pin_loops: pinning the event loops to CPUs [0, 1]`).
  CPU numbers are not cores: if two of them are hyperthreads of one core, the
  loops on them share that core. To give each loop a core of its own, set the
  affinity to one hyperthread per core (`lscpu -e` shows the pairs).
- With more loops (`listeners.udp.readers`) than CPUs, no loop is pinned, since
  two loops pinned to one CPU would queue behind each other for good. Startup
  warns.
- Only the loops are pinned. elodin's other threads (the main thread, the
  metrics endpoint, a blocklist rebuild) can still run on a loop's CPU, and
  while they do, that loop shares it.
- A CPU quota (`docker run --cpus`, `CPUQuota=`) is not an affinity. Pinned
  loops under a quota still share its time.
- If the affinity can't be read, or a loop can't be held to its CPU, startup
  warns and those loops run unpinned.
- It takes a restart. A reload that changes it says so and keeps the value the
  process started with.

## Queries in flight

`server.max_pending` bounds the queries in flight on fibers of their own: every
UDP query and DoH-over-HTTP/2 request from the moment it is admitted until it is
answered, every TCP or DoT query beyond the first one in flight on its
connection, and every cache refresh. Past it a datagram is dropped - the client
retries - and an HTTP/2 request is answered `503`, counted as `dropped=`; a TCP
or DoT connection falls back to one query at a time until a place frees.

Each TCP or DoT connection keeps one query in flight outside `max_pending`, and
each DoH-over-HTTP/1.1 connection answers one query at a time, so
`max_connections` bounds those instead.

The derived figure is memory over what a query can come to hold: the stack and
scratch it uses (a few kilobytes for a cache hit, about 20 KB for a miss that
walks a DNSSEC chain) and up to 256 KiB of decoded answers, which is the most a
request may decode without a heavy slot (below). An ordinary query holds a small
fraction of that; the figure is what an attacker steering answers can push every
query to, at an eighth of memory.

`elodin_queries_inflight` against `elodin_queries_inflight_max` shows how close
the server is; a figure sitting at the maximum while `elodin_queries_dropped_total`
rises is the server turning queries away. Against a 20 ms upstream, 1,000 in
flight is 37,500 cache misses a second, since a quarter is kept from upstream
waits (below); raise `max_pending` only when the dropped counter or
`elodin_queries_upstream_shed_total` says so.

### Waiting on an upstream

At most `max_pending` less a reserved quarter (never fewer than two reserved,
nor fewer than one left to wait in) of
these queries may be waiting on an upstream at once: forwarding, waiting on an
identical query already forwarding, walking a DNSSEC chain, or waiting on an
expired entry's refresh. The reserved quarter is never held for an upstream's
timeout, so cache hits keep being admitted while a dead upstream holds every
miss for `timeout` × `attempts`. A query that would wait past the bound is
answered as an unreachable upstream answers - the expired entry where
`cache.serve_stale` kept one, SERVFAIL otherwise - at once, logged as
`outcome=failed detail=upstream-busy` and counted in
`elodin_queries_upstream_shed_total`. The first one is logged at `warn`, the
rest at `debug`.

A client asking for an expired entry with no place left is served the entry at
once and starts no refresh, as when the refresh ceiling is reached; it is not
counted as shed. Where the entry can no longer be served - its signatures have
lapsed, or it was evicted - that client is answered SERVFAIL, logged as
`detail=upstream-busy`, and is not counted as shed either.

### What reaches the upstreams

`max_pending` is also how much of a flood the upstreams see. A query for a name
nobody has asked before - the random-subdomain attack - is a cache miss, and every
one admitted is forwarded. With threads, the worker count held that to about 128
upstream exchanges at once, around 6,000 a second against a 20 ms upstream,
however many clients took part. Now it is `max_pending` at once, thousands, which
is the point of the event loops for honest misses and the same multiplier for a
flood: twenty times or more of what reached a public upstream before, enough for
one with a per-client limit to start refusing this resolver, and every client
behind it with it.

`server.rate_limit` still holds each client prefix to its budget, so a flood from
one network is no larger than before. What changed is the ceiling on a flood
spread over many. Where the upstream is a public resolver with limits of its own,
or a link with a fixed capacity, set `max_pending` to what the upstream should
carry: target misses per second × upstream round trip, over the three quarters
that may wait on an upstream, with headroom - 1,000 is 37,500 a second against
20 ms. `dnssec.max_chain_walks` caps the chain walks
within that the same way, for validating resolvers.

Measured before and after the event loops, and against Unbound, in
[`bench/results/2026-10-26-event-loop.md`](../bench/results/2026-10-26-event-loop.md).

### Heavy decodes

A request may decode up to 8 MiB of the messages it reads - the most a query's
three readings of a full-length answer and a chain walk's DNSKEY sets can take.
Only 256 KiB of that is free: a request reading past it takes one of
`heavy_decodes` slots, shared by the whole process, and with every slot taken
the reading is refused as over budget and the query answered SERVFAIL. Honest
traffic stays far below the free part; the slots are what keeps a flood of
answers built to expand from holding 8 MiB per query in flight.
`elodin_decode_heavy_requests` against `elodin_decode_heavy_requests_max` shows
them.

## Transports

- **UDP**: one socket per loop. See [how fast datagrams can be
  read](connections.md#how-fast-datagrams-can-be-read).
- **TCP, DoT and DoH**: one fiber per connection, capped together by
  `server.max_connections` (512) and per client by
  [`max_connections_per_prefix`](connections.md#how-many-connections-one-client-may-hold)
  (half of it). HTTP/1.1 answers one query at a time per connection; **TCP,
  DoT and HTTP/2 answer concurrently**, each query on a fiber of its own (see
  [pipelined queries](#pipelined-queries-on-tcp-and-dot)). Connections are
  reused, so the cap bounds concurrent clients, not queries per second.

A held TCP connection costs about 5 KB resident after a query - the page of
stack its fiber is parked on and the fiber itself, since a connection that has
waited a quarter of a second for its next query hands the rest of its stack and
its scratch back - and a DoT or DoH/2 one about 39 KB, most of it OpenSSL's
session. An idle TLS
connection hands its record buffers back (`SSL_MODE_RELEASE_BUFFERS`) and takes
them again for its next record. A loop
keeps the stacks of finished connections and queries warm for the next ones,
never more than it had in use at once, and every second gives back as many as
it did not need in that second, down to eight. `--check` and startup warn when
`max_connections` at 128 KB each is more
than a quarter of the memory elodin may use:

```
server.max_connections is 4096: with every connection open that is about 512.0 MiB, more than a quarter of the 1.0 GiB this process may use
```

Lower `max_connections`, or give elodin more memory (`MemoryMax=`). elodin turns
transparent huge pages off for itself at startup (`PR_SET_THP_DISABLE`), so a
touched page of a stack or a heap never costs 2 MB.

HTTP/2 costs more CPU per query than HTTP/1.1 on cache hits, and wins when queries
are slow: a browser's concurrent requests overlap instead of queueing.

TLS handshakes are the expensive part of the encrypted transports, orders of
magnitude more CPU than answering on an open connection, and they run on the
loop the connection is on. An ECDSA P-256 handshake takes about a third of the
CPU an RSA-2048 one does (about 200 µs against 550 µs);
`mise run certs` generates ECDSA, and production should use it too.

Clients resume by session ticket (RFC 5077, and TLS 1.3's own), which costs the
server nothing per client. elodin keeps no server-side session cache: OpenSSL's
default would hold up to 20,480 sessions per DoT and DoH listener, about 10 MB
each, for clients that refuse tickets. Those clients do a full handshake every
time instead.

A session resumes for two hours from its full handshake; a ticket renewed on
resumption does not extend that. Each DoT and DoH listener seals its tickets
under a key of its own that it replaces every two hours, and it keeps the
replaced key for two hours more to open the tickets it sealed (RFC 9325 §3.4).
A key is erased within a maintenance tick (30 seconds) of turning four hours
old, suspended time included, so a key read out of the process's memory opens
only the tickets of the last four hours. A client that resumes on the replaced
key gets a new ticket under the current one. A `SIGHUP` builds new keys with the
reloaded certificate and erases the old ones, so every client holding a ticket
does one full handshake after a reload.

Opening a connection is charged to the prefix's [rate
limit](rate-limiting.md#rate-limiting), per /24 and /64 only, and a refusal is
cheap rather than free. **If you expose DoT or DoH to the internet, rate-limit new
connections per source in front of the resolver**: see [a connection rate limit in
front](public-resolver.md#a-connection-rate-limit-in-front). The handshake-flood
figures are on [the same page](public-resolver.md#handshake-floods).

### Pipelined queries on TCP and DoT

A client may send several queries down one TCP or DoT connection without
waiting (Android's Private DNS does). Each is answered as soon as it is ready,
in whatever order that is (RFC 7766 section 7), so a cache hit is not held up
behind a miss sent before it. At most 16 are in flight per connection; past
that elodin stops reading the connection until one is answered.

## Descriptors

Every query in flight may hold an upstream socket, so the descriptors elodin can
want are `max_connections`, `max_pending`, the idle upstream pools, the UDP
readers and two per loop, plus a reserve - and, where a group uses `strategy:
race`, `max_pending` times the servers of the widest racing group, for the race
queries ([upstreams](upstreams.md)). Startup warns when `RLIMIT_NOFILE` is short of
that (`LimitNOFILE=` in the systemd unit, 65536 as shipped).

## Memory mappings

Every query in flight, race query and connection runs on a fiber, and a fiber
holds three memory mappings (its stack, the guard page under it, its scratch),
and one more for each further 16 KiB a query's scratch grows to. Startup warns when `vm.max_map_count` (65530 by default) cannot hold
all of them, which the derived figures reach on a large machine racing a wide
group:

```
memory mappings: vm.max_map_count is 65530, short of the 163376 this configuration can want (...)
```

Past it no stack can be mapped: a query is dropped or shed and a connection
refused as `conn_failed=`. Raise it (`sysctl vm.max_map_count=262144`) or lower
`server.max_pending`.

A query whose scratch cannot grow, past this limit, `RLIMIT_AS` or the
machine's memory, fails on its own and the server keeps running. It is
answered SERVFAIL where there is room left to build one and gets no answer
where there is not. A TCP, DoT or HTTP/1.1 DoH connection whose next request
there is no room to read is closed. A DNSSEC validation refused memory anywhere is
reported undecided (EDE 22), not bogus, and caches nothing it settles after
the refusal.

## Refused and failed connections

| counter | cause | what the client sees |
|---|---|---|
| `conn_refused=` | past `max_connections` or the client's share; the `warn` line says which | DoT/DoH: refused during the handshake. TCP: the kernel already completed it, so a reset on first use |
| `conn_rate_limited=` | the prefix opened connections faster than `rate_limit.responses_per_second` allows | closed on accept, before TLS |
| `conn_failed=` | the OS would not map a stack for the connection (`RLIMIT_AS`, cgroup `memory.max`); raising `max_connections` makes it worse | the same as `conn_refused=` |
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
It starts elodin with the shipped unit's environment, so the figures describe
`MALLOC_MMAP_THRESHOLD_` as the unit sets it. The held-connection and handshake
figures on this page are from
[`bench/results/2026-11-06-unit-environment.md`](../bench/results/2026-11-06-unit-environment.md),
which also runs glibc's default threshold beside it: the two are within the
noise. Committed runs are under `bench/results/`: read them as the shape of the
thing, and re-take them rather than quoting an old run against a change.

On disk, `log.queries` writes a line per query and wants rotation. Nothing else
is written in steady state; the blocklist cache is the size of the lists.
