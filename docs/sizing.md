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

`server.workers`, `server.running_workers` and `server.upstream_workers` are no
longer used. A file that names them still
loads, and each is named in a `warn` at startup, at every reload and under
`--check`; 0.26.0 refuses them. Remove them.

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

## Queries in flight

`server.max_pending` bounds the queries in flight on fibers of their own: every
UDP query and DoH-over-HTTP/2 request from the moment it is admitted until it is
answered, and every cache refresh. Past it a datagram is dropped - the client
retries - and an HTTP/2 request is answered `503`, counted as `dropped=`.
TCP, DoT and DoH over HTTP/1.1 answer one query at a time on their connection,
in order, so `max_connections` bounds them instead.

The derived figure is memory over what a query can come to hold: the stack and
scratch it uses (a few kilobytes for a cache hit, about 20 KB for a miss that
walks a DNSSEC chain) and up to 256 KiB of decoded answers, which is the most a
request may decode without a heavy slot (below). An ordinary query holds a small
fraction of that; the figure is what an attacker steering answers can push every
query to, at an eighth of memory.

`elodin_queries_inflight` against `elodin_queries_inflight_max` shows how close
the server is; a figure sitting at the maximum while `elodin_queries_dropped_total`
rises is the server turning queries away. Against a 20 ms upstream, 1,000 in
flight is 50,000 cache misses a second; raise `max_pending` only when the dropped
counter says so.

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
carry: target misses per second × upstream round trip, with headroom - 1,000 is
50,000 a second against 20 ms. `dnssec.max_chain_walks` caps the chain walks
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
  (half of it). TCP, DoT and HTTP/1.1 answer one query at a time per connection;
  **HTTP/2 multiplexes**, each request on a fiber of its own counted against
  `max_pending`. Connections are reused, so the cap bounds concurrent clients,
  not queries per second.

A held TCP connection costs about 21 KB resident after a query - the stack its
fiber touched and its scratch - and a DoT or DoH/2 one about 72 KB, most of it
OpenSSL's session. A loop keeps the stacks of finished connections and queries warm for the
next ones and gives back all but eight once it has had nothing to do for a
second. `--check` and startup warn when `max_connections` at 128 KB each is more
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
loop the connection is on. ECDSA P-256 costs about half what RSA-2048 does;
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
No key lives longer than four hours, suspended time included, so a key read out
of the process's memory opens only the tickets of the last four hours. A client
that resumes on the replaced key gets a new ticket under the current one. A
`SIGHUP` builds new keys with the reloaded certificate and erases the old ones,
so every client holding a ticket does one full handshake after a reload.

Opening a connection is charged to the prefix's [rate
limit](rate-limiting.md#rate-limiting), per /24 and /64 only, and a refusal is
cheap rather than free. **If you expose DoT or DoH to the internet, rate-limit new
connections per source in front of the resolver**: see [a connection rate limit in
front](public-resolver.md#a-connection-rate-limit-in-front). The handshake-flood
figures are on [the same page](public-resolver.md#handshake-floods).

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
Committed runs are under `bench/results/`: read them as the shape of the thing,
and re-take them rather than quoting an old run against a change.

On disk, `log.queries` writes a line per query and wants rotation. Nothing else
is written in steady state; the blocklist cache is the size of the lists.
