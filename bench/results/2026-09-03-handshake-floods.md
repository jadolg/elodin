# A client that only handshakes

Measured 2026-09-03 on the machine the reports beside it were taken on — a
4-core aarch64 Linux VM with 7 GB of RAM — from an `o:speed` build of the branch
that adds these arms:

```
mise run release
cd bench && go run ./cmd/rrlexp -only handshake-flood -duration 10s -warmup 2s
```

The selector takes all seven arms below, the quiet DoT baseline they are read
against included.

The gap this closes is the second one issue #235 lists. `cmd/bench
-transport=handshake` already says what a fresh TLS handshake costs, as a
throughput figure taken from a server with nobody else on it. What nothing
measured is a client doing *only* handshakes while somebody else is trying to
resolve — and that is the load with the least standing in the way of it. The
response budget is spent by answers, so a client that never sends a query is
never charged. `server.max_connections` and its per-prefix share bound how many
connections are *held*, and this client holds each one for as long as a handshake
takes and then hangs up.

Seven arms, ten measured seconds each after two of the same load. The flood is 32
workers dialling, handshaking and closing in a loop — concurrency rather than a
rate, since there is nothing to pace. Two kinds of victim: a DoT client holding
one connection and asking 50 q/s, which is what a DoT stub resolver is, and a
plain TCP client opening a connection per query, which is what a client *arriving*
during the flood is.

## What the flood drew, and what it cost

| arm | flood | completed/s | CPU/s | CPU per handshake | `conn_refused` |
|---|---|---:|---:|---:|---:|
| `handshake-flood/dot` | DoT | **6,922** | **1.41** | 204 µs | **0** |
| `handshake-flood/dot/same-prefix` | DoT | 6,539 | 1.35 | 207 µs | **0** |
| `handshake-flood/doh` | DoH (h2 ALPN) | 6,950 | 1.44 | 207 µs | **0** |
| `handshake-flood/arriving-client` | DoT | 7,224 | 1.49 | 206 µs | **0** |

Seven thousand handshakes a second, about 205 µs of server CPU each, which is 1.4
of this machine's four cores — and `conn_refused` is **zero** in every row. With
the shipped configuration nothing refused anything: the table is 512 with a share
of 256, the flood holds at most 32 connections at once, and so neither bound is
ever reached. The limiter is on at its default throughout and
`elodin_rate_limited_total` is zero too, because this client asks nothing.

The DoH listener is the same story as the DoT one. Framing and HPACK are not
reached — the flood closes the moment the handshake is up, before an h2 preface —
so what the arm confirms is that the two accept paths cost the same, not what an
h2 request costs. The `doh2` arms in
`2026-09-03-rate-limit-bystander.md` are where that is measured.

## What it did to the bystander

| arm | victim | answered | p50 | p99 |
|---|---|---:|---:|---:|
| `handshake-flood/quiet-baseline-dot` | DoT, another /24, nobody else here | 500/500 (**100%**) | 153.4 ms | 440.8 ms |
| `handshake-flood/dot` | DoT, another /24 | 419/499 (**84%**) | **943.5 ms** | 2.0082 s |
| `handshake-flood/dot/same-prefix` | DoT, inside the flooded /24 | 410/500 (82%) | 1.01 s | 2.1211 s |
| `handshake-flood/doh` | DoT, another /24 | 412/500 (82%) | 1.0865 s | 2.1321 s |
| `handshake-flood/arriving-client` | TCP, another /24, one connection per query | 354/354 (**100%**) | 25.2 ms | 46.6 ms |

Two different answers, and the difference is the point.

A **DoT client running its one connection at capacity** loses 16 to 18 points of
its answer rate and six times its latency. Read the baseline first: a stream
connection is served one query at a time and an upstream round trip is 20 ms, so
a client offering 50 q/s on a single connection is already at its ceiling, and
already sitting at 153 ms with the server to itself — the same effect
`quiet-baseline/tcp` has shown since the first run of this harness, and the one
figure here with real run-to-run spread (an earlier run of the same arm gave
234 ms). The flood does not create that queue. It makes it six times as long.

A **client arriving during the flood** is unaffected: every query answered at one
upstream round trip. The prefix makes no difference either — inside the flooded
/24 (82%) or outside it (84%) is the same result, which is what you would expect
of a load nothing charges to a prefix in the first place.

So this is not a resolver being knocked over. It is a resolver spending a third
of itself on work nobody asked it to do, with the cost landing on whichever
clients were already running their connections hard.

## What a share can do about it, and what it cannot

The last pair pins a table of 64 with 64 dialers against it, so that the share is
smaller than the flood's concurrency and therefore reachable at all:

| arm | table | share | attempted/s | completed/s | refused/s | CPU/s | victim answered |
|---|---:|---:|---:|---:|---:|---:|---:|
| `handshake-flood/no-share` | 64 | 64 | 9,149 | **7,061** | 2,088 | **1.46** | 269/335 (80%), 66 connections closed |
| `handshake-flood/share` | 64 | 32 | 17,720 | **4,529** | 13,190 | **0.99** | 294/294 (**100%**) |

A share bounds how many handshakes run *at once*, which turns out to bound the
rate too: 7,061 completed a second becomes 4,529, and 1.46 of a core becomes
0.99. The arriving client goes from having 66 of its connections closed on it to
being served every query it asks. `conn_refused` is 24,224 in the first row and
154,791 in the second — the refusals a share buys are cheap, which is why the CPU
falls by a third while the attempts nearly double.

That is a bound on the cost, not a defence against it. The flood still gets four
and a half thousand handshakes a second out of a table it is being held to half
of, and on the shipped 512/256 a flood of this shape reaches neither figure. A
share sized to be a bound nobody trips over is not a share that stops this.

## What this does not say

**The seven thousand is this machine's ceiling, not an attacker's.** The flood, the
victim and the server share four cores here, and the flood's own TLS work is paid
for out of the same ones. A generator with the bandwidth of a botnet behind it
would reach further; what the arm establishes is the *price per handshake* and
that nothing bounds the number of them.

**Nothing here is spoofed.** A handshake proves the address it came from, so
every one of these connections is a client that really is where it says it is —
which is exactly why the answer to this load is a per-source connection *rate*
limit, in front of the resolver where such a thing belongs (nftables, or whatever
terminates TLS in the deployment). `server.max_connections_per_prefix` is a limit
on occupancy and cannot be made into one on arrivals without becoming a limit on
legitimate reconnection too.

**ECDSA is already the cheap case.** These arms serve a P-256 certificate, which
is about half of what RSA-2048 costs per handshake — the reason `mise run certs`
generates ECDSA. An operator serving RSA should read the CPU column as roughly
double.
