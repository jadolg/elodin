# Charging a client for arriving

Measured 2026-09-04 on the machine the reports beside it were taken on — a
4-core aarch64 Linux VM with 7 GB of RAM — from `o:speed` builds of `main` and of
the branch that adds a per-prefix budget on accepted connections (issue #247).

```
mise run release
cd bench && go run ./cmd/rrlexp -only handshake-flood -duration 10s -warmup 2s
```

Nine arms: the seven of `2026-09-03-handshake-floods.md`, which is where the load
is described and why it was the last uncharged one, plus a UDP bystander and its
own quiet baseline, which are new and are explained under **What it did to the
datagram path**. Every arm was run twice, back to back on an otherwise idle box —
once against a `main` binary and once against the patched one — so both columns
below come from the same machine on the same afternoon rather than from one report
quoted at another.

What changed in the server: opening a connection is charged to the client
prefix's own pool, refilled at `server.rate_limit.responses_per_second` like the
response budgets and spent in the accept loop before a thread exists and before
any TLS handshake. Two counters were added with it, because the condition was
invisible from inside the server:
`elodin_connections_rate_limited_total` and `elodin_tls_handshakes_total`.

## What the flood drew

| arm | | attempted/s | completed/s | CPU/s | CPU per handshake | `conn_refused` | `conn_rate_limited` |
|---|---|---:|---:|---:|---:|---:|---:|
| `handshake-flood/dot` | before | 6,032 | **6,032** | **1.25** | 208 µs | 0 | — |
| | after | 25,129 | **462** | **0.29** | 624 µs | 0 | 282,053 |
| `handshake-flood/dot/same-prefix` | before | 5,975 | 5,975 | 1.25 | 209 µs | 0 | — |
| | after | 27,394 | 461 | 0.25 | 542 µs | 0 | 311,214 |
| `handshake-flood/doh` | before | 5,999 | 5,999 | 1.33 | 221 µs | 0 | — |
| | after | 27,477 | 461 | 0.25 | 541 µs | 0 | 317,022 |
| `handshake-flood/arriving-client` | before | 6,475 | 6,475 | 1.36 | 210 µs | 0 | — |
| | after | 25,874 | 462 | 0.26 | 565 µs | 0 | 299,471 |
| `handshake-flood/udp-bystander` | before | 6,931 | 6,931 | 1.42 | 205 µs | 0 | — |
| | after | 27,499 | 462 | 0.25 | 542 µs | 0 | 307,680 |

Handshakes completed fall by a factor of thirteen and land on the figure the
budget names: 461 or 462 a second against a configured 500, the gap being the
burst spent during the warm-up and the handshakes the generator had in flight when
the window closed. Server CPU falls from 1.25–1.42 of four cores to 0.25–0.29 — a
fifth — and `conn_rate_limited` is around three hundred thousand, where before
there was no counter to read and `conn_refused` sat at zero.

The server's own `elodin_tls_handshakes_total` agrees with the generator: 6,536 to
6,539 across those five arms, against the twelve seconds of warm-up plus window at
461 a second and the victim's own connections. Before the change that number did
not exist, which is the whole of what an operator had to work from: `conn_refused`
zero, `elodin_rate_limited_total` zero, `elodin_queries_total` a few hundred, and a
third of the box gone.

Two columns to read carefully.

**`attempted/s` more than quadruples.** Refusing at the accept costs a prefix
compare and a close, so the same 32 workers get through four times as many dials a
second. That is the shape the `share` arm already showed on 2026-09-03 and it is
the bound working, not failing: what the server spends is a fifth of what it did
while the flood offers four times as much.

**`CPU per handshake` is not a handshake's price any more.** It is the arm's whole
CPU over the handshakes that completed, and after the change most of the numerator
is 25,000-plus accept-and-closes a second rather than key work. Read it as what the
flood paid per handshake it got — which tripled — and read `CPU/s` for what the
server spent.

## What it did to the bystander on a connection

| arm | victim | before | after |
|---|---|---|---|
| `handshake-flood/quiet-baseline-dot` | DoT, another /24, nobody else here | 488/500 (98%), p50 253.2 ms | 490/500 (98%), p50 259.0 ms |
| `handshake-flood/dot` | DoT, another /24 | 409/499 (**82%**), p50 **1.0982 s** | 440/500 (**88%**), p50 **718.5 ms** |
| `handshake-flood/dot/same-prefix` | DoT, inside the flooded /24 | 394/500 (79%), p50 1.2622 s | 449/500 (90%), p50 623.7 ms |
| `handshake-flood/doh` | DoT, another /24 | 409/500 (82%), p50 1.1387 s | 449/500 (90%), p50 705.2 ms |
| `handshake-flood/arriving-client` | TCP, another /24, one connection per query | 342/342 (100%), p50 26.2 ms | 385/385 (100%), p50 23.5 ms |

Half to two thirds of the damage, and not all of it. The DoT client running its
one connection at capacity goes from losing 16 points of its answer rate to losing
10, and from four times the quiet latency to under three times it. It does not come
back to the baseline, and the reason is the row above: 25,000 accepts and closes a
second is not free, and nothing in this server bounds how many times a client may
be *refused*.

That is the honest limit of an in-server budget and the reason the documentation
says what it says. A refusal has to be cheaper than the thing refused or the bound
is worse than nothing, and it is — but the only place to stop a peer from making
the server refuse it is in front of the server, in the packet filter or whatever
terminates TLS. What the budget buys is that a single unspoofed client cannot
spend a third of the resolver, and that the operator can now see it happening.

The `same-prefix` arm is worth a second look. It is the victim *inside* the flooded
/24, so it shares the arrival budget with the flood, and it comes out level with
the arm outside it (90% against 88%) rather than worse. Its own connection is
already open, and the queries on it are charged to the stream pool, which the
arrivals cannot touch — the trade the pools exist to make, doing what it is for. A
client in that /24 *reconnecting* mid-flood would be the one paying, and
`arriving-client` measures that shape from another prefix rather than this one.

## What it did to the datagram path

| arm | victim | before | after |
|---|---|---|---|
| `handshake-flood/quiet-baseline-udp` | UDP, another /24, nobody else here | 500/500 (100%), p50 20.3 ms | 500/500 (100%), p50 20.4 ms |
| `handshake-flood/udp-bystander` | UDP, another /24, flood running | 500/500 (100%), p50 24.3 ms | 500/500 (100%), p50 22.5 ms |

These two arms are new, and the reason to add them came from the change rather
than from the finding. The limiter keeps one mutex over its bucket table, and the
accept loop now takes it once per accepted connection — the same mutex the UDP
readers take for every datagram. Separate pools stop one class from spending
another's tokens; they do nothing about a lock. So a flood that dials four times
faster because refusals are cheap is also a flood taking that lock 27,000 times a
second, and every victim in the section above is on a connection, downstream of the
accept loop anyway. A UDP client in an unrelated prefix is what would show it.

It does not show. Every query answered in both columns, and the p50 goes from
24.3 ms to 22.5 ms against a quiet baseline of 20.3 and 20.4 — the flood costs a
UDP bystander about 4 ms of median latency before the change and about 2 ms after
it. The critical section is a hash, a compare and a few flops, so 27,000 more
acquisitions a second against a mutex nobody holds for long is not where this
server's time goes; the CPU the flood stopped spending is.

Read this as "the datagram path did not pay for the stream path", not as a
statement about lock contention in general. One arm at one rate on four cores does
not bound what a much larger accept rate would do, and the honest answer to a much
larger accept rate is the filter in front.

## What a share does now

The pair that pins a table of 64 against 64 dialers, which is where a share is
small enough to be reached at all:

| arm | table | share | | completed/s | refused/s | CPU/s | `conn_refused` | victim answered |
|---|---:|---:|---|---:|---:|---:|---:|---:|
| `handshake-flood/no-share` | 64 | 64 | before | 6,410 | 2,015 | 1.34 | 23,444 | 260/310 (84%), 50 connections closed |
| | | | after | 462 | 19,821 | 0.27 | 140 | 287/287 (**100%**) |
| `handshake-flood/share` | 64 | 32 | before | 4,066 | 11,769 | 0.92 | 139,403 | 279/279 (100%) |
| | | | after | 462 | 21,283 | 0.24 | 782 | 298/298 (100%) |

The arrival budget reaches this load long before either table figure does, so the
two arms now measure the same thing and both answer the arriving client every
query. `conn_refused` falls by two orders of magnitude in both, because a
connection refused at the budget never asks the table for a slot — which also
means the pair no longer separates what a share is worth from what the budget is
worth. It is kept because the *before* column is still the only measurement of a
share against this load, and because a run that showed the share doing the work
after this change would mean the budget had stopped.

## What this does not say

**Nothing here is spoofed, and nothing here is a botnet.** A handshake proves the
address it came from, so every one of these connections is a real client at a real
address — which is why an in-server budget can bound it at all. It is also why the
bound is per prefix and therefore multipliable: an actor with addresses in n
prefixes has n of the figure, and on IPv6 a routine /48 is 65,536 /64s. Same
granularity and same limitation as the response budget, and the reason the README
tells a publicly reachable instance to put a per-source connection rate limit in
front of the resolver as well.

**The baselines have run-to-run spread and the arms are read against the ones
taken beside them.** The DoT baseline reads 98% here in both runs against the 100%
of 2026-09-03: a DoT client offering 50 q/s on one connection against a 20 ms
upstream is already at its ceiling, which is the one figure in this harness that
moves on its own. The UDP baseline does not move at all.

**The default is what was measured.** `responses_per_second` is 500 in both runs,
which is what elodin ships; nothing here says whether 500 arrivals a second is the
right figure for a given deployment, only that the figure now bounds something it
did not bound before. An instance whose clients hold their connections open can
take it far lower.

**ECDSA is still the cheap case.** These arms serve a P-256 certificate, about half
what RSA-2048 costs per handshake. An operator serving RSA should read the
before-column CPU as roughly double, and the after-column as roughly unchanged —
the whole point of the change is that the key work is what stops happening.
