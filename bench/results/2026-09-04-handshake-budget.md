# Charging a client for arriving

Measured 2026-09-04 on the machine the reports beside it were taken on — a
4-core aarch64 Linux VM with 7 GB of RAM — from `o:speed` builds of `main` and of
the branch that adds a per-prefix budget on accepted connections (issue #247).

```
mise run release
cd bench && go run ./cmd/rrlexp -only handshake-flood -duration 10s -warmup 2s
```

The same seven arms as `2026-09-03-handshake-floods.md`, run twice: once against
a `main` binary and once against the patched one, back to back on an otherwise
idle box. That report is where the load is described and why it was the last
uncharged one; this one is the before and after, and the both-halves reading of
what the bound is worth.

What changed in the server: opening a connection is charged to the client
prefix's own pool, refilled at `server.rate_limit.responses_per_second` like the
response budgets and spent in the accept loop before a thread exists and before
any TLS handshake. Two counters were added with it, because the condition was
invisible from inside the server:
`elodin_connections_rate_limited_total` and `elodin_tls_handshakes_total`.

## What the flood drew

| arm | | attempted/s | completed/s | CPU/s | CPU per handshake | `conn_refused` | `conn_rate_limited` |
|---|---|---:|---:|---:|---:|---:|---:|
| `handshake-flood/dot` | before | 6,469 | **6,469** | **1.35** | 208 µs | 0 | — |
| | after | 28,485 | **461** | **0.23** | 498 µs | 0 | 332,513 |
| `handshake-flood/dot/same-prefix` | before | 6,091 | 6,091 | 1.29 | 211 µs | 0 | — |
| | after | 27,294 | 461 | 0.24 | 522 µs | 0 | 317,097 |
| `handshake-flood/doh` | before | 6,452 | 6,452 | 1.35 | 209 µs | 0 | — |
| | after | 28,192 | 461 | 0.22 | 487 µs | 0 | 323,467 |
| `handshake-flood/arriving-client` | before | 6,358 | 6,358 | 1.39 | 218 µs | 0 | — |
| | after | 26,873 | 462 | 0.23 | 492 µs | 0 | 310,387 |

Handshakes completed fall by a factor of fourteen and land on the figure the
budget names: 461 a second against a configured 500, the gap being the burst
spent during the warm-up and the handshakes the generator had in flight when the
window closed. Server CPU falls from 1.35 of four cores to 0.23 — a sixth — and
`conn_rate_limited` is a third of a million, where before there was no counter to
read and `conn_refused` sat at zero.

The server's own `elodin_tls_handshakes_total` agrees with the generator: 6,539,
6,537, 6,538 and 6,538 for the four arms, against the twelve seconds of warm-up
plus window at 461 a second and the victim's own connections. Before the change
that number did not exist, which is the whole of what an operator had to work
from: `conn_refused` zero, `elodin_rate_limited_total` zero,
`elodin_queries_total` a few hundred, and a third of the box gone.

Two columns to read carefully.

**`attempted/s` more than quadruples.** Refusing at the accept costs a prefix
compare and a close, so the same 32 workers get through four and a half times as
many dials a second. That is the shape the `share` arm already showed on
2026-09-03 and it is the bound working, not failing: what the server spends is a
sixth of what it did while the flood offers four times as much.

**`CPU per handshake` is not a handshake's price any more.** It is the arm's whole
CPU over the handshakes that completed, and after the change most of the numerator
is 28,000 accept-and-closes a second rather than key work. Read it as what the
flood paid per handshake it got — which more than doubled — and read `CPU/s` for
what the server spent.

## What it did to the bystander

| arm | victim | before | after |
|---|---|---|---|
| `handshake-flood/quiet-baseline-dot` | DoT, another /24, nobody else here | 483/499 (97%), p50 254.4 ms | 487/499 (98%), p50 233.0 ms |
| `handshake-flood/dot` | DoT, another /24 | 412/500 (**82%**), p50 **981.8 ms** | 457/500 (**91%**), p50 **597.1 ms** |
| `handshake-flood/dot/same-prefix` | DoT, inside the flooded /24 | 402/500 (80%), p50 1.1046 s | 459/500 (92%), p50 665.5 ms |
| `handshake-flood/doh` | DoT, another /24 | 411/499 (82%), p50 934.2 ms | 457/500 (91%), p50 522.3 ms |
| `handshake-flood/arriving-client` | TCP, another /24, one connection per query | 332/332 (100%), p50 26.4 ms | 395/395 (100%), p50 22.9 ms |

Half the damage, and not all of it. The DoT client running its one connection at
capacity goes from losing 15 to 17 points of its answer rate to losing 6 or 7, and
from four times the quiet latency to two and a half times it. It does not come
back to the baseline, and the reason is the row above: 28,000 accepts and closes a
second is not free, and nothing in this server bounds how many times a client may
be *refused*.

That is the honest limit of an in-server budget and the reason the documentation
says what it says. A refusal has to be cheaper than the thing refused or the bound
is worse than nothing, and it is — but the only place to stop a peer from making
the server refuse it is in front of the server, in the packet filter or whatever
terminates TLS. What the budget buys is that a single unspoofed client cannot
spend a third of the resolver, and that the operator can now see it happening.

The baseline arm reads 97% and 98% in these two runs against the 100% of
2026-09-03. It is the one figure in this harness with real run-to-run spread — a
DoT client offering 50 q/s on one connection against a 20 ms upstream is already
at its ceiling — so the before and after columns are read against each other and
against the baseline taken beside them, not against another day's.

## What a share does now

The pair that pins a table of 64 against 64 dialers, which is where a share is
small enough to be reached at all:

| arm | table | share | | completed/s | refused/s | CPU/s | `conn_refused` | victim answered |
|---|---:|---:|---|---:|---:|---:|---:|---:|
| `handshake-flood/no-share` | 64 | 64 | before | 6,266 | 1,836 | 1.36 | 21,223 | 255/298 (86%), 43 connections closed |
| | | | after | 462 | 24,461 | 0.23 | 113 | 320/320 (**100%**) |
| `handshake-flood/share` | 64 | 32 | before | 4,127 | 12,020 | 0.92 | 141,356 | 281/281 (100%) |
| | | | after | 462 | 24,986 | 0.22 | 731 | 321/321 (100%) |

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

**The default is what was measured.** `responses_per_second` is 500 in both runs,
which is what elodin ships; nothing here says whether 500 arrivals a second is the
right figure for a given deployment, only that the figure now bounds something it
did not bound before. An instance whose clients hold their connections open can
take it far lower.

**ECDSA is still the cheap case.** These arms serve a P-256 certificate, about half
what RSA-2048 costs per handshake. An operator serving RSA should read the
before-column CPU as roughly double, and the after-column as roughly unchanged —
the whole point of the change is that the key work is what stops happening.
