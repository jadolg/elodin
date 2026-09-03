# Charging the slip: what a budget of its own changes

Measured 2026-09-03 from an `o:speed` build of the slip-budget change, on a
4-core aarch64 Linux VM with 7 GB of RAM — the same machine class as
`2026-09-03-rate-limit-bystander.md`, which is the run every "before" figure
below comes from. Shipped limiter defaults (500 responses/s per /24, `slip: 2`,
`max_udp_response` 1232), `workers` 64 and `upstream_workers` 32 pinned, mock
upstream at 20 ms answering 70 A records — 1151 bytes.

Two arm groups rather than all twenty-one: `cached-flood`, where the flood asks
one cached name flat out and so measures what an attacker can aim at an address,
and `same-prefix`, where the bystander shares the flooded /24 and so measures
what the slip is *for*. The change touches nothing the other arms ask about. Ten
measured seconds per arm after two of the same load, so no arm reports a fresh
bucket's burst.

What changed in the code: a truncated answer is charged to a third per-prefix
pool, refilled at an eighth of `responses_per_second` — 62 a second at the
default. Before, it was charged to nothing, so `slip: 2` meant one truncated
answer per two over-limit datagrams however many of those arrived.

## What the flood delivered to the address it named

| arm | offered/s | answered/s | truncated/s | MB/s at that address |
|---|---:|---:|---:|---:|
| cached-flood/limiter-on — **before** | 2,062,844 | 500 | 497,131 | **18.97** |
| cached-flood/limiter-on — **after** | 1,911,992 | 462 | **58** | **0.54** |
| cached-flood/slip-0 — before | 2,004,652 | 500 | 0 | 0.58 |
| cached-flood/slip-0 — after | 1,892,321 | 462 | 0 | 0.53 |
| cached-flood/limiter-off — before | 1,298,930 | 152,680 | 0 | 176.65 |
| cached-flood/limiter-off — after | 1,309,781 | 109,256 | 0 | 126.41 |

0.58 MB/s was the budget's own arithmetic and the figure the documentation
implied — 500 answers of 1151 bytes. The shipped default delivered 33× that, and
the excess had no ceiling in it: it was half the arrival rate, whatever the
arrival rate was. It is now 0.54 MB/s, which is `slip: 0`'s figure plus 58
40-byte replies, and the 58 is the pool rather than a fraction of the two million
datagrams that drew it.

The `limiter-off` rows differ between runs by a third. That is this machine's
capacity to answer a cached name and not anything the change touches; both
arms are floors on the reflection a limiter prevents rather than worst cases.

## What it cost a bystander in an unrelated /24

500 queries offered at 50 q/s from `127.1.0.1` while `127.0.0.1` floods flat out.

| arm | answered | truncated | no reply | p50 | p99 |
|---|---:|---:|---:|---:|---:|
| cached-flood/limiter-on — **before** | 274 (55%) | 0 | 226 | 40.7ms | 73.2ms |
| cached-flood/limiter-on — **after** | **493 (99%)** | 0 | 7 | 33.6ms | 59.4ms |
| cached-flood/slip-0 — before | 493 (99%) | 0 | 6 | 32.4ms | 53.6ms |
| cached-flood/slip-0 — after | 495 (99%) | 0 | 5 | 34.1ms | 68.5ms |

This is the second cost the uncharged slip imposed, and it was the larger one.
Half a million small writes a second come off the single thread reading the UDP
socket, and prefix isolation cannot help a client whose query was never read: a
bystander in a /24 nobody was flooding lost 44 points of its answer rate to it.
With the slip charged, the default now measures what `slip: 0` measures — 99%,
which is the whole point of keeping a limiter on at all.

Server CPU over the window fell with it, 0.97 cores to 0.86, `slip: 0` being 0.91
before and 0.86 after.

## What it cost the bystander the slip exists for

500 queries offered at 50 q/s from `127.0.0.3`, flooded from `127.0.0.2` — same
/24, so the two share every budget the limiter keeps.

| arm | answered in full | truncated | no reply |
|---|---:|---:|---:|
| same-prefix/limiter-on — **before** | 33 (7%) | **250 (50%)** | 217 |
| same-prefix/limiter-on — **after** | 15 (3%) | **1** | 484 |
| same-prefix/slip-0 — before | 77 (15%) † | 0 | 423 |
| same-prefix/slip-0 — after | 26 (5%) † | 0 | 474 |
| same-prefix/victim-on-tcp — before | 497 (99%) | 0 | 3 |
| same-prefix/victim-on-tcp — after | 499 (100%) | 0 | 1 |

† The one row the earlier report footnotes as moving run to run: repeats of it
answered 6, 6, 11, 18 and 77 of 500. 26 is inside that spread, and the racing is
for each refilled token — the flood empties the bucket, a token appears 2 ms
later, and whichever client asks in that instant takes it.

This is the loss, and it is real. The invitation to TCP that the flooded prefix's
own client used to get for half its queries now arrives once in 500. The
arithmetic is not the share's fault and no share fixes it: the pool is per prefix
because an attacker picks addresses freely inside one, so 62 invitations a second
spread across 19,500 over-limit datagrams a second reach the client sending 47 of
them about once every ten seconds. A pool of 500 would reach it twelve times in
500 queries instead of once — still not a signal.

Where the invitation does survive is the overload it was written for: a prefix
asking twice its budget has a few hundred over-limit datagrams a second for those
62 to land among, and one that lands moves the client onto the stream pool for
good — which is the `victim-on-tcp` row, 100% answered at every setting, out of a
budget no datagram flood can empty. What a 40×-over-budget flood inside your own
/24 costs you is now most of the UDP signal; what it cost everyone else was
19 MB/s at a stranger and 44 points off an uninvolved client.

`slip: 0` remains for a deployment that wants neither, and it is now within
0.01 MB/s and a couple of percent of the default on every figure above — which is
another way of saying the default stopped being the expensive choice.

## How it was run

```sh
mise run release
cd bench
go run ./cmd/rrlexp -duration 10s -warmup 2s -only cached-flood
go run ./cmd/rrlexp -duration 10s -warmup 2s -only same-prefix
```

`-slip 0` and `-rps` move the trade directly; `-flood-rate 0` is flat out, which
is what the `cached-flood` arms set for themselves.
