# The DoT tail was the generator's

Issue #610: since #604, elodin's DoT p99 at 100 clients read ~3 ms against
0.6 ms before (`2026-11-05-competition.md`). Measured with a second generator,
the tail is not the server's. This run is why the harness now drives UDP, TCP
and DoT with dnsperf (see the README's "The load generators").

4-core arm64 VM (Linux 7.0.0-42-generic). elodin release builds of `3417de8`
(the merge before #604) and `e11e4e6` (main). Server on CPUs 0-1, generator
and mock upstream on 2-3, 100 clients, every answer from the cache, 6 s after
a 2 s warmup. loadgen is `bench/cmd/loadgen` at `e11e4e6`; dnsperf is 2.15.0
(`-c 100 -q 100 -T 2 -O latency-histogram`).

## At the same offered load

270,000 queries a second, below both builds' ceilings, so the two do the same
work. Alternating runs.

| generator | transport | before #604: p99 | main: p99 |
|---|---|---|---|
| loadgen | DoT | 0.50, 0.43, 0.45 ms | 3.24, 3.27, 3.24 ms |
| loadgen | TCP | 0.61, 0.59 ms | 2.63, 2.61 ms |
| dnsperf | DoT | 1.21, 0.83 ms | 0.78, 1.01 ms |
| dnsperf | TCP | 1.09, 0.94 ms | 0.69, 0.46 ms |

loadgen puts main's tail near 3 ms on TCP as well, below TCP's ceiling.
dnsperf puts main level with or ahead of the build before #604 on both.

## Where the 3 ms is

`perf sched` over 2 s of the loadgen run at 270,000 DoT queries a second on
main:

- elodin's threads were delayed more than 2 ms once, in 39,900 switches in.
- loadgen's threads were delayed more than 2 ms 500 times, in 8,795. During those
  waits the CPU ran another loadgen thread, or nothing.
- Waking an elodin thread (`sched_waking` to `sched_wakeup`, which on an idle
  target CPU is traced only once that CPU is up) took p99 0.044 ms, max 3.7 ms
  over 35,300 wake-ups. An idle vCPU is not slow to wake.

Pinned to two CPUs, the Go runtime runs two Ps. With only loadgen's
`GOMAXPROCS` changed, on main at saturation:

| loadgen GOMAXPROCS | DoT qps | DoT p99 |
|---|---|---|
| 2 (the default here) | 323,334, 325,468 | 3.02, 2.89 ms |
| 3 | 361,589, 344,911 | 1.03, 1.38 ms |
| 4 | 381,670, 387,219 | 0.82, 0.80 ms |
| 8 | 425,422, 426,089 | 0.49, 0.52 ms |
| 32 | 452,572 | 0.46 ms |
| 100 | 429,933 | 1.80 ms |

No setting suits every row. With `GOMAXPROCS=4` loadgen's UDP p99 went from
0.33–0.53 ms to 0.75 ms. That is why the fix is a second generator rather
than a setting.

## Saturated, under dnsperf

| build | DoT | TCP |
|---|---|---|
| before #604 | 308,269 / 0.64 ms; 306,820 / 0.72 ms | 372,365 / 0.53 ms |
| main | 407,045 / 0.53 ms; 460,594 / 0.32 ms | 522,340 / 0.32 ms |

## The harness, after the change

`go run ./cmd/bench -only compare -servers elodin -mock-cpus 2-3 -repeat 3
-duration 6s -warmup 2s -cooldown 2s`, with `-binary` for the build before
#604. The cache-hit row is throughput / p99 / CPU per query:

| build | UDP | TCP | DoT | DoH/1.1 | DoH/2 | blocked (UDP) |
|---|---|---|---|---|---|---|
| before #604 | 668,935 / 0.23 ms / 2 µs | 377,414 / 0.51 ms / 5 µs | 297,246 / 0.81 ms / 6 µs | 144,709 / 3.1 ms / 10 µs | 126,966 / 2.9 ms / 13 µs | 662,080 / 0.26 ms / 2 µs |
| main | 758,572 / 0.41 ms / 2 µs | 552,223 / 0.32 ms / 3 µs | 437,391 / 0.38 ms / 4 µs | 138,043 / 3.0 ms / 9 µs | 130,656 / 2.7 ms / 11 µs | 731,576 / 0.28 ms / 2 µs |

The DoH cells are still loadgen's. CPU per query is now counted from the end
of the warmup, as the answers it is divided by are. Before, the warmup's CPU
was counted as well, which put every CPU figure 20% high at the default 2 s
warmup and 10 s run (DoH/2 11 µs, against 13 µs in the 2026-11-05 run).

## server.pin_loops, re-measured

The p99.5 figure in `docs/sizing.md` (2.1–3.3 ms to 1.0–1.4 ms) was taken with
loadgen. Under dnsperf, DoT at 200,000 a second, main, three alternating pairs:

| pin_loops | p99 | p99.5 | p99.9 |
|---|---|---|---|
| false | 0.77, 0.67, 0.61 ms | 1.31, 1.18, 1.12 ms | 2.56, 3.01, 3.01 ms |
| true | 0.62, 0.64, 0.66 ms | 0.97, 1.09, 1.05 ms | 3.14, 2.62, 3.01 ms |
