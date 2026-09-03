# The same isolation over IPv6

Measured 2026-09-03 on the machine the reports beside it were taken on — a
4-core aarch64 Linux VM with 7 GB of RAM — from an `o:speed` build of the branch
that adds these arms:

```
sudo ip -6 addr add fd00:1::2/128 dev lo     # the flood
sudo ip -6 addr add fd00:1::3/128 dev lo     # a victim in its /64
sudo ip -6 addr add fd00:2::1/128 dev lo     # a victim in another /64
mise run release
cd bench && go run ./cmd/rrlexp -duration 10s -warmup 2s          # both families
cd bench && go run ./cmd/rrlexp -only v6/ -duration 10s -warmup 2s   # the repeat
```

The whole matrix, so that the IPv4 rows quoted beside the IPv6 ones are from the
same run of the same binary on the same machine, and then the three IPv6 arms
again on their own — for the reason the last section gives.

The third gap issue #235 lists. Every other arm of this harness is IPv4
loopback, and the budget is kept per /24 there and per /64 here — one procedure
deciding both (`client_prefix` in `src/server/ratelimit.odin`), so these arms ask
whether the second half of it holds up as well as the first. `src/itest` has the
case that matters most, a `::` listener keeping the families apart after issue
#170; what an integration case cannot show is a bystander's answer rate.

Three arms against a server listening on `::1`, everything else as the IPv4 arms
have it: a 20,000 q/s flood from `fd00:1::2`, a victim asking 50 q/s, ten
measured seconds after two of the same load, and the shipped limiter defaults.

## The bystander

| arm | victim | answered | p50 | p99 |
|---|---|---:|---:|---:|
| `v6/other-prefix/limiter-on` | `fd00:2::1`, another /64 | **500/500 (100%)** | 20.4 ms | 21.6 ms |
| `other-prefix/limiter-on` | `127.1.0.1`, another /24 | 500/500 (100%) | 20.3 ms | 21.4 ms |
| `v6/other-prefix/limiter-off` | `fd00:2::1`, no limiter | 72/500 (**14%**) | 163.4 ms | 309.7 ms |
| `other-prefix/limiter-off` | `127.1.0.1`, no limiter | 81/499 (16%) | 163.2 ms | 186.6 ms |

A /64 flood leaves a neighbouring /64 alone, and the control says the limiter is
what did it: with the same flood and no limiter the same victim gets 14% of its
answers, at eight times the latency. The two families come out within a point of
each other on both rows.

## The flood, and what the read path cost

| arm | offered/s | answered/s | truncated/s | at the source | CPU/s | peak RSS |
|---|---:|---:|---:|---:|---:|---:|
| `v6/other-prefix/limiter-on` | 19,998 | 462 | 57 | 0.54 MB | **0.05** | 92 MB |
| `other-prefix/limiter-on` | 20,000 | 462 | 57 | 0.54 MB | **0.05** | 91 MB |
| `v6/other-prefix/limiter-off` | 19,998 | 3,099 | 0 | 3.59 MB | 0.09 | 127 MB |
| `other-prefix/limiter-off` | 19,999 | 3,110 | 0 | 3.60 MB | 0.09 | 120 MB |

**An IPv6 flood costs the read path nothing measurable over an IPv4 one.** Same
offered rate, same CPU per second to two decimal places, same bytes delivered to
the address the flood named. The budget is denominated in responses and the
answers are the same size, so the figure the limiter holds the flood to is the
same 462 a second either way; the eight bytes of prefix hashed instead of three
do not show up.

## The arm that is collateral damage by design

| run | victim | answered |
|---|---|---:|
| `v6/same-prefix/limiter-on`, first run | `fd00:1::3`, inside the flooded /64 | 74/500 (15%) |
| `v6/same-prefix/limiter-on`, second run | `fd00:1::3`, inside the flooded /64 | 17/500 (3%) |
| `same-prefix/limiter-on` | `127.0.0.3`, inside the flooded /24 | 11/500 (2%) |

A victim inside the flooded prefix shares the budget with the flood by design,
and how the shared budget splits between a client offering 50 q/s and one
offering 20,000 is a race rather than a ratio: two runs of the same arm gave 15%
and 3%. Read the row as "most of it is gone", which is the same thing the IPv4
arm says, and not as a difference between the families — there is no mechanism
that would make one.

## What this does not say

**Three addresses on `lo` are not two networks.** These arms are ULAs on the
loopback interface, which is what makes them local the way 127.0.0.0/8 is local
for the IPv4 arms. Nothing here traverses a link, so nothing here says anything
about neighbour discovery, extension headers, fragmentation, or a v6 path MTU —
all of which a real IPv6 deployment meets and none of which this harness can
reach.

**A machine without those addresses runs none of them.** IPv6 has one loopback
address and no equivalent of 127/8, so the harness cannot invent the sources it
needs. Without them the `v6/` arms are skipped, named in the run output and in
the report's *Arms this run could not take* section with the command that would
have let them run — the one thing worse than not measuring this would be a report
that reads as though it had.
