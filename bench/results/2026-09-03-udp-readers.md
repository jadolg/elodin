# How fast the UDP socket can be drained

Measured 2026-09-03 from an `o:speed` build of the `fix/233-udp-reader-scaling`
branch (base 0076bf4), on the same 4-core aarch64 Linux VM with 7 GB of RAM that
`2026-09-03-rate-limit-bystander.md` was taken on.

Issue #233 asks what happens above the rate at which this server can *read*.
Everything a datagram costs before the rate limiter can see it — the `recvfrom`,
the allow-list compare, the siphash of the source prefix — happens on the thread
that read it, so a single reader is one core's worth of drain rate for the whole
server. Past it the kernel's receive queue overflows and datagrams are dropped by
the socket, where no budget in this server can reach them: the client whose query
is lost is whichever one the queue was full for, which is where the limiter's
fairness properties stop applying.

The change under test gives each reader a socket of its own on the same port
(`SO_REUSEPORT`) and so a receive queue of its own, and counts what the kernel
dropped on each. The arms are the flood from `other-prefix/flat-out` — flat out,
four sockets, at a prefix the victim is not in — with the reader count pinned at
one, two and four, and the server confined to two CPUs so that the load generator
in the harness process is not competing for the cores the readers want.

**Read this run for the ceiling it establishes and not for a speed-up. It does
not show one.**

## What each arm read, and what the kernel threw away

| arm | CPU/s | peak RSS | read | queue drops | drops as % of arrivals | offered/s |
|---|---:|---:|---:|---:|---:|---:|
| readers/one | 0.84 | 90 MB | 22,917,281 | 917,954 | 3.9% | 1,980,631 |
| readers/two | 0.84 | 91 MB | 16,976,125 | 1,628,263 | 8.7% | 1,527,443 |
| readers/four | 0.85 | 90 MB | 17,748,268 | 2,142,375 | 10.8% | 1,653,607 |

Ten measured seconds after two of the same load. Three earlier eight-second runs
of the same three arms agree with these to within a point, and the ordering —
one reader reading the most and dropping the least — was the same in all four.

## The victim, which is the question the arms were built to ask

| arm | victim | offered | answered | p50 | p99 |
|---|---|---:|---:|---:|---:|
| readers/one | 127.1.0.1 | 500 | 490 (98%) | 32.9ms | 55ms |
| readers/two | 127.1.0.1 | 500 | 491 (98%) | 29.8ms | 59.9ms |
| readers/four | 127.1.0.1 | 499 | 480 (96%) | 30.9ms | 56.7ms |

## What holds

**One reader drains 2.3 million datagrams a second here, which is more than this
machine can offer it.** 22.9M datagrams read in ten seconds, at 0.84 cores for
the whole process — the reader thread is not saturated, and the flood is being
generated on the same four cores it is running on. That is the number to quote
for "where it ends" on this hardware: `recvfrom`, the allow-list compare, the
siphash and the limiter's own arithmetic come to about 400 ns of one core per
datagram.

**The queue does drop, and nothing but this counter sees it.** Between 0.9M and
2.1M datagrams a run never reached a read: they are charged to no budget, counted
in no other series, and their absence at the client is indistinguishable from a
query nobody sent. `elodin_udp_receive_drops_total` is the whole of the visibility
into that, which is the half of #233 this run does settle.

**The bystander loss that motivated #233 is already gone, and was not the
reader's doing.** That arm measured 64% for a client in an unrelated /24; here the
same flood leaves it at 96–98% with a single reader. The difference is the fix
for issue #232: the slip's truncated answers were charged to no budget, so the
read loop was performing half a million sends a second of its own on top of the
reads. `2026-09-03-slip-budget.md` records that, and the header of the bystander
file says so. The read-side ceiling is real; the 36% was mostly the writes.

## What this run does not show

**No benefit from more readers, and on this bench a cost.** Two and four readers
read *less* and dropped *more* than one, and the offered rate fell by about 20%
when they were configured. The measurement cannot separate the reader count from
the machine: on loopback the sender delivers the datagram into the receiving
socket's queue inside its own `sendto`, so the `SO_REUSEPORT` hash and the extra
sockets are paid for by the load generator, which is running on the same four
cores as the server it is measuring. A second machine, or a real NIC with
interrupts to spread, is what would answer this properly.

So the reader count in this branch is headroom above a ceiling this hardware
cannot reach, on the reasoning that a single thread cannot exceed one core's
syscall rate and a 10 GbE link can deliver several times what one core here
drains. It is not a measured improvement, and nothing in the documentation should
say that it is. The mechanism it copies — a socket and a reader per core, as BIND
and Unbound do — is worth having for the same reason they have it, and the drop
counter is what tells an operator whether their own instance needs it.

**A packet filter in front of a publicly reachable instance is still the
mitigation.** Nothing here changes that: at 2 million datagrams a second the
kernel was dropping 4% of arrivals with a reader that was not even saturated,
and above the drain rate the thing choosing which clients are served is the
queue rather than the budget.

## Reproducing

```sh
mise run release
cd bench && go run ./cmd/rrlexp -only readers -duration 10s -warmup 2s -server-cpus 0,1
```

`-server-cpus` is what keeps the server off the generator's cores; without it the
arms differ by how much machine the generator got as well as by the reader count.
`-only readers` runs these three arms alone — the rest of the matrix is about the
rate limiter and is documented in `2026-09-03-rate-limit-bystander.md`.

The `read` and `queue drops` columns are `elodin_udp_datagrams_total` and
`elodin_udp_receive_drops_total`, summed over the readers, and the second of them
comes from the kernel's own counter in `/proc/net/udp` rather than from anything
this server does.
