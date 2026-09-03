# A DoH/1.1 refusal that keeps the connection

Measured 2026-09-03 on the machine `2026-09-03-rate-limit-bystander.md` was taken
on — a 4-core aarch64 Linux VM with 7 GB of RAM — from two `o:speed` builds that
differ in one branch: `da9f649` (`origin/main`, the refusal answers 429 and
closes) and the same tree with `serve_doh_request` answering 429 on the client's
own `keep_alive`. Same harness, same defaults, back to back:

```
mise run release                     # both builds
cd bench && go run ./cmd/rrlexp -only doh1 -binary ../bin/elodin-<build>
```

One arm, `doh1/flood-reconnects`: one unspoofed HTTP/1.1 client on 64
connections, flat out, against the shipped 500 responses/s per /24, with an
innocent UDP client asking 50 q/s from another address at the same time. Eight
measured seconds after one of warm-up, mock upstream at 20 ms answering 70 A
records.

## What the refusal cost

| | offered/s | answered/s | 429/s | connections opened | CPU | per refusal |
|---|---:|---:|---:|---:|---:|---:|
| `da9f649`, refusal closes | 5,556 | 501 | 5,055 | **40,484** | **1.33** | **263.1 µs** |
| this branch, refusal keeps | 113,354 | 514 | 112,840 | **64** | **0.89** | **7.9 µs** |
| `doh2/one-connection-flood`, for scale | 72,539 | 500 | 72,039 | 4 | 0.76 | 10.5 µs |

The h2 row is from the earlier report, taken on this machine with the same
defaults; it is here because it is what the fix was aiming at.

Connections opened falls to the arm's own socket count — 64 dials, once, and no
more however long the flood runs — because nothing closes a connection any more.
That is the whole of the difference: the per-refusal figure is 33× smaller and
below the h2 path's, an h1 refusal being 122 bytes on one write where an h2 one is
a HEADERS frame with a header block to encode.

The offered rate rises twentyfold in the fixed row and the CPU still falls. What
the old build's 5,556 q/s measured was not the client's capacity but the
handshake it was made to complete between questions; asking is cheap once asking
is all it does. So the fair comparison is the last column, and the fourth: the
server refuses 22× as many requests for two thirds of the CPU.

## What the bystander got

| | offered | answered | p50 | p99 |
|---|---:|---:|---:|---:|
| `da9f649` | 399 | 399 (100%) | 24.5 ms | 65.1 ms |
| this branch | 400 | 400 (100%) | 21.0 ms | 31.2 ms |

Neither build drops the innocent client's queries — the limiter is per prefix and
the victim is in another one — but the old build made it wait. p99 halves, and
p50 comes back to the 20 ms the mock upstream takes, which is this arm's floor:
what the bystander was paying for was CPU spent on ECDSA rather than on its
answer. `doh1/flood-reconnects` was the only DoH arm in the earlier report where
the victim's latency moved at all, and it no longer moves.

## What this does not measure

An attacker that opens connections and refuses to reuse them, which is the flood
this arm used to be forced into by accident. Nothing here stops a client dialling
64 times a second on purpose; `server.max_connections` and the accept path are
what bound that, and they bound it the same as they did before. What changed is
that a client no longer has to be told to.
