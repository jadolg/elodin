# One client holding the connection table, and a share that stops it

Measured 2026-09-03 on the machine the two reports beside it were taken on — a
4-core aarch64 Linux VM with 7 GB of RAM — from an `o:speed` build of the branch
that adds `server.max_connections_per_prefix`:

```
mise run release
cd bench && go run ./cmd/rrlexp -only slowloris
```

This is the arm `bench/results/2026-09-03-rate-limit-bystander.md` said was
missing. That report measured 56,249 connections accepted from one source
address in twelve seconds and concluded that nothing counts connections per
client — but every one of those died on the refusal that closed it, so it
demonstrated churn rather than occupancy. What it did not show was the thing that
locks a network out: connections opened from one prefix and **held**, idle,
against a table with no share-out.

Three arms, eight measured seconds each after one of warm-up:

- one client on 127.0.0.2 opening 96 TCP connections and asking nothing on any of
  them, against `max_connections: 64`;
- a victim on 127.1.0.1 — another /24 — asking 50 q/s over TCP, one connection
  per query, which is what a client shut out of the table actually experiences;
- `client_timeout` raised to a minute, so a slot reclaimed from an idle holder is
  never what serves the victim. That reclamation is real, and at ten seconds it is
  a delay rather than a bound.

A table of 64 with a share of 32 rather than the shipped 512 and 256: filling 512
slots measures the load generator's sockets more than the server's share-out, and
the property is scale-free. The response limiter is on at its shipped default in
every arm, and it never fires in the first two — an idle connection asks nothing,
so there is nothing for a budget denominated in queries to charge.

## What one holder took, and what the bystander got

| arm | table | share | opened | **held** | refused | victim answered | victim p50 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `slowloris/no-share` | 64 | none | 96 | **64** | 32 | **0% (0/400)** | — |
| `slowloris/share` | 64 | 32 | 96 | **32** | 64 | **100% (235/235)** | 31.2 ms |

With no share, one client holds all 64 slots and the victim's every connection is
closed on accept — 400 offered, 400 refused, not one answer. `elodin_queries_total`
for that arm is **1**: the readiness probe. The server spent 0.00 of a core and
answered nothing, which is what makes this a different failure from a flood. It is
not overloaded. It has nothing left to accept with.

With a share of half the table, the same 96 connections get 32 and the victim is
served every query it manages to ask. It offers fewer than the no-share arm (235
against 400) because each of its queries is a connection and a 20 ms upstream
round trip it waits for, where a refused connection comes back instantly; the
percentage is the number to read, not the count.

The refusals are counted as `conn_refused=` either way — 464 in the first arm
(the holder's 32 over the table, plus the victim's 400, plus the warm-up's), 128
in the second (the holder's 64, and the warm-up's) — so the event was visible in
both. What was not available before this branch is a configuration under which
the first row cannot happen.

## What the share costs a client that is not a holder

| arm | victim | offered | answered | p50 | p99 |
|---|---|---:|---:|---:|---:|
| `slowloris/share-costs-a-normal-client-nothing` | 127.1.0.1, TCP | 387 | **387 (100%)** | 20.5 ms | 21.3 ms |

The same share of 32, a client holding one connection at a time, and a 20,000
q/s UDP flood from the holder's /24 running alongside it: every query answered at
one upstream round trip. A share that bounds a client holding 96 connections is
not felt by one holding a single connection, which is the whole of the case for
having it on by default.

## What this does not say

The victim here is on TCP because that is where the occupancy is. **A UDP client
is not affected by a full connection table at all** — the read loop has no
per-client state and no connection to refuse — so a resolver whose table has been
taken looks perfectly healthy on datagrams while its TCP, DoT and DoH clients get
nothing. The clients it loses are the ones that proved their address by
handshake, which is the wrong half to lose.

Nor does any arm here spoof a source. Holding a connection means completing a
handshake, so a holder is where it says it is, and the share is charged to an
address that is real. That is why a share can be much tighter than a response
budget without being a weapon: an attacker cannot spend a stranger's share by
naming their prefix, the way a spoofed datagram flood can spend a stranger's
response budget. `src/server/ratelimit.odin` argues that distinction out at
length, and it is the reason the two bounds are kept separately while agreeing
about what a client is.
