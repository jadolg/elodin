# Rate limiting, from the bystander's side

Measured 2026-09-03 from an `o:speed` build of 8d716b9, on a 4-core aarch64
Linux VM with 7 GB of RAM — a smaller machine than the one
`2026-08-03-ryzen7-6850u.md` was taken on, which matters for two figures below
and for nothing else. The absolute rate an unlimited server answers a flood at
is this machine's capacity, so `cached-flood/limiter-off` is a floor on the
reflection a limiter prevents rather than a measurement of the worst case; the
read-side limit appears at whatever packet rate saturates one core, which here
is around two million a second. Everything the arms are compared on is a ratio
between two arms on the same machine.

The question neither test layer answers. `src/server/ratelimit.odin` argues that
a budget per destination prefix bounds what one address can be made to receive,
and `src/itest/cases_ratelimit.odin` asserts the mechanism: a flood is cut to the
budget, a datagram flood does not close a prefix's connections. Both work from
one client at a time. What an operator actually wants to know is the thing two
clients at once decide — whether the query *you* send while somebody else is
flooding comes back, and how long it takes.

So each arm runs two clients against one server: a flood, and a victim asking at
50 q/s. `bench/cmd/rrlexp` is the harness; every arm has a control with the
limiter off, because "the victim was served" says nothing on its own — a server
that was never saturated would serve it with no limiter at all.

Fifteen arms, ten measured seconds each after two seconds of the same load, so
no arm reports a fresh bucket's burst allowance. Shipped limiter defaults (500
responses/s per /24, `slip: 2`, `max_udp_response` 1232), `workers` 64 and
`upstream_workers` 32 pinned rather than derived, mock upstream at 20 ms
answering 70 A records — 1151 bytes, the largest answer the default
configuration will send.

## The victim

500 queries offered in each arm. "Truncated" is a `TC` answer, which is an
instruction to retry over TCP rather than an answer.

| arm | victim | via | answered | truncated | no reply | p50 | p99 |
|---|---|---|---:|---:|---:|---:|---:|
| quiet-baseline | 127.9.0.1 | udp | 500 (100%) | 0 | 0 | 20.7ms | 23.5ms |
| quiet-baseline/tcp | 127.9.0.1 | tcp | 497 (99%) | 0 | 3 | 153.7ms | 343.2ms |
| other-prefix/limiter-on | 127.1.0.1 | udp | **500 (100%)** | 0 | 0 | 20.5ms | 23.6ms |
| other-prefix/limiter-off | 127.1.0.1 | udp | 73 (15%) | 0 | 427 | 164.8ms | 181.8ms |
| same-prefix/limiter-on | 127.0.0.3 | udp | 33 (7%) | 250 | 217 | 20.6ms | 24.1ms |
| same-prefix/limiter-off | 127.0.0.3 | udp | 80 (16%) | 0 | 420 | 164.6ms | 174.7ms |
| same-prefix/victim-on-tcp | 127.0.0.3 | tcp | **497 (99%)** | 0 | 3 | 161.1ms | 510.4ms |
| same-prefix/victim-on-tcp/limiter-off | 127.0.0.3 | tcp | 493 (99%) | 0 | 7 | 229.8ms | 534.3ms |
| same-prefix/tcp-flood-udp-victim | 127.0.0.3 | udp | 500 (100%) | 0 | 0 | 20.6ms | 24.2ms |
| same-prefix/tcp-flood-64-conns | 127.0.0.3 | udp | 500 (100%) | 0 | 0 | 21ms | 163.3ms |
| cached-flood/limiter-off | 127.1.0.1 | udp | 87 (17%) | 0 | 412 | 63ms | 154.7ms |
| cached-flood/limiter-on | 127.1.0.1 | udp | 274 (55%) | 0 | 226 | 40.7ms | 73.2ms |
| cached-flood/slip-0 | 127.1.0.1 | udp | **493 (99%)** | 0 | 6 | 32.4ms | 53.6ms |
| same-prefix/slip-0 | 127.0.0.3 | udp | 77 (15%) † | 0 | 423 | 20.5ms | 21.7ms |
| other-prefix/flat-out | 127.1.0.1 | udp | 321 (64%) | 0 | 179 | 39.6ms | 83.5ms |

† The one row that moves run to run. Three repeats of it answered 6, 6 and 11 of
500, and an earlier run 18 - so a few percent is the figure, and the 77 here is
the high end of it. What it is racing for is each refilled token: the flood
empties the bucket, a token appears 2 ms later, and whichever client asks in that
instant takes it. Nothing else in the table has a spread worth a footnote.

## The flood, and what the address it named received

| arm | limiter | flood | via | offered/s | answered/s | truncated/s | MB/s back | bytes back per byte sent | CPU |
|---|---|---|---|---:|---:|---:|---:|---:|---:|
| other-prefix/limiter-on | on | 127.0.0.1 | udp | 19,999 | 500 | 9,517 | 0.95 | 1.0 | 0.10 |
| other-prefix/limiter-off | off | 127.0.0.1 | udp | 20,000 | 3,091 | 0 | 3.58 | 3.6 | 0.11 |
| same-prefix/limiter-on | on | 127.0.0.2 | udp | 19,999 | 497 | 9,550 | 0.95 | 1.0 | 0.09 |
| same-prefix/limiter-off | off | 127.0.0.2 | udp | 19,999 | 3,086 | 0 | 3.58 | 3.6 | 0.12 |
| same-prefix/victim-on-tcp | on | 127.0.0.2 | udp | 19,998 | 500 | 9,520 | 0.95 | 1.0 | 0.09 |
| same-prefix/victim-on-tcp/limiter-off | off | 127.0.0.2 | udp | 19,998 | 3,083 | 0 | 3.57 | 3.6 | 0.12 |
| same-prefix/tcp-flood-udp-victim | on | 127.0.0.2 | tcp | 19,999 | 400 | 0 | 0.46 | 0.4 | 0.02 |
| same-prefix/tcp-flood-64-conns | on | 127.0.0.2 | tcp | 389,183 | 515 | 0 | 0.60 | 0.0 | 0.03 |
| cached-flood/limiter-off | off | 127.0.0.1 | udp | 1,298,930 | 152,680 | 0 | **176.65** | 2.8 | 2.09 |
| cached-flood/limiter-on | on | 127.0.0.1 | udp | 2,062,844 | 500 | 497,131 | 18.97 | 0.2 | 0.97 |
| cached-flood/slip-0 | on | 127.0.0.1 | udp | 2,004,652 | 500 | 0 | **0.58** | 0.0 | 0.91 |
| same-prefix/slip-0 | on | 127.0.0.2 | udp | 19,999 | 492 | 0 | 0.57 | 0.6 | 0.07 |
| other-prefix/flat-out | on | 127.0.0.1 | udp | 1,746,487 | 500 | 478,028 | 20.06 | 0.2 | 0.98 |

CPU is cores over the measured window, the server process alone.

## What holds

**A flood in one /24 does not reach a client in another.** The victim's answer
rate and latency are indistinguishable from an idle server — 100% at p50 20.5 ms
against a baseline of 20.7 ms — while the flood is held at exactly the budget.
The control is what makes that the limiter's doing rather than spare capacity:
the same flood with the limiter off leaves the victim 15% of its answers and
eight times the latency. Repeated, the control lands between 15% and 21% - what
it keeps is whatever the shedding leaves it - and the limited arm is 100% in
every run.

**The two budgets are separate in both directions.** A UDP flood in the victim's
own /24 leaves its TCP queries at 99%, and a 64-connection pipelined TCP flood
leaves a UDP victim in that prefix at 100%. So the truncated answer's "come back
over TCP" leads to a budget the flood has not emptied, which is the property the
note at the top of `ratelimit.odin` says is worth more than it looks.

The eight-connection TCP flood is worth keeping next to the sixty-four-connection
one. It never reached the limiter at all — `limited=0` — because a connection is
served a query at a time against a 20 ms upstream, so eight of them offer about
400 queries a second, under the 500 the budget would refuse at. Serialisation
bounds a pipelining client before the limiter does; sixty-four connections pass
it, and then the stream budget cuts them to 515 a second.

**The amplification ceiling is the arithmetic it claims to be.** With the slip
off, the named address receives 0.58 MB/s, which is 500 responses times 1151
bytes. Against the same flood an unlimited resolver delivers 177 MB/s — 1.4
Gbit/s out of a four-core VM, for two cores of its own. And for the attacker the
exchange is a loss at every setting measured: bytes back never exceed bytes sent.

## What it does not do

**The slip, not the budget, sets what a large flood delivers.** Every second
over-budget datagram is answered with a ~40-byte truncated reply, and that count
scales with the attack rather than with the budget: at 2.1M q/s the named address
receives 497k of them a second, 18.97 MB/s, thirty-three times what the budget
implies. That is not amplification — the attacker spends more bandwidth than it
delivers, and `slip` exists precisely so the small answer stands in for the large
one. But it is volume aimed at an address that never asked, and nothing the
operator configured bounds it.

The same replies cost a bystander in a *different* prefix, which is the part not
visible from the reflection side. Writing half a million small datagrams a second
competes with the read loop that would have picked up the victim's query: **55%
answered with `slip: 2` against 99% with `slip: 0`**, same flood, same prefix
isolation. Charging slip replies against a budget of their own would keep the
invitation and drop that cost; it is a change to argue rather than one this
measurement makes.

**It bounds what the server sends, not what it can read.** At around two million
packets a second the single UDP read loop cannot drain the socket, and the
bystander's datagrams are lost in the receive queue before the limiter is
consulted — 64% answered, with the flood still correctly held at 500 answers a
second and the process spending a whole core in `recvfrom` and siphash. A
response rate limiter is the wrong instrument for that half; a packet filter in
front of the socket is the right one.

## What the prefix granularity costs, quantified

A bystander sharing the flooded /24 gets 7% of its UDP queries answered in full.
That is the budget being kept per prefix, which is deliberate — an attacker
spoofing addresses picks them freely inside a range, so a per-address budget
would only be spread across it — and the slip is what keeps such a client
resolving: half its queries came back truncated, 250 of 500, and following that
invitation to TCP got it 99% served out of the untouched stream budget.

`slip: 0` is what removes that recourse. What the victim keeps is the few percent
of the budget it wins in a race against the flood — 6, 6, 11, 18 and 77 answers
out of 500 across five runs — and no signal at all, where the slip told it half
the time to go where it would have been served. So the two rows are the trade the
default makes. `slip:
2` is right for a resolver whose clients sit behind NAT with a flood in their
range; `slip: 0` is right for one reachable by strangers at high packet rates,
where the slip is both the reflected volume and the bystanders' loss. The default
stays as it is.

## What the numbers do not say

The two clients use real source addresses on loopback — 127.0.0.1 and 127.1.0.1
are different /24s, 127.0.0.2 and 127.0.0.3 the same one — and the kernel fills
the field in, so no arm depends on the harness being believed about where a
datagram came from. What is not modelled is spoofing itself: a real reflection
attack names an address it cannot receive at, and every "bytes back" figure here
was collected by a client that could.

The TCP victim's 140 ms is the harness rather than the flood. One connection
offering 50 q/s against a 20 ms upstream queues at the edge of its own capacity,
and the idle control measures 147 ms. Read the TCP rows for their answer rate;
their latency describes the client pattern.

**UDP and TCP only, of the four transports.** DoT needs no arm of its own: it is
served by the same `serve_dns_stream` as TCP and charged at the same
`stream_rate_check` call site, so what a DoT arm would measure is the cost of TLS,
which `mise run bench` already reports. DoH is a gap rather than an omission —
`doh.odin` and `doh2.odin` each charge the budget themselves, and HTTP/2 brings a
property no arm here reaches: a client multiplexes concurrent requests down one
connection, so where eight pipelined TCP connections could not reach the stream
budget at all — a connection is served a query at a time — a single h2 connection
plausibly can. Its refusal differs too. TCP and DoT end the connection; an
over-budget h2 request is answered 429 and the connection stays open, so a flood
keeps paying for frame and HPACK work per refused request, which is the same shape
as the slip finding above and worth measuring the same way.

One machine, loopback, no packet loss and no path MTU. The absolute packet rates
are higher than any real link would deliver — that is what makes the read-side
limit visible at all — and the ratios between arms are the result.

## Reproducing

```sh
mise run release
cd bench && go run ./cmd/rrlexp -duration 10s -warmup 2s -out results/$(date +%F)-rate-limit-bystander.md
```

Deliberately not part of `mise run bench`: every scenario there turns rate
limiting off, because the load generator is one address asking as fast as it can,
and this is the run that leaves it on.

`-only <substring>` runs one arm. The flags that move the result are
`-flood-rate` (0 is flat out), `-victim-rate`, `-rps`, `-slip` and
`-answer-records`, which sets the answer size the budget is denominated in.
