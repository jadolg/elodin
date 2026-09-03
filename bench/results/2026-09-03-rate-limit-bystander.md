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

Twenty-one arms, ten measured seconds each after two seconds of the same load, so
no arm reports a fresh bucket's burst allowance. Two runs of the same harness on
the same machine: the fifteen datagram and stream arms, then the six DoH ones,
which have a section and tables of their own further down because a refusal there
is a status rather than a missing datagram. Shipped limiter defaults (500
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

## DoH

The two things only DoH reaches. Multiplexing: every other stream client here is
served a query at a time, which is why eight pipelined TCP connections offered the
limiter about 400 queries a second and never reached the budget at all. And the
refusal: TCP and DoT end the connection, DoH/1.1 answers 429 and then ends it, and
DoH/2 answers 429 and keeps going.

| arm | victim | via | answered | no answer | p50 | p99 | statuses |
|---|---|---|---:|---:|---:|---:|---|
| doh2/one-connection-flood | 127.0.0.3 | udp | 500 (100%) | 0 | 20.2ms | 21.8ms | — |
| doh2/flood-vs-doh-victim | 127.0.0.3 | doh2 | 4 (1%) | 496 | 20.2ms | 20.6ms | 4×200, 496×429 |
| doh2/flood-vs-doh-victim-other-prefix | 127.1.0.1 | doh2 | **500 (100%)** | 0 | 20.3ms | 22.6ms | 500×200 |
| doh2/flood-vs-other-prefix | 127.1.0.1 | udp | **500 (100%)** | 0 | 20.3ms | 23ms | — |
| doh2/flood-vs-other-prefix/limiter-off | 127.1.0.1 | udp | 500 (100%) | 0 | 21.4ms | 30ms | — |
| doh1/flood-reconnects | 127.0.0.3 | udp | 500 (100%) | 0 | 24ms | 41.8ms | — |

| arm | flood | via | offered/s | answered/s | 429/s | connections opened | CPU |
|---|---|---|---:|---:|---:|---:|---:|
| doh2/one-connection-flood | 127.0.0.2 | doh2 | 72,539 | 500 | 72,039 | 4 | 0.76 |
| doh2/flood-vs-doh-victim | 127.0.0.2 | doh2 | 71,876 | 500 | 71,376 | 1 | 0.75 |
| doh2/flood-vs-doh-victim-other-prefix | 127.0.0.2 | doh2 | 72,048 | 500 | 71,548 | 2 | 0.76 |
| doh2/flood-vs-other-prefix | 127.0.0.1 | doh2 | 70,307 | 500 | 69,807 | 2 | 0.75 |
| doh2/flood-vs-other-prefix/limiter-off | 127.0.0.1 | doh2 | 3,041 | 3,041 | 0 | 1 | 0.21 |
| doh1/flood-reconnects | 127.0.0.2 | doh1 | 6,123 | 501 | 5,622 | **56,249** | 1.33 |

No amplification column: a handshake settled that the client is where it says it
is, so there is no third party for an answer to be aimed at.

**The budget is the only thing bounding a DoH/2 client, and it holds.** One
connection with sixty-four requests outstanding offers 72,539 a second - a hundred
and eighty times what eight pipelined TCP connections managed, because nothing
here serialises - and 500 a second is what it is answered. Serialisation was doing
the bounding on the length-prefixed transports and it does none here, which makes
this the arm the stream budget exists for.

**Its prefix is a boundary in both directions.** A DoH victim in another /24 is
served 500 of 500 through the same flood, and a UDP victim inside the flooded /24
is served 500 of 500 as well - the datagram pool is untouched by what a connection
spends, which is the separation the file argues for, arriving from the DoH side.

**A DoH victim inside the flooded /24 has no recourse.** It gets 4 answers of 500
and 496 refusals - a few percent, and it varies the way `same-prefix/slip-0` does
and for the same reason: both clients are racing for each refilled token, and a
repeat of this arm answered 33 of 400. Over UDP the slip sends such a client to TCP, and TCP is a
budget the flood has not emptied; here the client is already on the stream pool,
and the pool it has not spent is the datagram one - which is the transport it chose
DoH to avoid. Nor is there a `Retry-After`, deliberately: `doh.odin` explains that
the field counts whole seconds and the budget has a token back in two milliseconds,
so the smallest value it could carry would send a client away for hundreds of times
the wait there is. The 429 is honest and immediate, and a client that reads it
learns only to try again.

**The 429-that-keeps-the-connection is cheap, and costs bystanders nothing.**
Refusing 70,000 requests a second costs 0.75 of a core - 10.5 µs each, against
about 0.5 µs for a dropped datagram - and the client in another /24 stays at 100%
with its latency unmoved. That is the opposite of the slip result on UDP, and for a
structural reason: this work happens on the flooding connection's own reader thread
rather than in the single UDP read loop every client's datagrams pass through.

**Closing the connection instead costs twenty-two times as much.** DoH/1.1 answers
429 with `keep_alive` false, so every refusal ends a connection the client
immediately re-establishes: 56,249 connections in twelve seconds, about 4,700 TLS
handshakes a second, 1.33 cores - 236 µs per refusal. It is also the only DoH arm
where the bystander's latency moved at all, p50 20.2 ms to 24 ms and p99 to 41.8 ms.
The decision is defensible - it is what the length-prefixed transports do, and RFC
6585 4 is written for exactly this - but the number an operator should have is that
an over-budget h1 client makes this server do ECDSA rather than DNS, and that h2's
refusal is two orders of magnitude cheaper for the same answer.

**And the limiter costs CPU here rather than saving it.** With it off, the same
flood is bounded by the server's own capacity instead: it settles at 3,041 answers
a second, 64 workers against a 20 ms upstream, and spends 0.21 of a core - while
the victim still gets 100%, because a DoH flood at three thousand a second starves
nothing. Turning the limiter on cuts the answered work sixfold and the bytes it
returns sixfold, and raises CPU three and a half times, because a flood that is
refused quickly is a flood that asks twenty-three times as often. The saving is in
the upstream round trips and the cache churn (500 forwards a second against
2,843) and not in processor time. On UDP the limiter saves both; here it trades one for
the other, and the trade is still worth making, since what it bounds is the work an
attacker can direct at everything else the server is doing.

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

**DoT is the one transport with no arm of its own.** It is served by the same
`serve_dns_stream` as TCP and charged at the same `stream_rate_check` call site, so
what a DoT arm would measure is the cost of TLS, which `mise run bench` already
reports, and not anything about the limiter. The other three each have their own
enforcement point — the UDP read loop, `doh.odin`, `doh2.odin` — and each is
measured above.

**The DoH client is Go's own HTTP stack**, which keeps the independence the rest of
the harness has: elodin's h2 and HPACK are the things under test, and a generator
sharing them could agree with a bug in either. Its byte counters are DNS payloads,
so they leave out the TLS records and HTTP framing around them — which is why the
DoH tables report no bytes-at-the-source figure.

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

`-only doh` runs the DoH arms alone, and `-only <substring>` any single one. The flags that move the result are
`-flood-rate` (0 is flat out), `-victim-rate`, `-rps`, `-slip` and
`-answer-records`, which sets the answer size the budget is denominated in.
