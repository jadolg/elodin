# Rate limiting and answer size

## How large a UDP answer may be

```yaml
server:
  max_udp_response: 1232          # 512–4096; the DNS Flag Day 2020 figure
```

A client says in its OPT record how large a response it can take, and a resolver
that simply believes it has handed the caller its own amplification factor: the
query arrives on a datagram nobody verified, so an attacker aiming answers at a
victim advertises the largest buffer it can. `max_udp_response` caps that number,
and it is what the per-prefix datagram budget under [rate
limiting](#rate-limiting) is denominated in.

The cost is a TC bit and a retry over TCP on any answer between the ceiling and
what the client asked for; against real traffic that is close to nothing, and the
headroom it removes is only reachable by a zone built to fill it. Raise it, up to
4096, on a network whose path MTU is known to carry large datagrams and where the
resolver is not reachable by anyone who would abuse it. A truncation the setting
caused is logged once at `warn` naming it; a client that asked for *less* than the
ceiling got what it asked for and nothing is said.

The ceiling is also the number the answer's own OPT record reports, RFC 6891
section 6.2.4 making that field the *responder's* maximum rather than a copy of
the requestor's — the counterpart to `max-udp-size` in BIND and Unbound. Coming
from Unbound, note that this is one knob where Unbound has two:
`edns-buffer-size` advertises and `max-udp-size` truncates; `max_udp_response` is
both.

It is UDP only: the stream transports prove the address by handshake, so there is
nothing to reflect and the OPT record goes back as the answer carried it. That
does mean a truncated answer needs somewhere to go — with `listeners.tcp` off, a
client told to retry has nowhere to retry to. Leave TCP on, or raise the ceiling.

## Rate limiting

```yaml
server:
  rate_limit:
    enabled: true                 # on by default
    responses_per_second: 500     # per client prefix (/24 or /64), and per budget: datagrams, queries on a connection, connections opened
    # response_size_estimate: 128 # bytes one answer costs the datagram budget; a larger one is charged as several. Left out it follows max_udp_response, so every answer costs one token
    slip: 2                       # answer at most every 2nd query over the budget truncated; 0 drops them all
```

A UDP query carries no proof of where it came from, so the answer goes wherever
the source address said — which is what makes any resolver an amplifier. How
large one datagram can be is capped by
[`max_udp_response`](#how-large-a-udp-answer-may-be); this is the cap on how many
of them.

The budget is on what this server will send *to one place*, not on how fast one
sender asks: with a spoofed address there is nothing of the sender's to measure.
So it is kept per destination prefix, /24 and /64, the granularity an attacker
picks addresses within, in a fixed table allocated once so the limiter is not
itself somewhere to put pressure.

**What one of those responses is worth in bytes is `response_size_estimate`.**
A victim receives traffic, and a count of sendings is worth whatever the answers
weigh — which the attacker picks by picking the question. At the shipped 500 that
is about 50 KB/s at one /24 if the answers are ~100-byte NODATAs and about 600
KB/s if they are full 1232-byte DNSSEC answers, a twelvefold spread in the figure
an operator thought they were setting. So an answer larger than the estimate is
charged `ceil(size / response_size_estimate)` tokens instead of one — admitted on
the first, billed for the rest once it is packed, which the next query from that
prefix pays for — and the bound becomes `responses_per_second ×
response_size_estimate` bytes a second whatever is asked for. AdGuard DNS's
setting of the same name does the same arithmetic.

Left out it is [`max_udp_response`](#how-large-a-udp-answer-may-be), the largest
datagram this server will send, so no answer is ever charged more than one token
and the figure means exactly what it meant before there was a second one. Set it
smaller to choose the quantity directly: with the 1232 ceiling,
`response_size_estimate: 128` holds a prefix to about 64 KB/s of answers rather
than 600, while a client whose answers are ordinary — an A record is ~60 bytes —
still gets its 500 a second. It is the datagram budget only: a connection has no
size worth charging, and a slip reply is not weighed at all — it is a header and
the question echoed back, 30-odd bytes for an ordinary name and at most 271 for a
maximal one, so the `slip` pool's own `responses_per_second / 8` a second sits on
top of the figure above rather than inside it.
The floor is 64 bytes, since below the smallest answer this server sends the
setting stops being a size at all; anything at or above `max_udp_response` is
what leaving it out already does.

The bill arrives after the datagram was admitted, not with it, so the debt is
carried rather than forgiven: a burst that reaches a full bucket is admitted
whole and billed for all of it afterwards, and the prefix then hears nothing
until it has paid — about `2 × (ceil(max_udp_response ÷ response_size_estimate) −
1)` seconds, so 18 at an estimate of 128 and 38 at the 64-byte floor. That is the
overspend the setting exists to charge for, and forgiving it would make the bound
above an average rather than a ceiling. `slip` is untouched by it: a real client
caught behind a spoofed burst in its /24 is still answered truncated and sent to
TCP, where no datagram budget follows it.

When it is set low enough to bite, `--check` and the startup line say what the
two figures multiply out to, at whatever scale the figure lands on — `640.0B/s`,
`62.5KiB/s`, `4.8MiB/s`. Each `overrides` entry's line carries the same product
for its own budget, since the estimate is one figure for the whole server: a
network raised to 4000/s at an estimate of 128 is told it has bought 500.0KiB/s,
not 4000 answers of whatever size. And when the estimate is set *above*
`max_udp_response`, where no answer can reach it, both say that instead, so a
figure that looks like a tightening and is not does not pass unremarked.

Over-budget queries are not simply dropped. At most every `slip`th one comes back
as a header and a question with the TC bit set: too small to be worth reflecting,
and the standard way of telling a client to ask again over TCP where the
handshake proves the address. A client behind a busy NAT keeps resolving, one
round trip slower; a spoofed source cannot follow it up. `slip: 0` drops them
instead.

Those truncated answers are charged to a budget of their own — **an eighth of
`responses_per_second` per prefix**, so at the default, 62 a second — which makes
`slip` "at most one in N" rather than "one in N of whatever arrives". It has to be
a budget, because before it was one their number was a fixed fraction of the attack
with no ceiling in it: a flood of two million datagrams a second had this server
send half a million truncated answers a second, 19 MB/s, at the address the flood
named, where the same configuration's 500 responses/s implies 0.58 MB/s. Byte for
byte the attacker loses on that exchange, so it is not amplification — what it is
is this server made a source of traffic proportional to somebody else's attack, and
half a million writes a second taken from the one thread reading the UDP socket,
which cost a bystander in an unrelated prefix 44 points of its answer rate. An
eighth and not the whole figure because a truncated answer is an invitation rather
than an answer: a client that acts on one moves to a connection, whose budget a
datagram flood cannot reach, so it needs far fewer of them than it would need
answers. `bench/results/2026-09-03-rate-limit-bystander.md` is where the uncharged
figures were measured and `2026-09-03-slip-budget.md` is the same arms with the
budget in place: 0.54 MB/s at the named address, and the uninvolved bystander back
to 99%.

The cost is that the invitation is worth less to a client inside a flooded prefix:
62 a second spread over the flood's own datagrams, rather than every second
datagram in the bucket. That holds up at the rates a busy NAT produces — a prefix
asking twice its budget has a few hundred over-limit datagrams a second to spread
them across, and one invitation that lands moves that client onto a connection for
good — and not against millions a second, where the client is left with the stream
budget and nothing pointing it there. `src/server/ratelimit.odin` argues the trade
out.

TCP, DoT and DoH are charged too, for the work behind an answer rather than for
amplification — without that, a flood down a handful of long-lived connections is
one the limiter never sees. **Three budgets per prefix, though, not one:**
datagrams charge one, queries read off a connection charge another, and opening a
connection charges a third — each getting the whole of `responses_per_second`, and
none of them spendable from another's side, since a spoofed UDP flood naming a
prefix would otherwise close the connections of the clients who actually live
there, or stop them opening one. The cost is that a client using every way in can
draw three times the figure, two thirds of it only over a completed handshake from
an address that is therefore real. `src/server/ratelimit.odin` argues this out.

**Opening a connection is charged because arriving is the expensive part.** A
client that dials, completes a TLS handshake and hangs up asks nothing, so no
budget of *answers* ever saw it, and it holds each connection too briefly for
[`max_connections_per_prefix`](connections.md#how-many-connections-one-client-may-hold) to
notice — 32 such dialers drew 6,032 handshakes a second and 1.25 of four cores
while `conn_refused` and `elodin_rate_limited_total` both read zero, and took 16
points of answer rate and four times the latency from a DoT client in an unrelated
prefix. With the budget the same load gets 462 handshakes a second and costs 0.29
of a core, and that bystander loses 10 points instead of 16.
`bench/results/2026-09-04-handshake-budget.md` is the before and after;
`2026-09-03-handshake-floods.md` is where the load is described.

The whole figure rather than a fraction of it, because a connection is the vehicle
for a query: `dig +tcp`, a `curl` per lookup and every stub that does not keep a
connection open spend one connection per answer, so a prefix entitled to 500
queries over connections has to be able to open 500. A smaller connection budget
would be a quiet reduction of the query budget for exactly the clients that
reconnect.

**So `responses_per_second` is now three bounds, and one of them has a burst to
size.** A prefix banks two seconds of each budget, so it can open
`2 × responses_per_second` connections at once — 1000 at the default — and then
`responses_per_second` a second. Answers arrive spread out and connections do not:
the moment that tests this is every device on a network reconnecting together,
after this resolver restarts or after a link comes back. That burst is bounded by
how many devices share a prefix, so at the default it is not a figure any real
network reaches. An operator who has tuned `responses_per_second` far *below* the
default should check it against that number rather than against their query rate —
`client_timeout` reclaiming an idle connection every 10 seconds is also what sets
the steady arrival rate, at roughly one device in ten per second.

Refusals are counted as `conn_rate_limited=` in the stats line and
`elodin_connections_rate_limited_total` on the endpoint, apart from
`conn_refused=`, which is the connection *table* being full — arrival and occupancy
are different problems with different settings behind them. Completed handshakes
are `handshakes=` and `elodin_tls_handshakes_total`, which is the first counter
here that says anything about what getting clients in the door costs.

What it does not do is stop a botnet, and it does not bring that bystander back to
its quiet baseline: refusing at the accept is cheap but not free, and a peer whose
dials cost it nothing simply dials four times faster. **A publicly reachable
instance wants a per-source connection rate limit in front of it** — see [a connection rate limit in
front](public-resolver.md#a-connection-rate-limit-in-front).

`slip` is a UDP mechanism, so over-budget queries on a connection are refused
instead: TCP and DoT closed, and over DoH — both HTTP/1.1 and HTTP/2 — answered
`429 Too Many Requests` on a connection that stays open unless the client itself
asked for a close. It stays because ending it charges this server a TLS handshake
per refusal and the flooding client nothing, which made refusing dearer than
answering. A refused connection that has already been sent answers is drained briefly
before it is closed, since closing a socket with unread data resets it and the
client's kernel would throw those answers away; one refused on its first query
has nothing to lose and is closed at once.

The budget is spent on questions, on every transport: a scanner's 404, a
`.mobileconfig` download or a POST naming the wrong content type reaches no
resolver, cache or upstream. Refusals are not charged either, the budget being
per /24 — charging a denied source would turn a narrowed allow list into a way to
have the clients beside it dropped.

`elodin_rate_limited_total` counts what was withheld;
`elodin_rate_limit_slipped_total` counts truncated answers, so it only ever moves
for UDP. `cookies.require` is the sharper instrument for an attack actually under
way.

### When a /24 is not a household

```yaml
server:
  rate_limit:
    responses_per_second: 500
    slip: 2
    overrides:
      # A carrier NAT: thousands of subscribers, not one household.
      - { prefix: 198.51.100.0/24, responses_per_second: 5000 }
      # A network being used for reflection, given a figure of its own rather
      # than narrowing what every other client gets.
      - { prefix: 203.0.113.0/24, responses_per_second: 50, slip: 0 }
```

The budgets are kept per /24 and per /64 because that is the granularity an
attacker picks addresses within, and that reasoning is right. The consequence is
that the unit means two incompatible things depending on where this server is: on
a LAN a /24 is a household or an office, and 500 responses a second is far past
what the busiest of those asks for. On the internet a /24 behind carrier-grade NAT
is thousands of subscribers, and 500 a second is what they get **between them**.

`overrides` is where an operator says which a given network is. Each entry names
a network and the figures it gets; everything else stays on the defaults above.
Where two entries both contain a client the more specific one decides, as in a
routing table, so `10.0.0.0/8` beside `10.1.2.0/24` means the /24's figure inside
it and the /8's everywhere else — the order they are written in decides nothing.
An entry that names no `slip` inherits the one above it.

**An entry cannot be finer than the accounting.** An IPv4 network longer than /24,
or an IPv6 one longer than /64, is refused at startup: every address in a /24
shares one bucket, so a `/32` could only ever be applied to the whole /24 around
it, which is 256 addresses getting a figure written for one. Write the /24.

Without an override, what the slip does about a busy NAT is real but bounded, and
the bound is worth knowing before deciding you do not need one. A prefix over its
datagram budget has at most every `slip`th over-limit query answered truncated,
which sends that client to TCP — where it is served out of a budget of its own, so
it keeps resolving one round trip slower. That holds while the prefix's *total*
stays inside the two budgets together. Past that it does not: the stream pool is
`responses_per_second` as well, and a client that opens a connection per query
spends the arrival budget too, so a /24 asking more than about twice the figure is
being refused rather than delayed however `slip` is set. A busy carrier NAT
reaches that.

`slip` is per entry because the two settings are one decision rather than two. A
public prefix usually wants a large budget and `slip: 0` — a truncated answer is
an invitation to open a connection, and an operator who has concluded that nobody
legitimate is behind the address being flooded does not want to send one. A LAN
wants the small budget and `slip: 2`.

Every network with figures of its own is named in the log at startup, one line
each, with the truncated-answer budget it derives. Nothing else can tell an
operator which tier a client was accounted on: the counters are not labelled per
prefix, because a series per /24 is cardinality a peer would choose. So a
misconfigured entry — one that does not match the clients it was meant for — is
visible in those lines and nowhere else.

What none of this bounds is how much of the server one client *occupies*. Every
budget here is a rate — arriving, and asking — and a client that stays inside them
can still hold every connection it was given for as long as it likes. That is
[how many connections one client may hold](connections.md#how-many-connections-one-client-may-hold).
