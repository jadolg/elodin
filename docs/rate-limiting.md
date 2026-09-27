# Rate limiting and answer size

A UDP query carries no proof of where it came from, so the answer goes wherever
the source address says, which is what makes a resolver an amplifier. Two
settings bound that: how large one answer may be, and how many go to one place.

## How large a UDP answer may be

```yaml
server:
  max_udp_response: 1232          # 512–4096; the DNS Flag Day 2020 figure
```

A client's OPT record says how large a response it can take, and an attacker
aiming answers at a victim advertises the largest it can. `max_udp_response`
caps that. An answer between the ceiling and what the client asked for goes out
truncated, and the client retries over TCP. The first truncation the setting
causes is logged at `warn`.

Raise it, up to 4096, only on a network whose path MTU carries large datagrams
and where nobody who would abuse it can reach the resolver.

The ceiling is also the figure the answer's own OPT record reports (RFC 6891
section 6.2.4). Unbound has two knobs for this, `edns-buffer-size` and
`max-udp-size`; `max_udp_response` is both.

It applies to UDP only; the stream transports prove the address by handshake.
A truncated answer needs TCP to retry on: leave `listeners.tcp` on, or raise the
ceiling.

## Rate limiting

```yaml
server:
  rate_limit:
    enabled: true                 # on by default
    responses_per_second: 500     # per client prefix (/24 or /64), and per budget: datagrams, queries on a connection, connections opened
    # response_size_estimate: 128 # bytes one answer costs the datagram budget; a larger one is charged as several. Left out it follows max_udp_response, so every answer costs one token
    slip: 2                       # answer at most every 2nd query over the budget truncated; 0 drops them all
```

The budget is on what elodin sends *to one place*, since a spoofed sender has
nothing of its own to measure. It is kept per destination prefix — /24 for IPv4,
/64 for IPv6 — in a fixed table allocated once.

**Each prefix gets three budgets of `responses_per_second`**, and none can be
spent from another:

| budget | charged for |
|---|---|
| datagrams | each UDP answer |
| stream queries | each query read off a TCP, DoT or DoH connection |
| connections | each connection opened |

They are separate so a spoofed UDP flood naming a prefix cannot close or block
the connections of the clients who really live there. A client using every way
in can therefore draw three times the figure, two thirds of it over handshakes
from a real address.

Opening a connection is charged because a client that handshakes and hangs up
asks nothing, so no query budget sees it; it gets the whole figure because a
client that opens a connection per query (`dig +tcp`, a `curl` per lookup) needs
one per answer. The figures behind this are under [running a public
resolver](public-resolver.md#what-elodin-bounds-on-its-own).

Each budget banks two seconds, so a prefix can open `2 × responses_per_second`
connections at once (1000 by default), then `responses_per_second` a second. That
burst is what every device on a network reconnecting at once has to fit in. If
you set `responses_per_second` far below the default, check it against that, not
against your query rate. `client_timeout` reclaiming idle connections every ten
seconds also sets a steady reconnect rate of roughly one device in ten a second.

The budgets are spent on questions only. A 404, a `.mobileconfig` download or a
POST with the wrong content type is not charged, and neither is a source the
[allow list](access-control.md#who-may-ask) refuses, since charging it would let
a refused source use up the budget of the clients in its /24.

### Over budget

- **UDP.** At most every `slip`th over-budget query gets back a header and the
  question with TC set: too small to be worth reflecting, and it tells a real
  client to retry over TCP. `slip: 0` drops them all. These truncated answers
  have their own budget, an eighth of `responses_per_second` per prefix (62 a
  second by default), so a flood cannot make elodin send one per two datagrams
  it receives.
- **TCP and DoT.** The connection is closed. One that had already been sent
  answers is drained briefly first, so the client's kernel does not discard
  them; one refused on its first query is closed at once.
- **DoH**, both HTTP versions. `429 Too Many Requests`, on a connection that
  stays open unless the client asked to close it.
- **Opening a connection.** Refused at accept.

`elodin_rate_limited_total` counts queries withheld,
`elodin_rate_limit_slipped_total` the truncated answers (UDP only), and
`conn_rate_limited=` / `elodin_connections_rate_limited_total` connections
refused. `conn_refused=` is different: the connection *table* was full. Completed
handshakes are `handshakes=` and `elodin_tls_handshakes_total`.

The limiter does not stop a botnet: refusing at accept is cheap, not free, and
every budget here is per prefix. **A publicly reachable instance wants a
per-source connection rate limit in front of it** — see [a connection rate limit
in front](public-resolver.md#a-connection-rate-limit-in-front).
`cookies.require` is the sharper tool for an attack under way.

### Charging by size

A count of answers is worth whatever they weigh, and the attacker picks the
question: 500 answers a second is about 50 KB/s as NODATAs and about 600 KB/s as
full 1232-byte DNSSEC answers. `response_size_estimate` turns the datagram budget
into bytes. An answer larger than the estimate is charged
`ceil(size / response_size_estimate)` tokens, so the bound becomes
`responses_per_second × response_size_estimate` bytes a second whatever is asked.

- Left out, it is `max_udp_response`, so every answer costs one token.
- `response_size_estimate: 128` with the 1232 ceiling holds a prefix to about
  64 KB/s, while ordinary answers (an A record is ~60 bytes) still get 500 a
  second.
- The floor is 64 bytes; a value at or above `max_udp_response` is the same as
  leaving it out.
- Connections are not weighed, and neither are truncated replies (30 to 271
  bytes), so the slip pool's 62 a second comes on top of the byte bound.
- The charge comes after the answer is sent, so a burst is admitted and then
  paid off: the prefix hears nothing for about
  `2 × (ceil(max_udp_response ÷ response_size_estimate) − 1)` seconds (18 at an
  estimate of 128). Truncated answers still go out meanwhile, so a real client
  can move to TCP.

When the estimate bites, `--check` and the startup line print the byte rate it
works out to (`62.5KiB/s`), as does each override's line. An estimate above
`max_udp_response`, which can never bite, is called out too.

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

On a LAN a /24 is a household, and 500 a second is far more than it asks. Behind
carrier-grade NAT a /24 is thousands of subscribers sharing 500 a second between
them. `overrides` says which a network is.

- The most specific entry containing a client decides, as in a routing table;
  the order entries are written in does not matter.
- An entry without `slip` inherits the top-level one. A public prefix usually
  wants a large budget and `slip: 0`; a LAN the default.
- An entry finer than the accounting (longer than /24 or /64) is refused at
  startup, since it would apply to the whole prefix around it.
- Each entry is named in the startup log with its truncated-answer budget. The
  counters are not labelled per prefix, so those lines are the only way to see
  whether an entry matches the clients it was meant for.

Without an override, `slip` keeps a busy NAT resolving over TCP only while its
total stays within the datagram and stream budgets together: past about twice
`responses_per_second`, the prefix is refused rather than slowed.

The budgets here are rates. How many connections one client may *hold* is
[a separate bound](connections.md#how-many-connections-one-client-may-hold).
