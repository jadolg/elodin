# elodin benchmark

The harness behind the README's *Capacity* and *Resource use* sections. It
exists so those numbers can be re-taken rather than trusted: every figure in
them comes out of `mise run bench`, and a claim that cannot be reproduced by
running it is a claim to delete.

```sh
mise run release          # the numbers describe the optimised build
mise run bench            # the whole matrix, about twenty minutes
```

Narrower runs, for when one table is what you care about:

```sh
mise run bench -- -only transports           # one section
mise run bench -- -repeat 1 -duration 3s     # quick and rough

cd bench                                     # or drive it directly
go run ./cmd/bench -out results/$(date +%F).md
```

Run the whole matrix in one go and the later sections come out 20–30% slower
than the earlier ones on a laptop, purely from heat. The committed result was
taken a section at a time from a cooled machine for that reason; `-cooldown`
sets the idle time between individual runs.

## What it controls

Throughput figures are worth nothing without the conditions attached, so the
harness owns all of them rather than inheriting them from the machine:

- **Its own upstream.** `cmd/mockdns` answers every query after a fixed delay,
  20 ms by default. That delay is the point: a worker is occupied for a whole
  upstream round trip, so it is what decides how many queries the pool can carry.
  An upstream answering instantly would measure a server nobody runs.
- **Its own configuration.** Each scenario writes the config it needs. Most keys
  are left at the shipped default, but four are not, for every scenario:
  validation is off (see below), rate limiting is off (the generator is one
  address asking as fast as it can, which is what the limiter exists to stop),
  `server.workers` / `server.upstream_workers` are pinned at 128 / 64 rather than
  derived from the machine, and `upstream.attempts` is 1 so a failure reads as
  one rather than as a slower success. `cmd/bench/server.go` is where that
  template lives.
- **Its own certificates.** ECDSA P-256 and RSA-2048, generated per run, so the
  handshake comparison is not at the mercy of whatever is in `certs/`.
- **The server process alone.** RSS and CPU come from `/proc/<pid>` for elodin
  only. The generator and the mock share this machine, and anything taken from
  the whole system would be mostly them.

**DNSSEC is off throughout.** The mock serves an unsigned zone with no chain to
the root, so with validation on every answer would be SERVFAIL and the tables
would describe a failing resolver. What validation costs is a separate question
from what the transports cost — as is what rate limiting costs, which is the
other setting held away from its shipped value for the same kind of reason.

## Why the load generator is its own thing

`cmd/loadgen` builds and parses DNS messages itself (`internal/dnswire`) rather
than linking elodin's codec. A generator sharing the encoder under test could
agree with a bug in it and still report success — the same reasoning the
integration suite applies to its fixtures.

Every client holds one connection for the whole run. That is what the
per-transport table is meant to describe: the cost of answering on an
established connection, not of establishing one. Handshakes are measured
separately by `-transport=handshake`, which reconnects for every query.

## Noise, and what is done about it

Run-to-run spread on an ordinary machine is around ten percent — larger than
several of the differences these tables are meant to show. So each scenario runs
three times and the median is kept (`-repeat`), and the spread is reported where
an A/B comparison depends on it.

That is enough to keep a result honest but not enough to make a busy laptop
behave like a quiet server. Before believing a difference smaller than the
reported spread, run the pair again — and if a result is surprising, run the
same configuration against itself and check the harness reports no difference.
That control is how the query-logging result was confirmed rather than assumed.

## Scenarios

| `-only` | what it produces |
|---|---|
| `workloads` | cache hits, blocked, rewritten, light load, sustained misses |
| `transports` | UDP, TCP, DoT, DoH/1.1, DoH/2 at 100 clients; TCP at 500 |
| `h1h2` | HTTP/1.1 against HTTP/2 under 8 concurrent requests per client |
| `cpu` | CPU per query per transport |
| `handshake` | fresh TLS handshakes, ECDSA against RSA |
| `memory` | idle, worker arenas, per blocklist rule, per cache entry |
| `shedding` | behaviour past capacity, bounded against unbounded queueing |
| `logging` | what `log.queries` costs and what it writes |

Rows that depend on the server doing a particular thing assert it: the blocked
row fails unless the answers are NXDOMAIN, so a rule that stopped matching shows
up as a failed run rather than as a number that quietly measures forwarding.

## The rate-limiting experiment

`cmd/rrlexp` is a separate thing from the matrix above, and not part of `mise run
bench`. Every arm runs two clients against one server at once — a flood and a
victim asking at a household rate — and reports what the *victim* got, which is
the question the response limiter's own tests cannot answer from one client at a
time. `cmd/rrlexp/main.go` opens with what each group of arms claims.

```sh
mise run release
cd bench
go run ./cmd/rrlexp -out results/$(date +%F)-rate-limit.md    # about six minutes
go run ./cmd/rrlexp -only handshake-flood                     # one group
```

Four things a publicly reachable instance meets are arms of their own:

| `-only` | what it asks |
|---|---|
| `slowloris` | one prefix holding the connection table idle, with and without a share of it |
| `handshake-flood` | a client that only handshakes, over DoT and DoH, against a DoT victim |
| `v6/` | the prefix-isolation arms over IPv6, where a prefix is a /64 |
| `-soak 1h` | one flood for an hour, with the server read throughout rather than at the end |

### IPv6

The IPv4 arms help themselves to addresses out of 127.0.0.0/8, which is local in
its entirety on Linux. IPv6 has one loopback address and no equivalent range, so
sending from two /64s at once takes three addresses this harness cannot create:

```sh
sudo ip -6 addr add fd00:1::2/128 dev lo   # the flood
sudo ip -6 addr add fd00:1::3/128 dev lo   # a victim in its /64
sudo ip -6 addr add fd00:2::1/128 dev lo   # a victim in another /64
```

ULAs on `lo`, so the arms stay as local as the IPv4 ones, and inside `fc00::/7`,
which `server.allow_from` allows by default the way it allows loopback. Without
them the `v6/` arms are skipped — named in the run and in the report, with the
command above, rather than quietly left out. `ip -6 addr del` the same three to
put the machine back.

### The soak

```sh
go run ./cmd/rrlexp -soak 1h -soak-sample 1m -out results/$(date +%F)-soak.md
```

`-soak` is a mode rather than an arm: it runs the soak arm alone, since an hour
of load behind six minutes of unrelated arms is six minutes of waiting to find
out whether the harness got as far as starting it. The report gains a row per
sample — resident memory, threads, descriptors, cache entries, connections being
served, and the victim's answer rate over that window rather than averaged over
the hour. An arm that stopped answering for its last ten minutes has the same
average as one that behaved throughout, which is the whole reason the mode
exists.

## The DNSSEC survey

```sh
cd bench
go run ./cmd/bench -survey 9.9.9.9:53 -out results/$(date +%F)-dnssec.md
```

This one asks the public network, so it is not part of `mise run bench` and its
result depends on the day. It exists because neither test layer can answer the
question it answers: both work from fixtures, so both can show that a forged
answer is refused, and neither can show that validation leaves working names
working. A validator that refused everything would pass the entire suite.

It asks every name in `domains.txt` through elodin with validation on, asks a
reference validating resolver the same thing, and compares the rcode and the AD
bit. Names marked `bogus` are deliberately broken and must be refused. A
disagreement is not automatically a bug — a zone signed with an algorithm the
local OpenSSL declines to run comes back without AD by design — but every one
of them needs an explanation.

## Layout

```
cmd/bench/      orchestrator: starts everything, runs the matrix, prints markdown
cmd/loadgen/    one scenario against a running server, reports JSON
cmd/mockdns/    upstream that answers after a fixed delay
cmd/rrlexp/     the rate-limiting and connection-share experiment: two clients, one server, per arm
internal/dnswire/   DNS message building and parsing, independent of elodin
internal/hist/      latency samples and percentiles
internal/procstat/  RSS, CPU time and thread count for one pid
results/        committed runs, so a change in the numbers is visible in a diff
```
