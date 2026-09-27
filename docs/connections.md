# Connections and datagrams

## How many connections one client may hold

```yaml
server:
  max_connections: 512            # TCP, DoT and DoH connections at once, for the whole server
  max_connections_per_prefix: 0   # how many of them one client may hold; 0 derives half
```

`max_connections` is one budget for the whole server, and on its own it says
nothing about how it is shared. Nothing else bounds how long a client keeps what
it was given either — [rate limiting](rate-limiting.md#rate-limiting) charges opening a connection
and charges the queries asked over it, and both are rates a client can stay inside
while letting go of nothing, while `client_timeout` reclaiming an idle one after
ten seconds is a delay rather than a limit to somebody willing to open another. So
the answer to "how many of my 512 connections can one stranger have" was "all of
them".

The two bounds need each other. A share does not bound arrivals: a flood that
holds each connection only for the length of a handshake never reaches 256 out of
512, which is what the handshake measurement under [rate
limiting](rate-limiting.md#rate-limiting) is about. An arrival
budget does not bound occupancy: a client opening one connection a second and
closing none fills any table inside any rate.

`max_connections_per_prefix` is the share. It is counted against established
connections, per /24 and per /64 — the same unit the response budget uses, so
the two agree about who a client is — and a connection past a client's share is
closed on accept and counted as `conn_refused=`, like one past the table itself.
The log line under it names which of the two figures refused it, because raising
the wrong one makes the other worse.

`0` derives half of `max_connections`, so the default table of 512 gives any one
prefix 256. Anything at or above `max_connections` is no cap at all — one client
may hold the whole table, which is what elodin did before this setting existed
and what an operator serving a single large NAT should ask for on purpose. Both
figures are in the log at startup, and in
`elodin_connections_max` / `elodin_connections_max_per_prefix`.

**On a private network, note what a prefix is.** Every device on
`192.168.1.0/24` is one client to this setting, sharing 256 connections between
them; a resolver serving more devices than half its table wants the share raised,
or `max_connections` raised underneath it. Half is chosen to be a bound nobody
trips over rather than a tight one: it guarantees that no single client can lock
the rest out, and asks nothing of an operator who has not read this.

On a public instance, consider going much lower. A real client holds one
connection per device and reuses it, so a share in the low tens is generous for
anybody legitimate and leaves a stranger holding a fortieth of the table instead
of half of it.

Note that what it bounds is a *prefix* rather than an actor, and the two are
furthest apart on IPv6: a /48 is 65,536 /64s and a routine allocation from a
hosting provider or a tunnel broker, so a stranger who has one can take a share
from each and fill the table out of as many prefixes as that takes. Two of them
are enough against the default 256. The share is what makes that expensive
rather than impossible — at 16, a table of 512 costs 32 prefixes instead of two
— and it is the same granularity, with the same limitation, as the [response
budget](rate-limiting.md#rate-limiting).

UDP is unaffected either way — no connections, no per-client state, nothing to
refuse — which is why a resolver whose table has been taken can look healthy on
datagrams while every TCP, DoT and DoH client gets nothing.
`bench/results/2026-09-03-connection-table-share.md` measures that, and the same
load with a share in place.

## How fast datagrams can be read

```yaml
listeners:
  udp:
    readers: 0                # threads reading the socket; 0 derives one per usable CPU, to 8
    receive_buffer: 1MiB      # what each reader asks the kernel to hold for it
```

Everything a datagram costs before the rate limiter can see it — the `recvfrom`,
the [allow-list](access-control.md#who-may-ask) compare, the siphash of the source prefix —
happens on the thread that read it. So the rate at which this server can *hear*
is the ceiling on every fairness property below it: past what its readers can
drain, the kernel's receive queue overflows and datagrams are dropped by the
socket, which is to say by nobody the configuration can reach. The client whose
queries are lost there is whichever one the queue happened to be full for.

Measured on a four-core aarch64 VM
(`bench/results/2026-09-03-udp-readers.md`): **one reader drains 2.3 million
datagrams a second**, or about 400 ns of one core each, and under a flood of two
million a second the kernel still dropped **4% of arrivals** — 918,000 datagrams
in ten seconds that reached no budget, no counter and no client. Read that as the
ceiling rather than as a disaster: the [rate limiter](rate-limiting.md#rate-limiting) held the
flood at its budget throughout and a client in an unrelated /24 was answered 98%
of the time.

The 36% that client lost when
[issue #233](https://github.com/jadolg/elodin/issues/233) was filed is gone, and
was mostly not the reader's doing: the slip's truncated answers were charged to
no budget then, so the read loop was also performing half a million sends a
second.
Giving them a pool of their own fixed that (`2026-09-03-slip-budget.md`), and
what is left is the drain rate itself.

Each reader binds the same address and port with `SO_REUSEPORT` and gets its own
receive queue, and the kernel spreads arriving datagrams between them by hashing
the 4-tuple. The drain rate then scales with cores instead of being one of them,
which is how BIND and Unbound scale the same path. Unset derives one reader per
usable CPU up to eight — the same "what can this machine have" reading as the
[worker counts](sizing.md#sizing) — and the number is in the startup line and in `--check`. The startup line also
reports what the kernel actually granted for a receive buffer; `--check` binds
nothing, so it can only say what will be asked for:

**The scaling is the mechanism's, not a measurement of this one.** The bench
above could not demonstrate a speed-up from a second reader, because the load
generator shares the machine with the server it is measuring and loopback
delivery is paid for by the sender: a second box, or a real NIC, is what would
answer it. One reader already drains more than this VM can offer, so what the
extra readers buy here is headroom above a ceiling nothing available could reach
— and `elodin_udp_receive_drops_total` is how an operator finds out whether their
own instance is anywhere near it.

```console
$ elodin --check
  udp: 4 readers, asking for 1MiB of receive buffer each (derived from 4 usable CPUs)
```

Sharing a port is bounded by the kernel to processes running as the same
effective user: elodin binds before it [drops privileges](install.md#privileges), so a
second process would have to be root — or, on an unprivileged high port, whoever
elodin already runs as — to take a share of the datagrams. That is somebody who
could read the traffic off the interface in any case, which is why this is worth
saying rather than worth worrying about. A *second elodin* is the one thing that
would qualify and must not be let in — a stale process, a unit started twice, a
configuration being tried out beside the running one would otherwise be handed
half the queries and answer them from whatever it was given. So the listener
asks for the port with an ordinary bind before the readers share it, and a port
somebody already holds is still refused with `Address_In_Use` exactly as it was
before the readers existed.

`receive_buffer` is what absorbs a burst that arrives while every reader is busy.
Linux clamps it to `net.core.rmem_max`, 208 KiB on a machine nobody has tuned, so
the startup line reports what was granted rather than what was asked for; raise
the sysctl if you raise this. What the kernel dropped anyway is published per
reader as `elodin_udp_receive_drops_total`, beside `elodin_udp_datagrams_total`
for what each reader did read — the two together are the only way to see this
condition from inside the server, since a datagram dropped in the queue never
reaches a read and is indistinguishable from one nobody sent. A rise in it is
also written to the log at the five-minute report, for operators who are not
scraping.

**None of this is a defence, and it is not meant to be read as one.** It is
headroom: it raises the rate at which the limiter's guarantees still hold, and
above that rate they still stop. A flood from a single source port hashes to a
single reader — which is the good case, the other readers being untouched — while
one from many source ports spreads over all of them exactly as legitimate traffic
does. **A publicly reachable instance wants a packet filter in front of it**, or
upstream scrubbing, which is what every public resolver runs anyway.
