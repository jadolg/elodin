# Connections and datagrams

## How many connections one client may hold

```yaml
server:
  max_connections: 512            # TCP, DoT and DoH connections at once, for the whole server
  max_connections_per_prefix: 0   # how many of them one client may hold; 0 derives half
```

`max_connections_per_prefix` is one client's share of the table, counted against
established connections per /24 and per /64 — the same unit as the [response
budget](rate-limiting.md#rate-limiting).

- `0` derives half of `max_connections`: 256 of the default 512.
- A value at or above `max_connections` is no cap: one client may hold the whole
  table. Ask for that on purpose only, e.g. for a single large NAT.
- A connection past the share is closed on accept and counted as
  `conn_refused=`, like one past the table. The first refusal is logged at `warn`, naming which of
  the two limits refused it, and later ones at `debug`; raising the wrong one makes the other worse.
- Both figures are logged at startup and exported as `elodin_connections_max` /
  `elodin_connections_max_per_prefix`.

The share bounds *occupancy*; the [rate limiter](rate-limiting.md#rate-limiting)
bounds *arrivals*. Each needs the other: a flood holding each connection only for
a handshake never reaches the share, and a client opening one connection a second
and closing none fills any table inside any rate. `client_timeout` reclaiming an
idle connection after ten seconds is a delay, not a bound.

**On a private network,** every device on `192.168.1.0/24` is one client,
sharing 256 connections. A resolver serving more devices than half its table
wants the share raised, or `max_connections` raised under it.

**On a public instance,** consider going much lower. A real client holds one
connection per device and reuses it, so a share in the low tens is generous.

The share bounds a *prefix*, not an actor. On IPv6 a /48 (a routine allocation)
is 65,536 /64s, so two /64s fill the default table; at a share of 16 it takes 32.

UDP is unaffected: no connections, no per-client state. A resolver whose table
has been taken can look healthy on datagrams while every TCP, DoT and DoH client
gets nothing. The measurement is under [running a public
resolver](public-resolver.md#connection-table-share).

## How fast datagrams can be read

```yaml
listeners:
  udp:
    readers: 0                # threads reading the socket; 0 derives one per usable CPU, to 8
    receive_buffer: 1MiB      # what each reader asks the kernel to hold for it
```

```console
$ elodin --check
  udp: 4 readers, asking for 1MiB of receive buffer each (derived from 4 usable CPUs)
```

Everything a datagram costs before the rate limiter sees it — the `recvfrom`, the
[allow-list](access-control.md#who-may-ask) compare, the hash of the source
prefix — happens on the reader thread. Past what the readers can drain, the
kernel's receive queue overflows and drops datagrams, so no budget or setting in
elodin applies to them. The drain rate and drop figures are under [running a
public resolver](public-resolver.md#datagrams-the-readers-can-drain).

- Each reader binds the same address and port with `SO_REUSEPORT` and gets its
  own receive queue; the kernel spreads datagrams between them by hashing the
  4-tuple. A flood from one source port lands on one reader; one from many ports
  spreads over all of them.
- `0` derives one reader per usable CPU, up to eight, the same reading as the
  [worker counts](sizing.md#sizing). The number is in the startup line and
  `--check`.
- The listener takes the port with an ordinary bind before the readers share it,
  so a port somebody else already holds — including a second elodin — is refused
  with `Address_In_Use`. Sharing is limited by the kernel to the same effective
  user, and elodin binds before it [drops privileges](install.md#privileges).
- `receive_buffer` absorbs a burst while every reader is busy. Linux clamps it to
  `net.core.rmem_max` (208 KiB untuned); the startup line reports what was
  granted, `--check` only what will be asked for. Raise the sysctl if you raise
  this.

What the kernel dropped is exported per reader as
`elodin_udp_receive_drops_total`, beside `elodin_udp_datagrams_total` for what
each reader read. They are the only way to see this from inside the server. A
rise in drops is also logged at the five-minute report.

Readers are headroom, not a defence. **A publicly reachable instance wants a
packet filter in front of it**, or upstream scrubbing.
