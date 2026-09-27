# Who may ask

```yaml
server:
  allow_from:                     # the default, shown in full
    - 127.0.0.0/8
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16
    - 169.254.0.0/16
    - ::1/128
    - fc00::/7
    - fe80::/10
```

The listeners bind `0.0.0.0`, so on a machine with a public address this list is
what keeps elodin from being an open resolver. It is BIND's `allow-recursion` and
Unbound's `access-control`. [Rate limiting](rate-limiting.md#rate-limiting) is a
separate bound: it caps what one victim receives; this keeps the server out of
the attack.

- **A list in the file replaces the default**, so include loopback if you want it.
- Entries are CIDR networks in either family. A bare address is that one host,
  host bits below the length are masked off, and a v4-mapped entry
  (`::ffff:192.168.0.0/112`) matches the IPv4 network it names.
- An entry that does not parse fails `--check`.
- Carrier-grade NAT (`100.64.0.0/10`, also used by Tailscale) is not in the
  default: behind one, elodin would serve the ISP's other customers.

The check runs before the message is parsed, before the rate limiter and before
the query is queued:

- **UDP**: the datagram is dropped (a REFUSED would itself be a reflection).
- **TCP, DoT, DoH**: the connection is closed on accept, before a thread or TLS
  handshake, so refused sources cannot use up `max_connections`.
- Counted as `refused=`: one per datagram on UDP, one per connection on streams.
- A UDP source no reply could reach — port 0, this server's own endpoint, a
  multicast group, the limited broadcast, or `0.0.0.0`/`::` — is dropped before
  the list, whatever it says, and counted as `dropped=`.

## A public resolver

```yaml
server:
  allow_from: []
```

An empty list is no restriction. elodin warns about it at every start; read
[rate limiting](rate-limiting.md#rate-limiting) and consider `cookies.require`
first.

Write the `[]`: `allow_from:` with nothing after it is a YAML null and a
configuration error, since it could mean either the default or its opposite.

## Recursion only when asked

elodin forwards to an upstream only when the query has RD set (RFC 1035 section
4.1.1). A query with RD=0 gets what is already cached, and otherwise REFUSED
rather than a silent drop, so the client finds out instead of timing out.

- Logged as `outcome=refused detail=rd`. It does not add to `refused=`, which
  counts sources turned away before a query exists.
- The refusal still carries RA=1, which states the server offers recursion
  (RFC 1035), as BIND and Unbound do.
