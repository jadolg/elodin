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

The listeners bind `0.0.0.0`, so on a machine with a public address elodin is
reachable from the internet; what keeps it from being an *open* resolver is this
list. BIND's `allow-recursion` and Unbound's `access-control` exist for the same
reason. It is a different bound from [rate limiting](rate-limiting.md#rate-limiting), not a
weaker version: the rate limiter caps what one victim can be made to receive, and
this is the half that keeps this server out of the attack aimed there.

The check runs before the message is parsed, before the rate limiter and before
the query is queued, so a source not on the list costs a prefix compare and
nothing else. Over UDP the datagram is dropped, a REFUSED to a datagram source
being a reflection of its own; over TCP, DoT and DoH the connection is closed on
accept, without a thread and without a TLS handshake, so the allow list cannot
become a way to exhaust `max_connections`. Refusals are counted as `refused=` — a
datagram each on UDP, a connection each on the stream transports. A UDP source
that no reply could reach — port 0, this server's own endpoint, a multicast
group, the limited broadcast, or `0.0.0.0`/`::` — is dropped ahead of the list
and counted as `dropped=` instead, whatever the list says.

A list in the file replaces the default rather than adding to it, so include
loopback if you want it. Entries are CIDR networks in either family; a bare
address is the single host it names, host bits below the length are masked off,
and a v4-mapped entry (`::ffff:192.168.0.0/112`) is the IPv4 network it names,
since that is how a mapped client on an IPv6 socket is compared. An entry that
will not parse fails `--check`. Carrier-grade NAT (`100.64.0.0/10`, which
Tailscale also uses) is deliberately not in the default: a resolver behind one
would be serving an ISP's other customers.

An empty list is no restriction, which is how you ask for a public resolver.
elodin warns about it at every start; before running one, read [rate
limiting](rate-limiting.md#rate-limiting) and consider `cookies.require`.

```yaml
server:
  allow_from: []
```

Note the `[]`. `allow_from:` with nothing after it is a YAML null and a
configuration error, since the two things it could have meant are the shipped
default and its exact opposite.

## Recursion only when asked

`allow_from` decides who may ask; the RD bit decides what they are asking for.
RFC 1035 section 4.1.1 makes RD the client's request for a recursive lookup, and
elodin only forwards to an upstream when it is set. A query with RD=0 gets
whatever is already cached and nothing more — REFUSED, not a silent drop, so a
client that meant to ask recursively finds out rather than timing out. It shows
as `outcome=refused detail=rd` in the query log and does not add to `refused=`,
which counts sources turned away before a query exists at all. The refusal still
carries RA=1, which RFC 1035 makes a statement that the server supports recursive
service rather than that this query used it — the same thing BIND and Unbound do.
