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
- An entry that does not parse fails `--check`, and so does one with a space
  outside ASCII at either end, such as a no-break space.
- Carrier-grade NAT (`100.64.0.0/10`, also used by Tailscale) is not in the
  default: behind one, elodin would serve the ISP's other customers.

The check runs before the message is parsed, before the rate limiter and before
the query is started:

- **UDP**: the datagram is dropped (a REFUSED would itself be a reflection).
- **TCP, DoT, DoH**: the connection is closed on accept, before a fiber or TLS
  handshake, so refused sources cannot use up `max_connections`.
- **A reload that narrows the list** reaches connections already open, at their
  next query: TCP and DoT ones are closed unanswered; a DoH request gets `403`
  and the connection is closed (HTTP/2 sends `GOAWAY` with `NO_ERROR` first).
- Counted as `refused=`: one per datagram on UDP, one per connection on streams,
  whether refused on accept or at its next query after a reload.
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

## What it says about itself

`server.identity` decides the CHAOS TXT answers to `version.bind`,
`version.server`, `hostname.bind` and `id.server`, and the `Server` field on
DoH and metrics answers. It applies on reload.

| Value | CHAOS names | `Server` field |
|---|---|---|
| `version` (default) | `elodin <version>` on the version names, `elodin` on the others | `elodin/<version>` |
| `"text"` (quoted) | the text, on all four | none |
| `off` | REFUSED, logged `outcome=refused detail=chaos` | none |

```yaml
server:
  identity: off
```

- A text is quoted, printable ASCII, 1 to 255 bytes. Quoting is what makes
  `"off"` or `"version"` a text; a bare word that is neither mode is refused.
- On a resolver strangers can reach, use `off`: the exact build tells them which
  of this project's published fixes it lacks. RFC 4892 asks that server
  identification be easy to disable, and RFC 9110 section 10.2.4 that `Server`
  not carry needless detail.
- The build stays in `--version`, the startup line and the `elodin_build_info`
  metric: the [metrics endpoint](metrics.md) binds loopback by default and is
  for the operator, not for clients.

## Recursion only when asked

elodin forwards to an upstream only when the query has RD set (RFC 1035 section
4.1.1). A query with RD=0 gets what is already cached, and otherwise REFUSED
rather than a silent drop, so the client finds out instead of timing out.

- Logged as `outcome=refused detail=rd`. It does not add to `refused=`, which
  counts sources turned away before a query exists.
- The refusal still carries RA=1, which states the server offers recursion
  (RFC 1035), as BIND and Unbound do.
