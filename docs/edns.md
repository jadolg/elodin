# DNS cookies, padding and keepalive

## DNS cookies

```yaml
cookies:
  enabled: true          # answer clients that send a cookie
  require: false         # demand a valid one from UDP clients that send any
  upstream: true         # present a cookie of our own to plain upstreams
  secret: ""             # 32 hex characters; empty draws a random one at startup
```

Cookies (RFC 7873, RFC 9018) add 64 bits a forger off the path cannot see to the
UDP transaction ID and source port.

| | client-facing | upstream |
|---|---|---|
| setting | `cookies.enabled` | `cookies.upstream` |
| default | on | on |
| secret | `cookies.secret`, or random at startup | random per upstream |
| server cookie | recomputed per query, nothing stored | learned and held per upstream |
| transports | UDP, TCP, DoT, DoH | UDP and TCP only |
| a cookie that does not check out | answered anyway, or BADCOOKIE with `require` | ignored, and the wait continues |
| a message with no cookie | answered, and given none back | accepted, unless that server has issued one before |

**Client-facing.** The server cookie is recomputed on each query from the
client's cookie, its address and a timestamp, keyed by the secret, so there is no
per-client table and a leaked cookie stops working within the hour. A cookie
option of impossible length is answered FORMERR with no cookie (RFC 7873
section 5.2.2).

- `require` answers a UDP query that carries a cookie but no valid server cookie
  with BADCOOKIE and a fresh cookie, before the name is looked up, so a forged
  query never gets an answer sent to its victim. It costs honest clients one
  extra round trip on first contact, so keep it for an attack under way (as RFC
  7873 intends). Queries with no cookie, and TCP, DoT and DoH, are unaffected.
- `require: true` with `enabled: false` is rejected at startup.
- Set `secret` when several elodin instances answer on one address; otherwise
  each rejects the cookies the others issued.

**Upstream.** elodin sends a random client cookie per server plus the server
cookie that server last issued.

- A reply whose cookie is not ours is ignored and elodin keeps waiting for the
  real one; answering SERVFAIL would reward the spoofer.
- Once a server has issued a cookie, a reply from it without one is ignored the
  same way (RFC 7873 §5.3). A server that never sent one is treated as not
  supporting cookies.
- A BADCOOKIE reply carries a fresh server cookie, and the query is retried once
  with it.
- Only queries that already carry an OPT record get a cookie, so elodin never
  negotiates EDNS for a client that did not. With DNSSEC validation on (the
  default) every forwarded query carries one.
- DoT and DoH upstreams get none; the certificate already proves more.

Neither side's cookie crosses over: a client's stops at elodin whatever the cookie settings, and an
upstream's is removed before the answer reaches a client or the cache.

## EDNS padding

RFC 7830 padding hides the length of an encrypted message, which otherwise can
reveal the name asked. elodin pads with the RFC 8467 block sizes, on DoT and DoH
only:

| | client-facing | upstream |
|---|---|---|
| block | 468 octets (RFC 8467 §4.2) | 128 octets (RFC 8467 §4.1) |
| transports | DoT and DoH | DoT and DoH upstreams |
| when | the client's query carried the option | every query that carries an OPT record |
| the other side's padding | replaced with ours | stripped before the answer is cached |

- There is no setting: a custom block size would itself identify the deployment.
- UDP and plain TCP are not padded (RFC 8467 §5): the message is readable anyway,
  and on UDP the bytes would enlarge the datagrams the [UDP answer
  ceiling](rate-limiting.md#how-large-a-udp-answer-may-be) bounds.
- A client that did not send the option gets no padding (RFC 7830 §4).
- Upstream, only queries that already carry an OPT record are padded, as with
  cookies.

## Telling a client how long its connection is held

A TCP or DoT query carrying the RFC 7828 edns-tcp-keepalive option is answered
with the option set to `server.client_timeout` (10s by default) in units of
100 ms: how long elodin holds an idle connection. The value is read when the
answer is built, so it follows the current setting. Without it, a DoT client
guesses and pays a TLS handshake each time it guesses wrong, the cost
[`max_connections_per_prefix`](connections.md#how-many-connections-one-client-may-hold)
and the [connection rate limit](rate-limiting.md#rate-limiting) are sized around.

The option is sent only when:

- the transport is TCP or DoT. UDP must ignore it (RFC 7828 §3.3.1), and DoH
  leaves it to HTTP (RFC 8484 §10).
- the client sent the option (§3.2.1).
- `client_timeout` is positive. A non-positive one is no idle timeout, and the
  only value that could say so, 0, means "close now" (§3.4).

The option is hop-by-hop: a client's is removed from the query before it is
forwarded.
