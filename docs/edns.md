# DNS cookies, padding and keepalive

## DNS cookies

```yaml
cookies:
  enabled: true          # answer clients that send a cookie
  require: false         # demand a valid one from UDP clients that send any
  upstream: true         # present a cookie of our own to plain upstreams
  secret: ""             # 32 hex characters; empty draws a random one at startup
```

A client talking to elodin over UDP has a 16-bit transaction ID and a randomised
source port between it and a forged answer — about 32 bits, both visible to
anyone on the path. Cookies (RFC 7873, RFC 9018) add 64 bits that are not.
Nothing is remembered per client: the token is recomputed on each query from the
client's own cookie, its address and a timestamp, keyed by a secret this process
holds, so there is no table for a flood of clients to fill and a leaked cookie
stops working within the hour. An answer carries one only when the query did. A cookie option of an impossible
length is answered FORMERR, with no cookie back (RFC 7873 section 5.2.2).

`require` makes a UDP query that carries a cookie show a valid server one before
it is answered — otherwise BADCOOKIE and a cookie to come back with, before the
name is looked up at all, so an attacker forging queries from someone else's
address never gets an answer sent there. It costs honest clients one extra round
trip the first time each asks, which is why RFC 7873 has it for use while an
attack is under way, and why it is off by default. Queries with no cookie, and
queries over TCP, DoT or DoH, are unaffected. It needs `enabled`: `require: true`
with `enabled: false` is rejected at startup rather than left looking like a
protection that is on.

`secret` matters when more than one elodin answers on the same address: without
it each draws its own at startup and rejects the cookies the others handed out.

`upstream` turns the mechanism the other way round, presenting a random client
cookie per server plus the server cookie that server last issued. A reply
carrying a cookie that is not ours cannot have come from the server we asked, so
it is passed over and the socket keeps waiting for the genuine one — answering a
spoofing attempt with SERVFAIL would hand the attacker most of what it was after.
Once a server has issued a cookie, a reply from it with the option left off is
passed over the same way (RFC 7873 §5.3); a server that has never sent one does
not implement them, and the exchange carries on without. A BADCOOKIE reply
carries a fresh server cookie, so the query is asked once more with it.

Neither side's cookie crosses over: the client's stops at elodin whatever the
settings, its server half having been minted here, and the upstream's is removed
before the answer goes near a client or the cache.

| | client-facing | upstream |
|---|---|---|
| setting | `cookies.enabled` | `cookies.upstream` |
| default | on | on |
| secret | `cookies.secret`, or random at startup | random per upstream |
| server cookie | recomputed per query, nothing stored | learned and held per upstream |
| transports | UDP, TCP, DoT, DoH | UDP and TCP only |
| a cookie that does not check out | answered anyway, or BADCOOKIE with `require` | ignored, and the wait continues |
| a message with no cookie | answered, and given none back | accepted, unless that server has issued one before |

Only queries that already carry an OPT record get a cookie, since adding one
would negotiate EDNS on behalf of a client that never asked — with validation on,
which is the default, every forwarded query carries one. DoT and DoH upstreams
are left out, a certificate establishing more than a cookie can.

## EDNS padding

Encryption hides what a DNS message says, not how long it is, and DNS messages
are distinctive enough by length that an observer holding a list of candidate
names can often tell which one was asked. RFC 7830 defines the mitigation — an
EDNS option carrying nothing but zeroes — and RFC 8467 fixes the block sizes.
elodin does both halves, on DoT and DoH only:

| | client-facing | upstream |
|---|---|---|
| block | 468 octets (RFC 8467 §4.2) | 128 octets (RFC 8467 §4.1) |
| transports | DoT and DoH | DoT and DoH upstreams |
| when | the client's query carried the option | every query that carries an OPT record |
| the other side's padding | replaced with ours | stripped before the answer is cached |

There is no setting. The RFC gives one pair of numbers rather than a knob, and a
deployment padding to a block of its own choosing would be recognisable by it,
which is the opposite of the point.

UDP and plain TCP are left out deliberately (RFC 8467 §5): padding a message
anyone on the path can read hides nothing from them, and on UDP the bytes would
come out of `server.max_udp_response`, enlarging exactly the datagrams the [UDP
answer ceiling](rate-limiting.md#how-large-a-udp-answer-may-be) exists to bound. A client that
did not send the option gets no padding either (RFC 7830 §4) — it never budgeted
for the bytes. Upstream, only queries that already carry an OPT record are
padded, for the same reason cookies are. An upstream that pads its replies back
has that padding taken off before the answer is stored, so the cache holds the
answer rather than the answer plus a block of zeroes.

## Telling a client how long its connection is held

A client that opens a TCP or DoT connection and reuses it has one number it needs
and cannot see: how long this server will hold the connection idle before
reclaiming it. That number is `server.client_timeout`, ten seconds by default,
and without being told it a client either re-handshakes on a cadence it guessed
or holds a connection it believes is alive and finds out on its next query. On
DoT that guess costs a full TLS handshake, which is the cost
[`max_connections_per_prefix`](connections.md#how-many-connections-one-client-may-hold) and the
[connection rate limit](rate-limiting.md#rate-limiting) are both sized around.

So a client that asks is told. RFC 7828 defines edns-tcp-keepalive for exactly
this, and a query carrying the option is answered with one stating
`server.client_timeout` in units of 100 ms — read from the setting when the answer
is built, so changing it changes what clients are told rather than leaving them
holding a stale figure.

Three conditions, each from a rule rather than a preference. Only TCP and DoT: on
UDP there is no connection and RFC 7828 §3.3.1 says a server "MUST ignore the
option", and RFC 8484 §10 puts the whole extension outside DoH, where the
connection's lifetime is HTTP's to describe. Only a client that sent the option,
which is how §3.2.1 has a client signal it cares. And nothing at all when
`client_timeout` is not a timeout that can be stated — a non-positive setting is
no idle timeout at all, and the only value the field could carry for that is 0,
which §3.4 defines as a request to close at once.

The option is hop-by-hop, so a client's own is taken back out of the query before
it is forwarded. It describes the connection between that client and this server
and means nothing one hop further on; relayed to a UDP upstream it would also be
this server sending the shape §3.2.1 forbids outright.
