# DNS-over-HTTPS

```yaml
listeners:
  doh:
    enabled: true
    address: "0.0.0.0"
    port: 443
    path: /dns-query
    cert_file: /etc/elodin/cert.pem
    key_file: /etc/elodin/key.pem
    mobileconfig_path: /apple-doh.mobileconfig
```

- **HTTP/2 and HTTP/1.1**, chosen by ALPN, preferring h2. Firefox and Chrome use
  DoH only over HTTP/2; curl, `dnscrypt-proxy` and HTTP/1.1-only routers keep working. A
  client offering neither fails the handshake.
- **Both RFC 8484 forms**, on either version: `POST` with an
  `application/dns-message` body, and `GET` with a base64url `dns` parameter.
  Any other method gets a **405** with `Allow: GET, POST`; on
  `mobileconfig_path` it is `Allow: GET`.
- Requests on one HTTP/2 connection are answered in parallel, each on a fiber of
  its own counted against `server.max_pending`, so a browser's A and AAAA
  lookups run at the same time.
- `Cache-Control: max-age` is the smallest TTL in the response as sent, after
  `cache.max_ttl` (7 days with the cache off). For a denial (NXDOMAIN, NODATA, or NODATA after a CNAME) it
  is also capped by the SOA's MINIMUM (RFC 8484 section 5.1), and it is 0 when
  there is no SOA.
- Every final response, on either version and from the metrics endpoint too,
  carries a `Date` (RFC 9110 section 6.6.1), refusals included. The interim
  `100 Continue` does not; the RFC leaves that optional.

HTTP/2 limits, per connection:

| limit | value | advertised in SETTINGS |
|---|---|---|
| concurrent streams | 128 | yes |
| header list | 32 KiB | yes |
| HPACK table (also the ceiling on a peer's table size update) | 4096 bytes | yes |
| CONTINUATION frames per header block | 128 | no |

Server push is refused and stream priority is ignored (RFC 9113 allows both),
though a PRIORITY frame's shape is still checked. The frame errors are the ones
RFC 9113 names, at both ends of an HTTP/2 connection, DoH listener and upstream:
a client preface not followed by SETTINGS (and a server's that does not open
with one) is a PROTOCOL_ERROR (section 3.4); a PING not 8 bytes long, a SETTINGS
not a multiple of 6, or a SETTINGS ACK with a payload is a FRAME_SIZE_ERROR; a
PING or SETTINGS on a stream, or a PRIORITY on stream 0, is a PROTOCOL_ERROR;
and a PRIORITY not 5 bytes long is a FRAME_SIZE_ERROR for the connection, where
section 6.3 names a stream error (section 5.4 allows the stronger one). An HPACK
table size update after a field in the same header block is a COMPRESSION_ERROR
(RFC 7541 section 4.2). A request whose `content-length` is repeated, is not
digits, or is not the sum of its DATA is a stream error of type PROTOCOL_ERROR
(section 8.1.1), and so is such a response from an HTTP/2 upstream, which is
not taken as an answer. A response that defines no content (a reply to HEAD, a
204 or a 304) is not held to the sum, though a repeated or non-numeric length
still fails it; a refusal whose body misses its length keeps its status and
`Retry-After` for the upstream's backoff. A header list that breaks RFC 9113 sections 8.2 or 8.3 is a stream error of type
PROTOCOL_ERROR; a conformant `CONNECT` gets a 404. HTTP/1.1 refuses the same
shapes.

A GOAWAY ends a connection only once what it lets through is done (RFC 9113
section 6.8). A client's GOAWAY leaves the requests it has sent to be
answered; then the listener sends GOAWAY(NO_ERROR) and reads nothing more, and
the connection closes when the client closes it or at `server.client_timeout`. An upstream's
GOAWAY takes the connection out of use for new queries, lets the queries at or
below its last stream id finish, and fails those above it as refused, which are
asked again on a fresh connection. A GOAWAY carrying an error code is the peer
closing on a failure, and ends the connection at once at either end.

A request may end with trailers after its body (RFC 9113 section 8.1). Their
fields are ignored; trailers that do not carry END_STREAM, or that hold a
pseudo-header or a field section 8.2 refuses, are the same PROTOCOL_ERROR. A
HEADERS frame on a stream the client has already ended, while elodin still holds
it, is a stream error of type STREAM_CLOSED (section 5.1). Neither closes the
connection. Once the stream is answered and retired, a HEADERS frame on it is a
connection error of type PROTOCOL_ERROR.

A request body is at most 65535 bytes, the most RFC 8484 section 6 allows a DNS
message. Past it, HTTP/2 resets the stream with ENHANCE_YOUR_CALM, and HTTP/1.1
answers a `Content-Length` or a chunk that declares more with **413** and closes
the connection, first discarding about 80 KiB of the body for up to a second so
that the 413 is not lost to a reset. A client that streams more than that without
`Expect: 100-continue` can still see the reset instead. A missing, repeated or
invalid `Host`, or a repeated `Content-Type`, is answered 400 ahead of the 413. A DNS message within
the limit that has the QR bit set is a response rather than a query, and is answered 400.

HTTP/1.1 framing follows RFC 9112. Each refusal below is answered and the
connection then closed, so nothing that follows on it is read as a request:

- A chunked body is read, chunk extensions (held to their grammar) and trailer
  fields included (section 7.1), and the connection closes after its answer,
  once what the client sent behind it is drained. The chunk lines and trailer
  fields are held to 16 KiB together, as a header block is, and past it are 400. A `Transfer-Encoding` whose last
  coding is not `chunked` or that names no coding at all, `chunked` applied
  twice or with a parameter, `Transfer-Encoding` beside a `Content-Length`, and
  `Transfer-Encoding` on HTTP/1.0 are 400; another coding ahead of `chunked` is
  501, as elodin decodes chunked alone.
- A `Content-Length` that is not plain decimal, or a second one even with the
  same value, is 400 (section 6.3).
- A folded field line, whitespace before a field's colon, a field name that is
  not a token, or a bare CR, bare LF or NUL in a line is 400 (sections 2.2, 5.1,
  5.2).
- `Expect: 100-continue` on a request whose body has not arrived yet is answered
  `100 Continue` before the body is read (RFC 9110 section 10.1.1), on HTTP/2
  too; refusals the header block already decides go out as the final status
  instead. HTTP/1.0 is not sent one.
- An absolute-form target (`GET https://host/dns-query?dns=… HTTP/1.1`) is
  served like the path it names, and its authority stands in for `Host`, which
  an HTTP/1.1 request still has to carry (section 3.2.2). An authority with
  userinfo is 400.

## Discovery by clients (DDR)

A client that knows only this server's Do53 address can ask it for an encrypted
endpoint to move to: the SVCB record at `_dns.resolver.arpa` (RFC 9462). Off by
default; name the host the DoT/DoH certificate covers:

```yaml
ddr:
  name: dns.example.com
```

- The answer has one SVCB record per enabled DoT and DoH listener, priority 1,
  target `name`, TTL 300: `alpn=dot` for DoT; `alpn=h2,http/1.1` and
  `dohpath=<listeners.doh.path>{?dns}` for DoH; `port` only when it is not 853 or
  443. `resolver.arpa` itself answers its SOA and NS; every other question in
  the zone is NODATA. The zone is served as RFC 6303 describes (RFC 9462 section
  6.4), so its answers set AA.
- The additional section carries the A/AAAA records of the `rewrites` rule for
  `name`, if there is one. Otherwise the client looks the name up itself.
- `name` must be a hostname, not an address, not the root and not in
  `resolver.arpa`, and needs DoT or DoH enabled. With DoH it also needs a `path`
  a URI template takes as written: none of ``"'<>\^`{|}``, spaces, or a `%` that does not start a
  `%XX` escape.
- A listener is designated only while its certificate covers `name` through a
  DNS SAN. A whole-label wildcard counts. A partial wildcard (`d*.example.com`)
  or the subject CN does not (RFC 9525 section 6.3).
- A listener whose certificate does not cover `name` is still served, at startup
  or after a reload, and is not designated. The server logs `ddr.name: the
  certificate of listeners.<dot|doh> does not cover <name>` (`no longer covers`
  after a reload), and `--check` warns. `--check` reads the certificate only,
  not the key, and looks nothing up.
- `--check` fails on a certificate it cannot read. It warns when the
  `rewrites` rule for `name` does any of these:
  - sinks it;
  - gives a loopback address, which only this machine reaches;
  - gives only addresses that a DoT or DoH listener here is not bound to. Each
    listener is judged on its own, and a `::` listener takes IPv4 unless
    `net.ipv6.bindv6only` is 1.

  Without a rule there is nothing local to judge.
- `ddr` needs a restart to change.
- A `rewrites` rule for `_dns.resolver.arpa` wins over this.

Clients use a designation only after checking it (RFC 9462 sections 4.2 and 4.3):

- **Verified:** the certificate covers `name` and has the Do53 address the client
  asked as an IP SAN.
- **Opportunistic:** for a server on a private or link-local address, `name`
  resolves to that same address. A `rewrites` rule mapping `name` to the LAN
  address does this and also fills the additional section.

## Apple devices (iOS, iPadOS, macOS)

iOS 14 / macOS 11 and later take encrypted DNS from a configuration profile, and
the DoH listener serves one. Browse to `mobileconfig_path` on the device,
download the `.mobileconfig`, and install it under **Settings → General → VPN &
Device Management**; the device then sends all its DNS here over HTTPS.

- Set `mobileconfig_path: ""` to withhold it. It is served only while DoH is
  enabled.
- The profile's `ServerURL` is built from the authority the request arrived on.
  A listener answering on several names hands each device a profile for the one
  it used.
- That authority must be one the listener can be reached at: a host a DNS SAN
  of its certificate covers (a whole-label wildcard counts; the subject CN and
  a partial wildcard such as `d*.example.com` do not), with no port, port 443, or `listeners.doh.port`, written in
  plain decimal with no leading zero. Anything else gets a **400**. So behind a
  NAT forwarding a public port that is neither 443 nor the bound port (8443 to
  9443, say), bind elodin to the public port or have devices reach it on 443.
- The authority is lowercased. The profile's identifiers derive from the URL, so
  reinstalling replaces it rather than adding a duplicate.

The profile is **signed with the DoH listener's own certificate**; there is
nothing to configure, and a renewed certificate is picked up without a restart.
The device checks the signer against its own trust store:

- a public CA certificate (Let's Encrypt and the like): *Verified*, in green.
  `cert_file` must hold the full chain; the device has the root, not the
  intermediates.
- a self-signed certificate: *Not Verified*, but it still installs.

While the certificate is outside its validity window the endpoint answers
**503**.

Signed profiles are cached and signing is rate limited. Given the host, port and
spelling rules above, an ordinary certificate allows only a handful of
authorities, all cached. A certificate whose SAN is a wildcard or an IP address
covers unbounded hosts, so under a sustained flood a device whose authority is
not cached yet can get a 503 until the flood stops. Resolution is unaffected;
only the profile download is refused.
