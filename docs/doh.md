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

The endpoint serves HTTP/2 and HTTP/1.1 and picks between them with ALPN,
preferring h2. That matters because Firefox and Chrome will only use a DoH
resolver over HTTP/2, while curl, `dnscrypt-proxy` and HTTP/1.1 routers keep
working unchanged; a client offering neither gets a clean handshake failure.
Both request forms of RFC 8484 are accepted on either version: `POST` with an
`application/dns-message` body, and `GET` with a base64url `dns` parameter.
Requests on one HTTP/2 connection are answered on the query worker pool rather
than one after another on the connection's reader thread, so the A and AAAA
lookups a browser issues for the same name run at the same time.

`src/h2/` covers the preface and SETTINGS exchange, HPACK with Huffman decoding
and a full dynamic table, HEADERS with CONTINUATION, DATA, connection- and
stream-level flow control, WINDOW_UPDATE, PING, RST_STREAM and GOAWAY. Server
push is refused and stream priority parsed and ignored, which RFC 9113 permits.
What one connection may make this end hold is stated in the SETTINGS frame rather
than left to be discovered: 128 concurrent streams, a 32 KiB header list and a
4096-byte HPACK table — also the ceiling on a peer's table size updates. One more
bound has no SETTINGS field and is enforced without being advertised: at most 128
CONTINUATION frames per header block, since a block bounded only by its
size never ends if the frames carrying it are empty.

A decoded header list is checked against RFC 9113 sections 8.2 and 8.3 before it
becomes a request, and anything malformed there is a stream error of type
PROTOCOL_ERROR. A conformant `CONNECT` is the one shape that looks malformed by
those rules and is not, so it draws a 404 rather than a stream error. The
HTTP/1.1 side refuses the same shapes.

## Apple devices (iOS, iPadOS, macOS)

Encrypted DNS on iOS 14 / macOS 11 and later is configured with a profile rather
than an app, and the DoH listener serves one: browse to `mobileconfig_path` on
the device and it downloads a `.mobileconfig` that, installed under **Settings →
General → VPN & Device Management**, sends the device's DNS here over HTTPS
system-wide.

The `ServerURL` inside is built from the authority the request arrived on, and
that has to be one this listener could actually have been reached at: a host the
DoH listener's certificate covers, on no port, port 443, or `listeners.doh.port`.
Anything else gets a 400 rather than a profile the device could never use — and
the port has to be written the ordinary way, in decimal with no leading zero. (The
port rule means a deployment reached on a public port that is neither 443 nor the
port elodin is bound to — a NAT forwarding 8443 to an elodin on 9443, say — gets a
400 for that authority: bind elodin to the public port, or put the device on 443,
since the URL a profile carries has to be one the device can dial.) A
listener answering on several names hands each device a profile for the one it
used. Its identifiers derive from the URL, so reinstalling replaces the profile
rather than stacking a duplicate. Set `mobileconfig_path: ""` to withhold it; it
is served only while DoH is enabled.

The profile is **signed with the DoH listener's own certificate** — there is
nothing extra to configure, and the signature follows a renewal without a
restart. What the device shows depends on that certificate, since it validates
the signer against its own trust store:

- a certificate from a public CA (Let's Encrypt and the like) — *Verified*, in
  green. Make sure `cert_file` holds the full chain: the device has the root but
  not the intermediates, and a leaf served alone cannot be chained to anything.
- a self-signed certificate — *Not Verified*, as an unsigned profile was before.
  It still installs.

While the certificate is outside its validity window the endpoint answers 503
rather than handing out a profile signed with it.

Signing is rate limited and the signed profiles are cached, and what a client may
ask to have signed is bounded from several directions: only hosts the certificate
covers, only on a port this listener answers on, and only in one spelling of each
— the authority is lowercased and the port has to be plain decimal. On an ordinary
certificate that leaves a handful of authorities, all of them cached.

A certificate whose SAN is a wildcard or an IP address has no such ceiling on the
hosts it covers, and there the rate limit is what remains. Under a sustained flood
a device whose authority is not already cached can be refused with a 503 until it
stops. Resolution is unaffected — it is the profile download that is refused, and
only while the flood lasts.
