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
  `cache.max_ttl`. For a denial (NXDOMAIN, NODATA, or NODATA after a CNAME) it
  is also capped by the SOA's MINIMUM (RFC 8484 section 5.1), and it is 0 when
  there is no SOA.

HTTP/2 limits, per connection:

| limit | value | advertised in SETTINGS |
|---|---|---|
| concurrent streams | 128 | yes |
| header list | 32 KiB | yes |
| HPACK table (also the ceiling on a peer's table size update) | 4096 bytes | yes |
| CONTINUATION frames per header block | 128 | no |

Server push is refused and stream priority is ignored (RFC 9113 allows both). A
header list that breaks RFC 9113 sections 8.2 or 8.3 is a stream error of type
PROTOCOL_ERROR; a conformant `CONNECT` gets a 404. HTTP/1.1 refuses the same
shapes.

A request body is at most 65535 bytes, the most RFC 8484 section 6 allows a DNS
message. Past it, HTTP/2 resets the stream with ENHANCE_YOUR_CALM, and HTTP/1.1
answers a `Content-Length` that declares more with **413** and closes the
connection, first discarding about 80 KiB of the body for up to a second so that
the 413 is not lost to a reset. A client that streams more than that without
`Expect: 100-continue` can still see the reset instead. A missing, repeated or
invalid `Host`, or a repeated `Content-Type`, is answered 400 ahead of the 413. A `Content-Length` that is not
plain decimal, or one beside a second `Content-Length` or a `Transfer-Encoding`,
gets no answer at all, whatever else is wrong with the request.

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
  443. Every other question in `resolver.arpa` is NODATA.
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
