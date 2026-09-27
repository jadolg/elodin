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
- Requests on one HTTP/2 connection are answered in parallel on the query worker
  pool, so a browser's A and AAAA lookups run at the same time.

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
- That authority must be one the listener can be reached at: a host its
  certificate covers, with no port, port 443, or `listeners.doh.port`, written in
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
