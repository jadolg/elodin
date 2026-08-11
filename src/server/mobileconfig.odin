package server

import "core:crypto/siphash"
import "core:strings"

/*
The Apple configuration profile (.mobileconfig) that points an iPhone, iPad or
Mac at this server's DNS-over-HTTPS endpoint.

iOS 14 and macOS 11 onwards take encrypted DNS as a profile carrying a
`com.apple.dnsSettings.managed` payload (Apple's Configuration Profile
Reference). Installing it makes the device resolve through the DoH `ServerURL`
system-wide, with no app to run. The profile served here is unsigned, so on
install the device labels it "Unverified" - expected for a self-hosted resolver,
and no barrier to using it.

`ServerURL` is built from the host the request arrived on rather than from a
name in the config: the client reached this endpoint over the same TLS
connection whose certificate the DoH URL has to match, so the `Host` header (or
the HTTP/2 `:authority`) is by construction a name that resolves and verifies.
Nothing here has to be told what the server is called, and a listener answering
on several names hands each client a profile for the one it actually used.
*/

// What a device's profile installer expects; anything else and Safari offers to
// download the file rather than open it as a profile.
DOH_MOBILECONFIG_CONTENT_TYPE :: "application/x-apple-aspen-config"

// The reverse-DNS prefix Apple asks payload identifiers to be built from. Ours
// carries the per-URL UUID so two elodin profiles on one device do not collide.
@(private)
MOBILECONFIG_ID_PREFIX :: "com.github.jadolg.elodin.doh"

/*
Build the profile for a DoH endpoint reached at `https://<host><doh_path>`.

`host` is the authority the request carried - a hostname, or `host:port` for a
DoH listener on a non-standard port - and `doh_path` is `listeners.doh.path`.
Both are placed into XML and a URL, so both are escaped on the way in; callers
pass `host` through `valid_mobileconfig_host` first, which rejects anything a URL
authority cannot contain.
*/
build_doh_mobileconfig :: proc(host: string, doh_path: string, allocator := context.allocator) -> string {
	server_url_raw := strings.concatenate({"https://", host, doh_path}, context.temp_allocator)

	// Derived from the URL rather than drawn at random, so installing the profile
	// a second time replaces the first instead of stacking a duplicate. The two
	// payloads in one profile need distinct UUIDs, hence the tags.
	profile_uuid := mobileconfig_uuid(server_url_raw, "profile")
	dns_uuid := mobileconfig_uuid(server_url_raw, "dns")

	url := xml_escape(server_url_raw, context.temp_allocator)
	display_host := xml_escape(host, context.temp_allocator)

	b := strings.builder_make(allocator)
	strings.write_string(&b, `<?xml version="1.0" encoding="UTF-8"?>`)
	strings.write_byte(&b, '\n')
	strings.write_string(
		&b,
		`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">`,
	)
	strings.write_byte(&b, '\n')
	strings.write_string(&b, "<plist version=\"1.0\">\n")
	strings.write_string(&b, "<dict>\n")
	strings.write_string(&b, "\t<key>PayloadContent</key>\n")
	strings.write_string(&b, "\t<array>\n")
	strings.write_string(&b, "\t\t<dict>\n")
	strings.write_string(&b, "\t\t\t<key>DNSSettings</key>\n")
	strings.write_string(&b, "\t\t\t<dict>\n")
	strings.write_string(&b, "\t\t\t\t<key>DNSProtocol</key>\n")
	strings.write_string(&b, "\t\t\t\t<string>HTTPS</string>\n")
	strings.write_string(&b, "\t\t\t\t<key>ServerURL</key>\n")
	write_tag(&b, "\t\t\t\t", "string", url)
	strings.write_string(&b, "\t\t\t</dict>\n")
	strings.write_string(&b, "\t\t\t<key>PayloadDescription</key>\n")
	strings.write_string(&b, "\t\t\t<string>Resolve DNS through elodin over HTTPS.</string>\n")
	strings.write_string(&b, "\t\t\t<key>PayloadDisplayName</key>\n")
	strings.write_string(&b, "\t\t\t<string>elodin DNS-over-HTTPS</string>\n")
	strings.write_string(&b, "\t\t\t<key>PayloadIdentifier</key>\n")
	write_tag(&b, "\t\t\t", "string", mobileconfig_identifier(dns_uuid))
	strings.write_string(&b, "\t\t\t<key>PayloadType</key>\n")
	strings.write_string(&b, "\t\t\t<string>com.apple.dnsSettings.managed</string>\n")
	strings.write_string(&b, "\t\t\t<key>PayloadUUID</key>\n")
	write_tag(&b, "\t\t\t", "string", dns_uuid)
	strings.write_string(&b, "\t\t\t<key>PayloadVersion</key>\n")
	strings.write_string(&b, "\t\t\t<integer>1</integer>\n")
	strings.write_string(&b, "\t\t</dict>\n")
	strings.write_string(&b, "\t</array>\n")
	strings.write_string(&b, "\t<key>PayloadDescription</key>\n")
	write_tag(&b, "\t", "string", strings.concatenate({"Encrypted DNS via ", display_host, "."}, context.temp_allocator))
	strings.write_string(&b, "\t<key>PayloadDisplayName</key>\n")
	write_tag(&b, "\t", "string", strings.concatenate({"elodin DoH (", display_host, ")"}, context.temp_allocator))
	strings.write_string(&b, "\t<key>PayloadIdentifier</key>\n")
	write_tag(&b, "\t", "string", mobileconfig_identifier(profile_uuid))
	strings.write_string(&b, "\t<key>PayloadRemovalDisallowed</key>\n")
	strings.write_string(&b, "\t<false/>\n")
	strings.write_string(&b, "\t<key>PayloadType</key>\n")
	strings.write_string(&b, "\t<string>Configuration</string>\n")
	strings.write_string(&b, "\t<key>PayloadUUID</key>\n")
	write_tag(&b, "\t", "string", profile_uuid)
	strings.write_string(&b, "\t<key>PayloadVersion</key>\n")
	strings.write_string(&b, "\t<integer>1</integer>\n")
	strings.write_string(&b, "</dict>\n")
	strings.write_string(&b, "</plist>\n")
	return strings.to_string(b)
}

@(private)
write_tag :: proc(b: ^strings.Builder, indent: string, tag: string, value: string) {
	strings.write_string(b, indent)
	strings.write_byte(b, '<')
	strings.write_string(b, tag)
	strings.write_byte(b, '>')
	strings.write_string(b, value)
	strings.write_string(b, "</")
	strings.write_string(b, tag)
	strings.write_byte(b, '>')
	strings.write_byte(b, '\n')
}

@(private)
mobileconfig_identifier :: proc(uuid: string) -> string {
	return strings.concatenate({MOBILECONFIG_ID_PREFIX, ".", uuid}, context.temp_allocator)
}

/*
The fixed key the UUIDs are hashed under.

These UUIDs identify a profile; they authenticate nothing, so the key is a
constant rather than a secret - the point is only that the same URL yields the
same UUID on every machine, so a device that reinstalls the profile updates the
one it had.
*/
@(private)
MOBILECONFIG_UUID_KEY := [16]u8 {
	0x65,
	0x6c,
	0x6f,
	0x64,
	0x69,
	0x6e,
	0x2d,
	0x64,
	0x6f,
	0x68,
	0x2d,
	0x75,
	0x75,
	0x69,
	0x64,
	0x21,
}

/*
A UUID derived from `seed`, in the 8-4-4-4-12 form Apple expects.

SipHash yields eight bytes and a UUID needs sixteen, so it is taken twice: once
over the seed and once over the seed with `tag` appended, which is also what
makes the two payloads in one profile come out different.
*/
@(private)
mobileconfig_uuid :: proc(seed: string, tag: string) -> string {
	bytes: [16]u8
	key := MOBILECONFIG_UUID_KEY
	siphash.sum_bytes_to_buffer_2_4(transmute([]u8)seed, key[:], bytes[:8])
	tagged := strings.concatenate({seed, "/", tag}, context.temp_allocator)
	siphash.sum_bytes_to_buffer_2_4(transmute([]u8)tagged, key[:], bytes[8:])

	HEX :: "0123456789ABCDEF"
	out: [36]u8
	j := 0
	for i in 0 ..< 16 {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out[j] = '-'
			j += 1
		}
		out[j] = HEX[bytes[i] >> 4]
		out[j + 1] = HEX[bytes[i] & 0x0f]
		j += 2
	}
	return strings.clone(string(out[:]), context.temp_allocator)
}

/*
Whether `host` is something a DoH URL can be built around.

The value comes off the wire - the HTTP `Host` header or the HTTP/2
`:authority` - so it is checked before it is put into a URL and an XML document.
A URL authority is a hostname or IP literal with an optional port, so the set of
bytes it may contain is small; anything outside it is refused rather than
escaped and served, since it is not a host this server could have a certificate
for anyway.
*/
@(private)
valid_mobileconfig_host :: proc(host: string) -> bool {
	// A hostname is at most 253 characters; the brackets and port of an IPv6
	// authority add a handful more. Anything longer is not a host.
	if len(host) == 0 || len(host) > 261 {
		return false
	}
	for i in 0 ..< len(host) {
		switch host[i] {
		case 'a' ..= 'z', 'A' ..= 'Z', '0' ..= '9', '.', '-', ':', '[', ']':
		// A hostname, an IPv4 literal, or a bracketed IPv6 authority with a port.
		case:
			return false
		}
	}
	return true
}

// Escape the five characters that would otherwise be read as XML markup. Applied
// to every value that goes into the profile, so a host with a character the
// validator happens to allow - a bracket, say - still yields well-formed XML.
@(private)
xml_escape :: proc(s: string, allocator := context.allocator) -> string {
	b := strings.builder_make(allocator)
	for i in 0 ..< len(s) {
		switch s[i] {
		case '&':
			strings.write_string(&b, "&amp;")
		case '<':
			strings.write_string(&b, "&lt;")
		case '>':
			strings.write_string(&b, "&gt;")
		case '"':
			strings.write_string(&b, "&quot;")
		case '\'':
			strings.write_string(&b, "&#39;")
		case:
			strings.write_byte(&b, s[i])
		}
	}
	return strings.to_string(b)
}
