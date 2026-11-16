package server

import "core:net"
import "core:strings"
import "core:testing"
import "core:time"
import "elodin:config"
import "elodin:dns"

// The names `answer_chaos` answers, and what each says under `Identity.Version`.
@(private = "file")
Chaos_Name :: struct {
	name, version_text: string,
}

@(private = "file")
CHAOS_NAMES :: [?]Chaos_Name {
	{"version.bind.", "elodin " + VERSION},
	{"version.server.", "elodin " + VERSION},
	{"hostname.bind.", "elodin"},
	{"id.server.", "elodin"},
}

// The one TXT string `resp` answers with, or `ok` false when it holds anything else.
@(private = "file")
only_txt :: proc(resp: dns.Message) -> (text: string, ok: bool) {
	if len(resp.answer) != 1 {
		return "", false
	}
	txt, is_txt := resp.answer[0].data.(dns.Rdata_TXT)
	if !is_txt || len(txt.strings) != 1 {
		return "", false
	}
	return txt.strings[0], true
}

/*
`server.identity` decides every CHAOS name the same way: the build under
`version`, the operator's text under a text, and REFUSED under `off` - the rcode
any other class this server does not serve gets, rather than an answer saying
the name does not exist (RFC 4892 sections 3 and 5 ask only that it be easy to
disable).
*/
@(test)
test_server_identity_decides_every_chaos_name :: proc(t: ^testing.T) {
	cfg: config.Config
	s := local_server(&cfg)
	defer free_all(context.temp_allocator)

	for c in CHAOS_NAMES do for type in ([]dns.Type{.TXT, .ANY}) {
		cfg.server.identity, cfg.server.identity_text = .Version, ""
		resp, outcome, ok := ask_local(&s, c.name, type, class = .CH)
		if !testing.expectf(t, ok, "%s %v, version: no answer", c.name, type) {
			continue
		}
		text, one := only_txt(resp)
		testing.expectf(t, outcome == .Local && one && text == c.version_text, "%s %v, version: %v %q, want Local %q", c.name, type, outcome, text, c.version_text)

		cfg.server.identity, cfg.server.identity_text = .Text, "resolver"
		resp, outcome, ok = ask_local(&s, c.name, type, class = .CH)
		if !testing.expectf(t, ok, "%s %v, text: no answer", c.name, type) {
			continue
		}
		text, one = only_txt(resp)
		testing.expectf(t, outcome == .Local && one && text == "resolver", "%s %v, text: %v %q, want Local \"resolver\"", c.name, type, outcome, text)

		cfg.server.identity, cfg.server.identity_text = .Off, ""
		resp, outcome, ok = ask_local(&s, c.name, type, class = .CH)
		if !testing.expectf(t, ok, "%s %v, off: no answer", c.name, type) {
			continue
		}
		testing.expectf(
			t,
			outcome == .Refused && resp.flags.rcode == u8(dns.Rcode.Refused) && len(resp.answer) == 0,
			"%s %v, off: %v rcode %v with %d answers, want Refused and none",
			c.name,
			type,
			outcome,
			resp.flags.rcode,
			len(resp.answer),
		)
	}
}

/*
The `Server` field names the build under `version` and is left out otherwise:
RFC 9110 section 10.2.4 makes it optional, and asks that an origin not send
needlessly fine-grained detail in it.
*/
@(test)
test_server_identity_decides_the_server_field :: proc(t: ^testing.T) {
	Case :: struct {
		identity: config.Identity,
		want:     string,
	}
	cases := []Case {
		{.Version, "\r\nServer: elodin/" + VERSION + "\r\n"},
		{.Text, ""},
		{.Off, ""},
	}
	for c in cases {
		cfg: config.Config
		s := local_server(&cfg)
		cfg.server.identity = c.identity
		cfg.server.identity_text = "resolver" if c.identity == .Text else ""

		client, accepted, paired := loopback_tcp_pair(t)
		if !paired {
			return
		}
		defer net.close(client)
		written := send_http_ok(&s, Conn{socket = accepted}, DOH_CONTENT_TYPE, nil, false, "Cache-Control", "no-store")
		net.close(accepted)
		if !testing.expectf(t, written, "%v: the 200 was not written", c.identity) {
			continue
		}
		got, err := read_until_close(client, 3 * time.Second)
		if !testing.expectf(t, err == nil && strings.has_prefix(got, "HTTP/1.1 200 OK\r\n"), "%v: read %q (%v), want a 200", c.identity, got, err) {
			continue
		}
		if c.want != "" {
			testing.expectf(t, strings.contains(got, c.want), "%v: %q holds no %q", c.identity, got, c.want)
		} else {
			testing.expectf(t, !strings.contains(got, "\r\nServer:"), "%v: %q sends a Server field", c.identity, got)
		}
		free_all(context.temp_allocator)
	}
}
