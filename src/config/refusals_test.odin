package config

import "core:strings"
import "core:testing"

// Whether loading `doc` fails with `wanted` as one of its messages, word for word.
@(private = "file")
refused_with :: proc(t: ^testing.T, doc, wanted: string, loc := #caller_location) {
	_, err := load_string(doc, context.temp_allocator, tls_files = false)
	e, has := err.?
	if !testing.expectf(t, has, "accepted, wanted %q, from:\n%s", wanted, doc, loc = loc) {
		return
	}
	for m in e.messages {
		if m == wanted {
			return
		}
	}
	testing.expectf(t, false, "no message is %q: %v", wanted, e.messages, loc = loc)
}

/*
The refusals a shared loader writes for each of its callers, word for word: the
key each names is the caller's own, so one helper behind several sections must
not let one section's name leak into another's message.
*/
@(test)
test_shared_loaders_name_their_callers_keys :: proc(t: ^testing.T) {
	Case :: struct {
		doc, wanted: string,
	}
	DOH :: "listeners:\n  doh: {enabled: true, cert_file: c, key_file: k, path: "
	cases := [?]Case {
		{MINIMAL + "blocking:\n  rules: {a: b}\n", "blocking.rules: expected a list of rules"},
		{MINIMAL + "blocking:\n  allow: {a: b}\n", "blocking.allow: expected a list of rules"},
		{MINIMAL + "dnssec:\n  trust_anchors: {a: b}\n", "dnssec.trust_anchors: expected a list of DS records"},
		{MINIMAL + DOH + "dns-query}\n", "listeners.doh.path: must start with '/'"},
		{MINIMAL + DOH + "\"/q?x\"}\n", "listeners.doh.path: must be visible ASCII with no '?' or '#'"},
		{MINIMAL + DOH + "/dns-query, mobileconfig_path: p}\n", "listeners.doh.mobileconfig_path: must start with '/'"},
		{
			MINIMAL + DOH + "/dns-query, mobileconfig_path: \"/p#x\"}\n",
			"listeners.doh.mobileconfig_path: must be visible ASCII with no '?' or '#'",
		},
		{MINIMAL + "metrics:\n  enabled: true\n  path: m\n", "metrics.path: must start with '/'"},
		{MINIMAL + "metrics:\n  enabled: true\n  path: \"/m?x\"\n", "metrics.path: must be visible ASCII with no '?' or '#'"},
		{
			"upstream:\n  servers: 1.1.1.1\n",
			"upstream.servers: expected a list of servers, with a \"-\" in front of each one",
		},
		{
			MINIMAL + "  zones:\n    - domains: [corp.example]\n      servers: 10.0.0.1\n",
			"upstream.zones[0].servers: expected a list of servers, with a \"-\" in front of each one",
		},
		{"upstream:\n  bootstrap: [nope]\n  servers: [1.1.1.1]\n", "upstream.bootstrap: \"nope\" is not an IP address"},
		{
			MINIMAL + "  zones:\n    - domains: [corp.example]\n      bootstrap: [nope]\n      servers: [10.0.0.1]\n",
			"upstream.zones[0].bootstrap: \"nope\" is not an IP address",
		},
		{MINIMAL + "  zones:\n    - domains: [corp.example]\n      servers: [\"tls://\"]\n", "upstream.zones[0].servers[0]: cannot parse \"tls://\""},
		{
			MINIMAL + "server:\n  max_connections: 0\n",
			"server.max_connections must be at least 1 (it is 0); 512 is the default",
		},
		{
			MINIMAL + "listeners:\n  udp: {enabled: false}\n  tcp: {enabled: false}\n",
			"listeners: every listener is disabled, so nothing would be served",
		},
	}
	for c in cases {
		refused_with(t, c.doc, c.wanted)
	}

	// A route whose `servers` is not a list is dropped there, not reported a
	// second time as a route with no servers.
	_, err := load_string(MINIMAL + "  zones:\n    - domains: [corp.example]\n      servers: 10.0.0.1\n", context.temp_allocator)
	if e, has := err.?; testing.expect(t, has, "a route with servers: 10.0.0.1 loaded") {
		testing.expectf(t, len(e.messages) == 1, "wanted one refusal: %v", e.messages)
	}
	free_all(context.temp_allocator)
}

/*
A space outside ASCII at either end of a configured name is refused, not
trimmed: a no-break space pasted from a web page, or written as YAML's `\_`, is
a byte the operator wrote, and the name means its bytes or nothing (#438). ASCII
space around it is still trimmed.
*/
@(test)
test_a_space_outside_ascii_at_a_names_end_is_refused :: proc(t: ^testing.T) {
	Case :: struct {
		doc, key: string,
	}
	REWRITE :: "rewrites:\n  - domain: "
	cases := [?]Case {
		{MINIMAL + REWRITE + "\"lan.example\\_\"\n    answer: 10.0.0.1\n", "rewrites[0].domain: \"lan.example\\u00a0\""},
		{MINIMAL + REWRITE + "\"*.lan.example\\_\"\n    answer: 10.0.0.1\n", "rewrites[0].domain: \"*.lan.example\\u00a0\""},
		{MINIMAL + REWRITE + "lan.example\n    answer: \"host.example\\_\"\n", "rewrites[0].answer: an answer host"},
		{MINIMAL + REWRITE + "lan.example\n    answer: \"\\_host.example\"\n", "rewrites[0].answer: an answer host"},
		{MINIMAL + REWRITE + "lan.example\n    answer: \"CNAME host.example\\_\"\n", "rewrites[0].answer: CNAME host"},
		{MINIMAL + REWRITE + "lan.example\n    answer: \"MX 10 mail.example\\_\"\n", "rewrites[0].answer: MX host"},
		{MINIMAL + "  zones:\n    - domains: [\"corp.example\\_\"]\n      servers: [10.0.0.1]\n", "upstream.zones[0].domains[0]"},
		{MINIMAL + "rebind:\n  allow_domains: [\"\\_home.example\"]\n", "rebind.allow_domains[0]"},
	}
	for c in cases {
		_, err := load_string(c.doc, context.temp_allocator)
		e, has := err.?
		if !testing.expectf(t, has, "accepted:\n%s", c.doc) {
			continue
		}
		found := false
		for m in e.messages {
			found ||= strings.has_prefix(m, c.key) && strings.contains(m, "outside ASCII")
		}
		testing.expectf(t, found, "no refusal names %q: %v", c.key, e.messages)
	}

	// The address is not one with the space on it.
	_, err := load_string(MINIMAL + REWRITE + "lan.example\n    answer: \"A 192.0.2.1\\_\"\n", context.temp_allocator)
	testing.expect(t, err != nil, "an address with a no-break space after it was read as the address")

	// Nor is a name with one inside it, which is two fields run together.
	_, err = load_string(MINIMAL + REWRITE + "lan.example\n    answer: \"TXT\\_hello\"\n", context.temp_allocator)
	testing.expect(t, err != nil, "\"TXT\\u00a0hello\" was read as a name")

	// A domain of ASCII space alone is no domain, not the root.
	refused_with(t, MINIMAL + REWRITE + "\"   \"\n    answer: 10.0.0.1\n", "rewrites[0]: missing domain")

	// ASCII space is trimmed, and before the `*.` is looked for.
	cfg, aerr := load_string(
		MINIMAL +
		REWRITE +
		"\" lan.example\\t\"\n    answer: \"CNAME host.example \"\n" +
		"  - domain: \" *.wild.example\"\n    answer: 10.0.0.1\n" +
		"rebind:\n  allow_domains: [\" home.example\\t\"]\n",
		context.temp_allocator,
	)
	if testing.expectf(t, aerr == nil, "ASCII space was refused: %v", aerr) {
		testing.expect_value(t, cfg.rewrites[0].domain, "lan.example.")
		testing.expect_value(t, cfg.rewrites[0].answers[0].name, "host.example.")
		testing.expect_value(t, cfg.rewrites[1].domain, "wild.example.")
		testing.expect(t, cfg.rewrites[1].wildcard, "\" *.wild.example\" was not read as a wildcard")
		testing.expect_value(t, cfg.rebind.allow_domains[0], "home.example.")
	}
	free_all(context.temp_allocator)
}

/*
A rewrite's type token and `block` fold ASCII only, as names do: "ſrv" (a long
s) is not SRV, and "bloc" with a KELVIN SIGN is not `block`, though Unicode
folding takes both for it.
*/
@(test)
test_rewrite_tokens_fold_ascii_only :: proc(t: ^testing.T) {
	REWRITE :: MINIMAL + "rewrites:\n  - domain: lan.example\n    answer: "
	_, err := load_string(REWRITE + "\"\u017frv 0 5 5060 sip.example\"\n", context.temp_allocator)
	testing.expect(t, err != nil, "a long s was read as SRV")

	cfg, kerr := load_string(REWRITE + "\"bloc\u212a\"\n", context.temp_allocator)
	// It loads, as a CNAME to that name: a refusal would leave nothing to check.
	if testing.expectf(t, kerr == nil && len(cfg.rewrites) == 1, "%v", kerr) {
		testing.expect(t, cfg.rewrites[0].answers[0].kind != .Block, "a KELVIN SIGN was read as the k of block")
	}

	// And a TXT string keeps a space outside ASCII at its end: it is text, and
	// the operator wrote it.
	txt, terr := load_string(REWRITE + "\"TXT hello\\_\"\n", context.temp_allocator)
	if testing.expectf(t, terr == nil, "%v", terr) {
		testing.expect_value(t, txt.rewrites[0].answers[0].strings[0], "hello\u00a0")
	}
	free_all(context.temp_allocator)
}

// An access-list entry with a space outside ASCII at an end is refused, as a
// name with one is: trimmed, it would admit a network the file does not spell.
@(test)
test_an_allow_from_entry_with_a_unicode_space_is_refused :: proc(t: ^testing.T) {
	_, err := load_string(MINIMAL + "server:\n  allow_from: [\"10.0.0.0/8\\_\"]\n", context.temp_allocator)
	testing.expect(t, err != nil, "10.0.0.0/8 with a no-break space was accepted")
	_, ok := load_string(MINIMAL + "server:\n  allow_from: [\" 10.0.0.0/8 \"]\n", context.temp_allocator)
	testing.expect(t, ok == nil, "ASCII space around an entry is trimmed")
	free_all(context.temp_allocator)
}
