package config

import "core:strings"
import "core:testing"
import "elodin:dns"

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
A configured name holding a byte outside ASCII is refused, naming the character
(#661): a client asks for an international name as its A-label (RFC 5891
section 5), so a U-label rule never fires, and an invisible character at an
edge misses the same way. A letter, number or mark gets the punycode hint;
anything else is to be deleted.
*/
@(test)
test_a_name_outside_ascii_is_refused :: proc(t: ^testing.T) {
	Case :: struct {
		doc, wanted: string,
	}
	REWRITE :: MINIMAL + "rewrites:\n  - domain: "
	cases := [?]Case {
		{REWRITE + "\"b\u00fccher.lan\"\n    answer: 10.0.0.1\n", "rewrites[0].domain: \"b\u00fccher.lan\" holds U+00FC, which is outside ASCII; " + dns.IDN_HINT},
		{REWRITE + "\"*.b\u00fccher.lan\"\n    answer: 10.0.0.1\n", "rewrites[0].domain: \"*.b\u00fccher.lan\" holds U+00FC, which is outside ASCII; " + dns.IDN_HINT},
		{REWRITE + "\"nas.lan\u200b\"\n    answer: 10.0.0.1\n", "rewrites[0].domain: \"nas.lan\\u200b\" holds U+200B, which is outside ASCII; " + DELETE_HINT},
		{REWRITE + "\"\ufeffnas.lan\"\n    answer: 10.0.0.1\n", "rewrites[0].domain: \"\\ufeffnas.lan\" holds U+FEFF, which is outside ASCII; " + DELETE_HINT},
		{REWRITE + "\"a\u2603.lan\"\n    answer: 10.0.0.1\n", "rewrites[0].domain: \"a\\u2603.lan\" holds U+2603, which is outside ASCII; " + DELETE_HINT},
		{REWRITE + "lan.example\n    answer: \"n\u00e4s.example.com\"\n", "rewrites[0].answer: an answer host \"n\u00e4s.example.com\" holds U+00E4, which is outside ASCII; " + dns.IDN_HINT},
		{REWRITE + "lan.example\n    answer: \"MX 10 m\u00e4il.example\"\n", "rewrites[0].answer: MX host \"m\u00e4il.example\" holds U+00E4, which is outside ASCII; " + dns.IDN_HINT},
		{MINIMAL + "  zones:\n    - domains: [\"c\u00f6rp.lan\"]\n      servers: [10.0.0.1]\n", "upstream.zones[0].domains[0]: \"c\u00f6rp.lan\" holds U+00F6, which is outside ASCII; " + dns.IDN_HINT},
		{MINIMAL + "rebind:\n  allow_domains: [\"h\u00f6me.example\"]\n", "rebind.allow_domains[0]: \"h\u00f6me.example\" holds U+00F6, which is outside ASCII; " + dns.IDN_HINT},
		{REWRITE + "\"a\xffb.lan\"\n    answer: 10.0.0.1\n", "rewrites[0].domain: \"a\\xffb.lan\" holds U+FFFD, which is outside ASCII; " + DELETE_HINT},
		// A joiner follows the character it joins (RFC 5892 appendix A.1, A.2),
		// so one at a label's edge was pasted with the name; inside, it may be
		// part of a word.
		{REWRITE + "\"nas.lan\u200d\"\n    answer: 10.0.0.1\n", "rewrites[0].domain: \"nas.lan\\u200d\" holds U+200D, which is outside ASCII; " + DELETE_HINT},
		{REWRITE + "\"\u200cnas.lan\"\n    answer: 10.0.0.1\n", "rewrites[0].domain: \"\\u200cnas.lan\" holds U+200C, which is outside ASCII; " + DELETE_HINT},
		{REWRITE + "\"nas\u200d.lan\"\n    answer: 10.0.0.1\n", "rewrites[0].domain: \"nas\\u200d.lan\" holds U+200D, which is outside ASCII; " + DELETE_HINT},
		{REWRITE + "\"a\u200db.lan\"\n    answer: 10.0.0.1\n", "rewrites[0].domain: \"a\\u200db.lan\" holds U+200D, which is outside ASCII; " + dns.IDN_HINT},
		{MINIMAL + "ddr:\n  name: \"d\u00f6t.example\"\n", "ddr.name holds U+00F6, which is outside ASCII; " + dns.IDN_HINT},
		{
			MINIMAL + "dnssec:\n  trust_anchors: [\"" + ROOT_ANCHOR + "\", \"b\u00fccher.lan. IN DS 1 8 2 " + ROOT_DIGEST + "\"]\n",
			"dnssec.trust_anchors[1]: \"b\u00fccher.lan. IN DS 1 8 2 " + ROOT_DIGEST + "\" holds U+00FC, which is outside ASCII; " + dns.IDN_HINT,
		},
	}
	for c in cases {
		refused_with(t, c.doc, c.wanted)
	}

	// A space outside ASCII between an answer's fields is a field split, not a
	// character to delete: deleted, `CNAMEhost.example` would load.
	refused_with(t, REWRITE + "lan.example\n    answer: \"CNAME\\_host.example\"\n", "rewrites[0].answer: an answer needs one host name, got \"CNAME\\u00a0host.example\"")

	// A trust anchor's owner is the name checked; its fields split on any
	// space, as `dnssec.parse_trust_anchor` reads them, so a no-break space
	// between two is a separator.
	_, aerr := load_string(MINIMAL + "dnssec:\n  trust_anchors: [\". IN DS 20326\\_8 2 " + ROOT_DIGEST + "\"]\n", context.temp_allocator)
	testing.expectf(t, aerr == nil, "a no-break space between DS fields was refused: %v", aerr)

	// The A-label loads, and so does a name of raw octets written as `\DDD`,
	// which is the spelling a query with those octets is compared in.
	cfg, err := load_string(
		REWRITE + "xn--bcher-kva.lan\n    answer: 10.0.0.1\n  - domain: 'b\\195\\188cher.lan'\n    answer: 10.0.0.2\n",
		context.temp_allocator,
	)
	if testing.expectf(t, err == nil, "%v", err) {
		testing.expect_value(t, cfg.rewrites[0].domain, "xn--bcher-kva.lan.")
		testing.expect_value(t, cfg.rewrites[1].domain, "b\\195\\188cher.lan.")
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

	// Read as `block` it would load; it is a host name outside ASCII instead.
	refused_with(
		t,
		REWRITE + "\"bloc\u212a\"\n",
		"rewrites[0].answer: an answer host \"bloc\\u212a\" holds U+212A, which is outside ASCII; " + dns.IDN_HINT,
	)

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
