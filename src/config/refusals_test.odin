package config

import "core:fmt"
import "core:testing"
import "elodin:dns"

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
			fmt.tprintf("server.max_connections must be at least 1 (it is 0); %d is the default", DEFAULT_MAX_CONNECTIONS),
		},
		{
			MINIMAL + "listeners:\n  udp: {enabled: false}\n  tcp: {enabled: false}\n",
			"listeners: every listener is disabled, so nothing would be served",
		},
	}
	for c in cases {
		expect_refused(t, c.doc, c.wanted, exact = true, tls_files = false)
	}
	free_all(context.temp_allocator)
}

/*
A group whose `servers` is not a list, or whose every server is refused, is
reported once, for that: not a second time as a group with no servers. A file
that names none is still told it needs one.
*/
@(test)
test_a_refused_server_is_reported_once :: proc(t: ^testing.T) {
	ROUTE :: MINIMAL + "  zones:\n    - domains: [corp.example]\n      servers: "
	expect_refused(t, ROUTE + "10.0.0.1\n", "upstream.zones[0].servers: expected a list", prefix = true, exactly_one = true)
	expect_refused(t, ROUTE + "[\"tls://\"]\n", "upstream.zones[0].servers[0]: cannot parse", prefix = true, exactly_one = true)
	expect_refused(t, "upstream:\n  servers: 1.1.1.1\n", "upstream.servers: expected a list", prefix = true, exactly_one = true)
	expect_refused(
		t,
		"upstream:\n  servers: [\"tls://1.1.1.1:853\"]\n",
		"upstream.servers[0]: verify is on",
		prefix = true,
		exactly_one = true,
	)
	expect_refused(
		t,
		"upstream:\n  servers: [\"tls://1.1.1.1:853\", 9.9.9.9]\n",
		"upstream.servers[0]: verify is on",
		prefix = true,
		exactly_one = true,
	)
	expect_refused(t, "log:\n  level: info\n", "upstream.servers: at least one upstream server is required", exact = true, exactly_one = true)
	expect_refused(t, "upstream:\n  servers: []\n", "upstream.servers: at least one upstream server is required", exact = true, exactly_one = true)
	expect_refused(t, ROUTE + "[]\n", "upstream.zones: the route for corp.example. needs at least one server", exact = true, exactly_one = true)
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
		expect_refused(t, c.doc, c.key, "outside ASCII")
	}

	// The address is not one with the space on it.
	expect_refused(
		t,
		MINIMAL + REWRITE + "lan.example\n    answer: \"A 192.0.2.1\\_\"\n",
		"rewrites[0].answer: A needs an IPv4 address, got \"192.0.2.1\\u00a0\"",
		exact = true,
	)

	// Nor is a name with one inside it, which is two fields run together.
	expect_refused(
		t,
		MINIMAL + REWRITE + "lan.example\n    answer: \"TXT\\_hello\"\n",
		"rewrites[0].answer: an answer needs one host name, got \"TXT\\u00a0hello\"",
		exact = true,
	)

	// A domain of ASCII space alone is no domain, not the root.
	expect_refused(t, MINIMAL + REWRITE + "\"   \"\n    answer: 10.0.0.1\n", "rewrites[0]: missing domain", exact = true)

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
		// A joiner, geresh or gershayim follows a character past ASCII (RFC 5892
		// appendix A.1, A.2, A.5, A.6), so the first one past ASCII was pasted.
		{REWRITE + "\"nas.lan\u200d\"\n    answer: 10.0.0.1\n", "rewrites[0].domain: \"nas.lan\\u200d\" holds U+200D, which is outside ASCII; " + DELETE_HINT},
		{REWRITE + "\"\u200cnas.lan\"\n    answer: 10.0.0.1\n", "rewrites[0].domain: \"\\u200cnas.lan\" holds U+200C, which is outside ASCII; " + DELETE_HINT},
		{REWRITE + "\"a\u200db.lan\"\n    answer: 10.0.0.1\n", "rewrites[0].domain: \"a\\u200db.lan\" holds U+200D, which is outside ASCII; " + DELETE_HINT},
		{REWRITE + "\"a\u05f3b.lan\"\n    answer: 10.0.0.1\n", "rewrites[0].domain: \"a\\u05f3b.lan\" holds U+05F3, which is outside ASCII; " + DELETE_HINT},
		{MINIMAL + "ddr:\n  name: \"d\u00f6t.example\"\n", "ddr.name: \"d\u00f6t.example\" holds U+00F6, which is outside ASCII; " + dns.IDN_HINT},
		{
			MINIMAL + "dnssec:\n  trust_anchors: [\"" + ROOT_ANCHOR + "\", \"b\u00fccher.lan. IN DS 1 8 2 " + ROOT_DIGEST + "\"]\n",
			"dnssec.trust_anchors[1]: \"b\u00fccher.lan. IN DS 1 8 2 " + ROOT_DIGEST + "\" holds U+00FC, which is outside ASCII; " + dns.IDN_HINT,
		},
	}
	for c in cases {
		expect_refused(t, c.doc, c.wanted, exact = true)
	}

	// A space outside ASCII between an answer's fields is a field split, not a
	// character to delete: deleted, `CNAMEhost.example` would load.
	expect_refused(t, REWRITE + "lan.example\n    answer: \"CNAME\\_host.example\"\n", "rewrites[0].answer: an answer needs one host name, got \"CNAME\\u00a0host.example\"", exact = true)

	// A trust anchor's owner is the name checked; its fields split on any
	// space, as `dnssec.parse_trust_anchor` reads them, so a no-break space
	// between two is a separator.
	_, aerr := load_string(MINIMAL + "dnssec:\n  trust_anchors: [\". IN DS 20326\\_8 2 " + ROOT_DIGEST + "\"]\n", context.temp_allocator)
	testing.expectf(t, aerr == nil, "a no-break space between DS fields was refused: %v", aerr)
	// The bare form has no owner: its first field is the key tag, and a digit
	// past ASCII there is no DS record, not a name.
	expect_refused(
		t,
		MINIMAL + "dnssec:\n  trust_anchors: [\"\uff12\uff10326 8 2 " + ROOT_DIGEST + "\"]\n",
		"dnssec.trust_anchors[0]: \"\\uff12\\uff10326 8 2 " + ROOT_DIGEST + "\" is not a DS record",
		exact = true,
	)

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
	expect_refused(t, REWRITE + "\"\u017frv 0 5 5060 sip.example\"\n", "rewrites[0].answer: \"\\u017frv 0 5 5060 sip.example\" is not an answer this understands", prefix = true)

	// Read as `block` it would load; it is a host name outside ASCII instead.
	expect_refused(
		t,
		REWRITE + "\"bloc\u212a\"\n",
		"rewrites[0].answer: an answer host \"bloc\\u212a\" holds U+212A, which is outside ASCII; " + dns.IDN_HINT,
		exact = true,
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
	expect_refused(t, MINIMAL + "server:\n  allow_from: [\"10.0.0.0/8\\_\"]\n", "server.allow_from[0]: \"10.0.0.0/8\\u00a0\" is not a network in CIDR form", prefix = true)
	_, err := load_string(MINIMAL + "server:\n  allow_from: [\" 10.0.0.0/8 \"]\n", context.temp_allocator)
	testing.expectf(t, err == nil, "ASCII space around an entry was not trimmed: %v", err)
	free_all(context.temp_allocator)
}
