package yaml

import "core:fmt"
import "core:testing"
import "core:time"

@(private = "file")
DOC :: `
# elodin sample
log:
  level: debug
  queries: true

listeners:
  udp:
    enabled: true
    address: "0.0.0.0"
    port: 53
  doh:
    enabled: false
    path: /dns-query

upstream:
  strategy: round_robin
  timeout: 2500ms
  servers:
    - name: cloudflare
      type: tls
      address: 1.1.1.1
      port: 853
      hostname: cloudflare-dns.com
    - name: google
      type: https
      url: https://dns.google/dns-query   # inline comment
      bootstrap: [8.8.8.8, 8.8.4.4]
    - name: router
      type: udp
      address: 192.168.1.1

blocking:
  response: nxdomain
  custom_ipv6: "::"
  refresh: 24h
  rules:
    - "||doubleclick.net^"
    - ads.example.com
  flow: {a: 1, b: two}
  banner: |
    line one
    line two
`

@(test)
test_parse_nested_mapping :: proc(t: ^testing.T) {
	root, err := parse(DOC, context.temp_allocator)
	testing.expectf(t, err == nil, "parse failed: %v", err)

	lvl, ok := as_string(at(root, "log.level"))
	testing.expect(t, ok, "log.level missing")
	testing.expect_value(t, lvl, "debug")

	q, qok := as_bool(at(root, "log.queries"))
	testing.expect(t, qok, "log.queries missing")
	testing.expect(t, q, "log.queries should be true")

	port, pok := as_int(at(root, "listeners.udp.port"))
	testing.expect(t, pok, "port missing")
	testing.expect_value(t, port, i64(53))

	addr, aok := as_string(at(root, "listeners.udp.address"))
	testing.expect(t, aok, "address missing")
	testing.expect_value(t, addr, "0.0.0.0")

	path, pathok := as_string(at(root, "listeners.doh.path"))
	testing.expect(t, pathok, "path missing")
	testing.expect_value(t, path, "/dns-query")
	free_all(context.temp_allocator)
}

@(test)
test_parse_sequence_of_maps :: proc(t: ^testing.T) {
	root, err := parse(DOC, context.temp_allocator)
	testing.expectf(t, err == nil, "parse failed: %v", err)

	servers := items(at(root, "upstream.servers"))
	testing.expect_value(t, len(servers), 3)

	n0, _ := as_string(get(servers[0], "name"))
	testing.expect_value(t, n0, "cloudflare")
	p0, _ := as_int(get(servers[0], "port"))
	testing.expect_value(t, p0, i64(853))
	h0, _ := as_string(get(servers[0], "hostname"))
	testing.expect_value(t, h0, "cloudflare-dns.com")

	// A URL's "://" must not be mistaken for a key separator, and the trailing
	// inline comment must be stripped.
	u1, _ := as_string(get(servers[1], "url"))
	testing.expect_value(t, u1, "https://dns.google/dns-query")

	boot, bok := as_string_list(get(servers[1], "bootstrap"), context.temp_allocator)
	testing.expect(t, bok, "bootstrap list missing")
	testing.expect_value(t, len(boot), 2)
	testing.expect_value(t, boot[1], "8.8.4.4")

	n2, _ := as_string(get(servers[2], "name"))
	testing.expect_value(t, n2, "router")
	free_all(context.temp_allocator)
}

@(test)
test_scalars_and_flow :: proc(t: ^testing.T) {
	root, err := parse(DOC, context.temp_allocator)
	testing.expectf(t, err == nil, "parse failed: %v", err)

	// A quoted "::" must survive; unquoted it would look like a key separator.
	v6, ok := as_string(at(root, "blocking.custom_ipv6"))
	testing.expect(t, ok, "custom_ipv6 missing")
	testing.expect_value(t, v6, "::")

	d, dok := as_duration(at(root, "blocking.refresh"))
	testing.expect(t, dok, "refresh missing")
	testing.expect_value(t, d, 24 * time.Hour)

	td, tdok := as_duration(at(root, "upstream.timeout"))
	testing.expect(t, tdok, "timeout missing")
	testing.expect_value(t, td, 2500 * time.Millisecond)

	rules, rok := as_string_list(at(root, "blocking.rules"), context.temp_allocator)
	testing.expect(t, rok, "rules missing")
	testing.expect_value(t, len(rules), 2)
	testing.expect_value(t, rules[0], "||doubleclick.net^")
	testing.expect_value(t, rules[1], "ads.example.com")

	fa, faok := as_int(at(root, "blocking.flow.a"))
	testing.expect(t, faok, "flow.a missing")
	testing.expect_value(t, fa, i64(1))
	fb, _ := as_string(at(root, "blocking.flow.b"))
	testing.expect_value(t, fb, "two")

	banner, bok := as_string(at(root, "blocking.banner"))
	testing.expect(t, bok, "banner missing")
	testing.expect_value(t, banner, "line one\nline two\n")
	free_all(context.temp_allocator)
}

@(test)
test_duration_forms :: proc(t: ^testing.T) {
	root, err := parse("a: 30\nb: 1h30m\nc: 250ms\nd: 7d\n", context.temp_allocator)
	testing.expectf(t, err == nil, "parse failed: %v", err)

	a, _ := as_duration(get(root, "a"))
	testing.expect_value(t, a, 30 * time.Second)
	b, _ := as_duration(get(root, "b"))
	testing.expect_value(t, b, 90 * time.Minute)
	c, _ := as_duration(get(root, "c"))
	testing.expect_value(t, c, 250 * time.Millisecond)
	d, _ := as_duration(get(root, "d"))
	testing.expect_value(t, d, 7 * 24 * time.Hour)
	free_all(context.temp_allocator)
}

@(test)
test_byte_size_forms :: proc(t: ^testing.T) {
	Case :: struct {
		text:  string,
		value: i64,
		ok:    bool,
	}

	CASES := []Case {
		{"1024", 1024, true},
		{"64MiB", 64 * 1024 * 1024, true},
		{"64 MiB", 64 * 1024 * 1024, true},
		{"512KiB", 512 * 1024, true},
		{"512KB", 512_000, true},
		{"2GiB", 2 * 1024 * 1024 * 1024, true},
		{"1B", 1, true},
		{"0", 0, true},
		// A size is one number and one unit. Everything else is a typo, and a
		// typo that parses is a bound nobody chose.
		{"1MiB512KiB", 0, false},
		{"64 MiBs", 0, false},
		{"MiB", 0, false},
		{"-1", 0, false},
		{"64.5MiB", 0, false},
		{"0x40", 0, false},
		{"", 0, false},
		// Would wrap to something small and plausible if it were let through.
		{"9223372036854775808", 0, false},
		{"16777216TiB", 0, false},
		{"99999999999GiB", 0, false},
	}

	for c in CASES {
		root, err := parse(fmt.tprintf("size: %q\n", c.text), context.temp_allocator)
		testing.expectf(t, err == nil, "parse failed for %q: %v", c.text, err)
		v, ok := as_bytes(get(root, "size"))
		testing.expectf(t, ok == c.ok, "%q: parsed=%v, expected %v", c.text, ok, c.ok)
		if c.ok {
			testing.expectf(t, v == c.value, "%q came to %d, expected %d", c.text, v, c.value)
		}
		free_all(context.temp_allocator)
	}
}

@(test)
test_top_level_sequence_under_key :: proc(t: ^testing.T) {
	// Sequence entries aligned with their parent key, which YAML allows.
	src := `
rewrites:
- domain: nas.home
  answer: 192.168.1.50
- domain: printer.home
  answer: 192.168.1.51
`
	root, err := parse(src, context.temp_allocator)
	testing.expectf(t, err == nil, "parse failed: %v", err)

	rw := items(get(root, "rewrites"))
	testing.expect_value(t, len(rw), 2)
	d0, _ := as_string(get(rw[0], "domain"))
	testing.expect_value(t, d0, "nas.home")
	a1, _ := as_string(get(rw[1], "answer"))
	testing.expect_value(t, a1, "192.168.1.51")
	free_all(context.temp_allocator)
}

@(test)
test_escapes_and_quotes :: proc(t: ^testing.T) {
	src := "a: \"tab\\there\"\nb: 'it''s fine'\nc: \"hash # not comment\"\nd: plain # comment\n"
	root, err := parse(src, context.temp_allocator)
	testing.expectf(t, err == nil, "parse failed: %v", err)

	a, _ := as_string(get(root, "a"))
	testing.expect_value(t, a, "tab\there")
	b, _ := as_string(get(root, "b"))
	testing.expect_value(t, b, "it's fine")
	c, _ := as_string(get(root, "c"))
	testing.expect_value(t, c, "hash # not comment")
	d, _ := as_string(get(root, "d"))
	testing.expect_value(t, d, "plain")
	free_all(context.temp_allocator)
}

@(test)
test_null_and_missing :: proc(t: ^testing.T) {
	root, err := parse("a:\nb: null\nc: ~\nd: \"null\"\n", context.temp_allocator)
	testing.expectf(t, err == nil, "parse failed: %v", err)

	testing.expect(t, is_null(get(root, "a")), "empty value should be null")
	testing.expect(t, is_null(get(root, "b")), "null should be null")
	testing.expect(t, is_null(get(root, "c")), "~ should be null")
	testing.expect(t, !is_null(get(root, "d")), "quoted null is a string")
	testing.expect(t, is_null(get(root, "missing")), "missing key should be null")
	free_all(context.temp_allocator)
}

@(test)
test_tab_indentation_rejected :: proc(t: ^testing.T) {
	_, err := parse("a:\n\tb: 1\n", context.temp_allocator)
	testing.expect(t, err != nil, "tab indentation should be rejected")
	free_all(context.temp_allocator)
}

@(test)
test_mismatched_flow_close_rejected :: proc(t: ^testing.T) {
	// A flow collection closed by the wrong bracket left the item scanner
	// parked on the stray closer: it consumed nothing, so every turn of the
	// loop appended one more empty scalar and the parser ate memory until the
	// process died.
	cases := []string{"a: [x}", "a: [1, 2}", "a: [}", "a: {k: [v}}", "a: [[1]}"}
	for src in cases {
		_, err := parse(src, context.temp_allocator)
		testing.expectf(t, err != nil, "%q should be rejected", src)
		free_all(context.temp_allocator)
	}
}

@(test)
test_escaped_quote_does_not_close_scalar :: proc(t: ^testing.T) {
	// `\"` closed double-quote mode one byte early, so everything after it was
	// read as if unquoted: a `#` became a comment and a `: ` a key separator.
	root, err := parse("key: \"val\\\" # not comment\"\n", context.temp_allocator)
	testing.expectf(t, err == nil, "parse failed: %v", err)
	v, ok := as_string(get(root, "key"))
	testing.expect(t, ok, "key missing")
	testing.expect_value(t, v, "val\" # not comment")
	free_all(context.temp_allocator)
}

@(test)
test_escaped_quote_in_quoted_key :: proc(t: ^testing.T) {
	root, err := parse("\"a\\\": b\": 1\n", context.temp_allocator)
	testing.expectf(t, err == nil, "parse failed: %v", err)
	v, ok := as_int(get(root, "a\": b"))
	testing.expect(t, ok, "key missing")
	testing.expect_value(t, v, i64(1))
	free_all(context.temp_allocator)
}

@(test)
test_escaped_quote_in_sequence_entry :: proc(t: ^testing.T) {
	// The `: ` inside the quoted entry made it look like `- key: value`, and the
	// entry was parsed as a mapping instead of a scalar.
	root, err := parse("list:\n  - \"a\\\": b\"\n", context.temp_allocator)
	testing.expectf(t, err == nil, "parse failed: %v", err)
	l := items(get(root, "list"))
	if !testing.expect_value(t, len(l), 1) {
		free_all(context.temp_allocator)
		return
	}
	v, ok := as_string(l[0])
	testing.expect(t, ok, "entry is not a scalar")
	testing.expect_value(t, v, "a\": b")
	free_all(context.temp_allocator)
}

@(test)
test_escaped_quote_in_flow_collection :: proc(t: ^testing.T) {
	root, err := parse("a: [\"x\\\" # y\", plain]\n", context.temp_allocator)
	testing.expectf(t, err == nil, "parse failed: %v", err)
	l, ok := as_string_list(get(root, "a"), context.temp_allocator)
	testing.expect(t, ok, "flow list missing")
	if !testing.expect_value(t, len(l), 2) {
		free_all(context.temp_allocator)
		return
	}
	testing.expect_value(t, l[0], "x\" # y")
	testing.expect_value(t, l[1], "plain")
	free_all(context.temp_allocator)
}

@(test)
test_escaped_backslash_still_closes_scalar :: proc(t: ^testing.T) {
	// The escape skip covers exactly one byte, so a trailing `\\` has to leave
	// the quote after it free to close the scalar. Three scanners track quotes
	// independently - comment stripping, key splitting and flow items - and each
	// one is pinned here, because a skip one byte too wide reads as correct
	// until a value ends in a backslash.
	root, err := parse("a: \"ends \\\\\" # comment\nb: 2\n", context.temp_allocator)
	testing.expectf(t, err == nil, "parse failed: %v", err)
	v, ok := as_string(get(root, "a"))
	testing.expect(t, ok, "a missing")
	testing.expect_value(t, v, "ends \\")
	n, nok := as_int(get(root, "b"))
	testing.expect(t, nok, "b missing")
	testing.expect_value(t, n, i64(2))

	kroot, kerr := parse("\"a\\\\\": 1\n", context.temp_allocator)
	testing.expectf(t, kerr == nil, "parse failed: %v", kerr)
	kv, kok := as_int(get(kroot, "a\\"))
	testing.expect(t, kok, "key missing")
	testing.expect_value(t, kv, i64(1))

	froot, ferr := parse("a: [\"x\\\\\", plain]\n", context.temp_allocator)
	testing.expectf(t, ferr == nil, "parse failed: %v", ferr)
	l, lok := as_string_list(get(froot, "a"), context.temp_allocator)
	testing.expect(t, lok, "flow list missing")
	if !testing.expect_value(t, len(l), 2) {
		free_all(context.temp_allocator)
		return
	}
	testing.expect_value(t, l[0], "x\\")
	testing.expect_value(t, l[1], "plain")
	free_all(context.temp_allocator)
}

@(test)
test_block_scalar_keeps_comment_characters :: proc(t: ^testing.T) {
	// Inside a block scalar a `#` is content, not a comment. The line scanner
	// ran comment handling over every line before block scalars were assembled,
	// so a whole-line comment vanished and an inline one truncated the line.
	root, err := parse("a: |\n  # not a comment\nb: |\n  text # not a comment\n", context.temp_allocator)
	testing.expectf(t, err == nil, "parse failed: %v", err)
	a, aok := as_string(get(root, "a"))
	testing.expect(t, aok, "a missing")
	testing.expect_value(t, a, "# not a comment\n")
	b, bok := as_string(get(root, "b"))
	testing.expect(t, bok, "b missing")
	testing.expect_value(t, b, "text # not a comment\n")
	free_all(context.temp_allocator)
}

@(test)
test_block_scalar_keeps_blank_lines :: proc(t: ^testing.T) {
	// Blank lines inside a block scalar are content too: they were dropped with
	// the document's own blank lines, silently closing up the paragraphs.
	root, err := parse("a: |\n  one\n\n  two\n", context.temp_allocator)
	testing.expectf(t, err == nil, "parse failed: %v", err)
	a, ok := as_string(get(root, "a"))
	testing.expect(t, ok, "a missing")
	testing.expect_value(t, a, "one\n\ntwo\n")
	free_all(context.temp_allocator)
}

@(test)
test_block_scalar_keeps_document_markers :: proc(t: ^testing.T) {
	root, err := parse("a: |\n  ---\n  x\n  ...\n", context.temp_allocator)
	testing.expectf(t, err == nil, "parse failed: %v", err)
	a, ok := as_string(get(root, "a"))
	testing.expect(t, ok, "a missing")
	testing.expect_value(t, a, "---\nx\n...\n")
	free_all(context.temp_allocator)
}

@(test)
test_block_scalar_ends_at_dedent :: proc(t: ^testing.T) {
	// Taking the body verbatim must stop at the block's indentation. Past it a
	// comment is a comment again and a blank line is just a separator, or the
	// rest of the document would be swallowed into the scalar.
	src := `
a: |
  x # kept

# dropped
b: 2
`
	root, err := parse(src, context.temp_allocator)
	testing.expectf(t, err == nil, "parse failed: %v", err)
	a, aok := as_string(get(root, "a"))
	testing.expect(t, aok, "a missing")
	testing.expect_value(t, a, "x # kept\n")
	b, bok := as_int(get(root, "b"))
	testing.expect(t, bok, "b missing")
	testing.expect_value(t, b, i64(2))
	free_all(context.temp_allocator)
}

@(test)
test_block_scalar_ends_below_its_own_indent :: proc(t: ^testing.T) {
	// The key's indentation only bounds the first body line. After that the
	// block's own indentation is the boundary, so a line that clears the key
	// but falls short of the block is outside it and a comment again.
	root, err := parse("a: |\n    x\n  # c\nb: 2\n", context.temp_allocator)
	testing.expectf(t, err == nil, "parse failed: %v", err)
	a, aok := as_string(get(root, "a"))
	testing.expect(t, aok, "a missing")
	testing.expect_value(t, a, "x\n")
	n, nok := as_int(get(root, "b"))
	testing.expect(t, nok, "b missing")
	testing.expect_value(t, n, i64(2))

	froot, ferr := parse("a: >\n    deep\n  # c\nb: 2\n", context.temp_allocator)
	testing.expectf(t, ferr == nil, "parse failed: %v", ferr)
	f, fok := as_string(get(froot, "a"))
	testing.expect(t, fok, "folded a missing")
	testing.expect_value(t, f, "deep")
	free_all(context.temp_allocator)
}

@(test)
test_folded_scalar_blank_line_is_a_break :: proc(t: ^testing.T) {
	// Folding joins lines with a space, but a blank line between them is a
	// paragraph break. Blank lines only reach the folder now that the scanner
	// keeps them, and folding them as spaces would double the separator.
	root, err := parse("a: >\n  one\n  two\n\n  three\n", context.temp_allocator)
	testing.expectf(t, err == nil, "parse failed: %v", err)
	a, ok := as_string(get(root, "a"))
	testing.expect(t, ok, "a missing")
	testing.expect_value(t, a, "one two\nthree")
	free_all(context.temp_allocator)
}

@(test)
test_block_scalar_under_escaped_quote_key :: proc(t: ^testing.T) {
	// Deciding whether a line opens a block scalar runs the key through
	// find_key_colon, so a key holding an escaped quote exercises both that
	// and the verbatim body at once.
	root, err := parse("\"a\\\": b\": |\n  # content\n  x # tail\nc: 2\n", context.temp_allocator)
	testing.expectf(t, err == nil, "parse failed: %v", err)
	v, ok := as_string(get(root, "a\": b"))
	testing.expect(t, ok, "key missing")
	testing.expect_value(t, v, "# content\nx # tail\n")
	c, cok := as_int(get(root, "c"))
	testing.expect(t, cok, "c missing")
	testing.expect_value(t, c, i64(2))
	free_all(context.temp_allocator)
}

@(test)
test_block_scalar_body_allows_tabs :: proc(t: ^testing.T) {
	// Indentation is spaces, but past it a tab is content like any other byte.
	// A tab straight after the indentation is the case that moved: the
	// document-wide tab check used to reject it before the body was content.
	root, err := parse("a: |\n  \ty\nb: 2\n", context.temp_allocator)
	testing.expectf(t, err == nil, "parse failed: %v", err)
	a, ok := as_string(get(root, "a"))
	testing.expect(t, ok, "a missing")
	testing.expect_value(t, a, "\ty\n")

	mid, merr := parse("a: |\n  x\ty\n", context.temp_allocator)
	testing.expectf(t, merr == nil, "parse failed: %v", merr)
	m, mok := as_string(get(mid, "a"))
	testing.expect(t, mok, "a missing")
	testing.expect_value(t, m, "x\ty\n")
	free_all(context.temp_allocator)
}

@(test)
test_block_scalar_blank_line_of_any_whitespace :: proc(t: ^testing.T) {
	// A line holding only a tab is blank, not a boundary. Reading it as one
	// ended the block early and handed the lines after it back to the comment
	// stripper, so a `#` further down the body went missing again.
	root, err := parse("a: |\n  x\n\t\n  y # tail\nb: 2\n", context.temp_allocator)
	testing.expectf(t, err == nil, "parse failed: %v", err)
	a, ok := as_string(get(root, "a"))
	testing.expect(t, ok, "a missing")
	testing.expect_value(t, a, "x\n\ny # tail\n")
	n, nok := as_int(get(root, "b"))
	testing.expect(t, nok, "b missing")
	testing.expect_value(t, n, i64(2))
	free_all(context.temp_allocator)
}

@(test)
test_block_scalar_keeps_interior_trailing_spaces :: proc(t: ^testing.T) {
	// Trailing spaces on a body line are content. Only the last line loses
	// them, to chomping, which trims spaces along with the newlines.
	root, err := parse("a: |\n  one  \n  two\n", context.temp_allocator)
	testing.expectf(t, err == nil, "parse failed: %v", err)
	a, ok := as_string(get(root, "a"))
	testing.expect(t, ok, "a missing")
	testing.expect_value(t, a, "one  \ntwo\n")
	free_all(context.temp_allocator)
}

@(test)
test_folded_scalar_keeps_a_leading_blank :: proc(t: ^testing.T) {
	// A folded block that opens on a blank line keeps it, as the literal form
	// does. Only the space joining two lines needs a line before it.
	root, err := parse("a: >-\n\n  one\n  two\n", context.temp_allocator)
	testing.expectf(t, err == nil, "parse failed: %v", err)
	a, ok := as_string(get(root, "a"))
	testing.expect(t, ok, "a missing")
	testing.expect_value(t, a, "\none two")

	lit, lerr := parse("a: |\n\n  one\n", context.temp_allocator)
	testing.expectf(t, lerr == nil, "parse failed: %v", lerr)
	l, lok := as_string(get(lit, "a"))
	testing.expect(t, lok, "literal a missing")
	testing.expect_value(t, l, "\none\n")
	free_all(context.temp_allocator)
}

@(test)
test_block_scalar_line_endings_and_eof :: proc(t: ^testing.T) {
	// The body is trimmed of `\r` only, where the rest of the document also
	// loses trailing spaces and tabs, so CRLF input needs pinning separately.
	crlf, cerr := parse("a: |\r\n  x # k\r\nb: 2\r\n", context.temp_allocator)
	testing.expectf(t, cerr == nil, "parse failed: %v", cerr)
	c, cok := as_string(get(crlf, "a"))
	testing.expect(t, cok, "a missing")
	testing.expect_value(t, c, "x # k\n")
	n, nok := as_int(get(crlf, "b"))
	testing.expect(t, nok, "b missing")
	testing.expect_value(t, n, i64(2))

	// A body that runs to the end of input without a closing newline.
	eof, eerr := parse("a: |\n  x # k", context.temp_allocator)
	testing.expectf(t, eerr == nil, "parse failed: %v", eerr)
	e, eok := as_string(get(eof, "a"))
	testing.expect(t, eok, "a missing at EOF")
	testing.expect_value(t, e, "x # k\n")
	free_all(context.temp_allocator)
}

@(test)
test_block_scalar_under_sequence_entry :: proc(t: ^testing.T) {
	// The block's parent is the entry's content column, not the dash's own, so
	// a key aligned with `banner` has to close the scalar rather than join it.
	src := `
list:
  - name: one
    banner: |
      # inside
    other: two
`
	root, err := parse(src, context.temp_allocator)
	testing.expectf(t, err == nil, "parse failed: %v", err)
	l := items(get(root, "list"))
	if !testing.expect_value(t, len(l), 1) {
		free_all(context.temp_allocator)
		return
	}
	banner, bok := as_string(get(l[0], "banner"))
	testing.expect(t, bok, "banner missing")
	testing.expect_value(t, banner, "# inside\n")
	other, ook := as_string(get(l[0], "other"))
	testing.expect(t, ook, "other missing")
	testing.expect_value(t, other, "two")
	free_all(context.temp_allocator)
}

@(test)
test_bad_mapping_line_reports_line_number :: proc(t: ^testing.T) {
	_, err := parse("a: 1\nb: 2\nthis is not a mapping\n", context.temp_allocator)
	e, has := err.?
	testing.expect(t, has, "expected an error")
	testing.expect_value(t, e.line, 3)
	free_all(context.temp_allocator)
}
