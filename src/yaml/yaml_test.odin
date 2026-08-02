package yaml

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
test_bad_mapping_line_reports_line_number :: proc(t: ^testing.T) {
	_, err := parse("a: 1\nb: 2\nthis is not a mapping\n", context.temp_allocator)
	e, has := err.?
	testing.expect(t, has, "expected an error")
	testing.expect_value(t, e.line, 3)
	free_all(context.temp_allocator)
}
