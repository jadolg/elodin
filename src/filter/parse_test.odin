package filter

import "core:strings"
import "core:testing"

/*
The list parsers, one syntax at a time.

`filter_test.odin` drives the engine end to end and covers adblock syntax
thoroughly. What is left, and what this file is for, is the hosts and
bare-domain paths and the pieces underneath all three - comment stripping,
format sniffing, name normalisation, the parent walk a subdomain rule is matched
by.

Getting these wrong is quiet in both directions, which is what makes them worth
pinning. A rule dropped by a parser that did not recognise its line means the
list silently stops blocking what its author meant to block, and nobody notices
until they look at a packet capture. A rule read too broadly - an apex entry
treated as covering subdomains, a housekeeping line from a hosts file taken as a
name to sink - takes working names off the air for everyone behind this server,
and `localhost` is on the second list.
*/

@(private = "file")
parsed :: proc(text: string, format: Format) -> (^Set, ^Set) {
	block, allow := set_make(), set_make()
	parse_list(block, allow, text, format)
	return block, allow
}

@(private = "file")
matches :: proc(text: string, format: Format, name: string) -> Decision {
	block, allow := parsed(text, format)
	e := engine_make()
	defer engine_destroy(e)
	engine_swap(e, block, allow)
	return engine_match(e, name, .A)
}

@(test)
test_hosts_housekeeping_names_are_never_sunk :: proc(t: ^testing.T) {
	/*
	Every hosts file on the internet begins by mapping `localhost` and its
	relatives, and a blocklist distributed in that format carries the same
	prologue. Sinking those would point this machine's own loopback names at the
	blocked answer - which breaks far more than it blocks, and does it on the
	machine running the server.
	*/
	src := `
127.0.0.1 localhost
127.0.0.1 localhost.localdomain
127.0.0.1 local
255.255.255.255 broadcasthost
::1 ip6-localhost
::1 ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts
0.0.0.0 0.0.0.0
0.0.0.0 ads.example
`
	block, allow := parsed(src, .Hosts)
	defer set_destroy(block)
	defer set_destroy(allow)
	testing.expectf(t, block.count == 1, "only the one real rule should be kept, got %d", block.count)
	testing.expect(t, set_lookup(block, "ads.example", .A), "the real rule should be there")
	for name in LOCALHOST_NAMES {
		testing.expectf(t, !set_lookup(block, name, .A), "%q must not be sunk", name)
	}

	// And the check does not care about case, because hosts files do not.
	upper, upper_allow := parsed("0.0.0.0 LocalHost\n0.0.0.0 IP6-AllNodes\n", .Hosts)
	defer set_destroy(upper)
	defer set_destroy(upper_allow)
	testing.expect_value(t, upper.count, 0)
}

@(test)
test_a_hosts_line_sinks_every_name_after_the_address :: proc(t: ^testing.T) {
	// One address, several names, which is how hosts files pack aliases.
	block, allow := parsed("0.0.0.0 a.example b.example\tc.example\n", .Hosts)
	defer set_destroy(block)
	defer set_destroy(allow)
	testing.expect_value(t, block.count, 3)
	for name in ([]string{"a.example", "b.example", "c.example"}) {
		testing.expectf(t, set_lookup(block, name, .A), "%q should be blocked", name)
	}
}

@(test)
test_a_hosts_line_with_no_address_adds_nothing :: proc(t: ^testing.T) {
	/*
	A hosts line is an address followed by names. A line holding only a name has
	no address, so there is nothing to say where the first field ends and the
	names begin - and reading the whole line as a name would sink whatever the
	author actually wrote there.
	*/
	block, allow := parsed("ads.example\n\n   \n", .Hosts)
	defer set_destroy(block)
	defer set_destroy(allow)
	testing.expect_value(t, block.count, 0)
}

@(test)
test_hosts_rules_cover_the_name_and_not_what_is_under_it :: proc(t: ^testing.T) {
	/*
	A hosts entry names one host. Pi-hole and AdGuard both treat it that way,
	and widening it to the subtree would block names the list never mentioned -
	a hosts entry for `example.com` taking out every customer subdomain under it.
	*/
	src := "0.0.0.0 ads.example\n"
	testing.expect_value(t, matches(src, .Hosts, "ads.example."), Decision.Blocked)
	testing.expect_value(t, matches(src, .Hosts, "sub.ads.example."), Decision.None)
}

@(test)
test_comments_are_stripped_from_the_end_of_a_line :: proc(t: ^testing.T) {
	// Both markers, mid-line and at the start, in each of the two formats that
	// strip them.
	testing.expect_value(t, strip_line_comment("ads.example # why"), "ads.example ")
	testing.expect_value(t, strip_line_comment("ads.example ! why"), "ads.example ")
	testing.expect_value(t, strip_line_comment("# all of it"), "")
	testing.expect_value(t, strip_line_comment("no comment here"), "no comment here")

	testing.expect_value(t, matches("0.0.0.0 ads.example # tracker\n", .Hosts, "ads.example."), Decision.Blocked)
	testing.expect_value(t, matches("ads.example # tracker\n", .Domains, "ads.example."), Decision.Blocked)
}

@(test)
test_first_field_is_ip_needs_a_field_and_an_address :: proc(t: ^testing.T) {
	/*
	The heuristic that tells a hosts file from a bare domain list. A domain list
	is one name per line with no second field, so requiring the space is what
	keeps `1.2.3.4` on a line of its own - a perfectly good name to block - from
	turning the whole list into a hosts file.
	*/
	testing.expect(t, first_field_is_ip("0.0.0.0 ads.example"), "an address and a name is a hosts line")
	testing.expect(t, first_field_is_ip("127.0.0.1\tads.example"), "a tab separates fields too")
	testing.expect(t, first_field_is_ip("::1 ads.example"), "so does an IPv6 address")
	testing.expect(t, !first_field_is_ip("0.0.0.0"), "an address with no name is not a hosts line")
	testing.expect(t, !first_field_is_ip("ads.example"), "and neither is a bare name")
	testing.expect(t, !first_field_is_ip("1.2.3 ads.example"), "three octets is not an address")
	testing.expect(t, !first_field_is_ip("a.b.c.d ads.example"), "nor is a name shaped like one")
	// A colon does not make a word an IPv6 address, nor digits and dots an IPv4 one.
	testing.expect(t, !first_field_is_ip("Error: rate limited"), "a word with a colon is not an address")
	testing.expect(t, !first_field_is_ip("10.20.30 ads.example"), "a short IPv4 form is not a hosts address")
	testing.expect(t, !first_field_is_ip("1.2.3.4:80 ads.example"), "nor is an address with a port")
	testing.expect(t, !first_field_is_ip("[::1]:53 ads.example"), "in either family")
	testing.expect(t, !first_field_is_ip("x::1]:53 ads.example"), "nor with a bracket further in")
	testing.expect(t, !first_field_is_ip("999.1.1.1 ads.example"), "an octet past 255 is not an address")
	testing.expect(t, first_field_is_ip("::ffff:192.0.2.1 ads.example"), "a mapped address is one")
	testing.expect(t, !first_field_is_ip("]: ads.example"), "nor is a stray bracket")
}

/*
`core:net`'s `split_port` slices from after a `[` it does not check for before
dev-2026-10, so a list line beginning `]:` panics there. This is the fuzzer's
input: whatever a list host serves reaches the address parser.
*/
@(test)
test_a_list_line_beginning_with_a_bracket_does_not_panic :: proc(t: ^testing.T) {
	text := "\x00f\n]:\t\xeb@\xf1/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb{99\\[/\np\n1}/"
	for format in Format {
		block, allow := parsed(text, format)
		set_destroy(block)
		set_destroy(allow)
	}
}

@(test)
test_a_hosts_line_needs_an_address_first :: proc(t: ^testing.T) {
	// An error page served as a hosts list sank every word after the first
	// (#317), and passed for a list that held rules.
	block, allow := parsed("429 Too Many Requests\nError: service unavailable\n0.0.0.0 ads.example\n", .Hosts)
	defer set_destroy(block)
	defer set_destroy(allow)
	testing.expect_value(t, block.count, 1)
	testing.expect(t, set_lookup(block, "ads.example", .A))
	testing.expect(t, !set_lookup(block, "requests", .A), "a word of an error page was sunk")
}

@(test)
test_format_detection_reads_past_a_comment_prologue :: proc(t: ^testing.T) {
	/*
	Published lists open with a licence header running to dozens of lines. The
	sniffer has to get past that to the first line that says anything, and it
	has a budget of 50 *meaningful* lines rather than 50 lines, or a long enough
	header would have every list read as a bare domain list.
	*/
	header := strings.repeat("# generated by something, do not edit\n", 60, context.temp_allocator)
	testing.expect_value(t, detect_format(strings.concatenate({header, "0.0.0.0 a.example\n0.0.0.0 b.example\n"}, context.temp_allocator)), Format.Hosts)
	testing.expect_value(t, detect_format(strings.concatenate({header, "a.example\nb.example\n"}, context.temp_allocator)), Format.Domains)

	// dnsmasq syntax is adblock as far as the parser is concerned.
	testing.expect_value(t, detect_format("address=/ads.example/0.0.0.0\n"), Format.Adblock)
	testing.expect_value(t, detect_format("server=/ads.example/\n"), Format.Adblock)
	// An allow rule at the top, before any block rule.
	testing.expect_value(t, detect_format("@@||good.example^\n"), Format.Adblock)
	// A file with nothing in it at all.
	testing.expect_value(t, detect_format(""), Format.Domains)
	testing.expect_value(t, detect_format("\n\n# only comments\n"), Format.Domains)
	free_all(context.temp_allocator)
}

@(test)
test_format_detection_reads_no_rule_inside_a_comment :: proc(t: ^testing.T) {
	/*
	A hosts or domain list's `#` comment is prose, and may mention adblock
	syntax. Read as a probe, a `||` there would have a hosts list parsed as
	adblock, where none of its lines is a rule, so the list blocks nothing (#322).
	*/
	commented := "# note: adblock ||domain^ syntax is not used here\n0.0.0.0 ads.example\n0.0.0.0 track.example\n"
	testing.expect_value(t, detect_format(commented), Format.Hosts)
	testing.expect_value(t, matches(commented, .Auto, "ads.example."), Decision.Blocked)

	trailing := "0.0.0.0 ads.example # not ||ads.example^\n0.0.0.0 track.example\n"
	testing.expect_value(t, detect_format(trailing), Format.Hosts)
	testing.expect_value(t, matches(trailing, .Auto, "track.example."), Decision.Blocked)

	domains := "ads.example # was ||ads.example^\ntrack.example\n"
	testing.expect_value(t, detect_format(domains), Format.Domains)
	testing.expect_value(t, matches(domains, .Auto, "track.example."), Decision.Blocked)

	// A `!` opens a trailing comment in both parsers too (`strip_line_comment`).
	bang := "0.0.0.0 ads.example ! not ||ads.example^\n0.0.0.0 track.example\n"
	testing.expect_value(t, detect_format(bang), Format.Hosts)
	testing.expect_value(t, matches(bang, .Auto, "track.example."), Decision.Blocked)

	// A rule is still a rule when a `#` follows it.
	testing.expect_value(t, detect_format("||ads.example^$csp=a#b\n"), Format.Adblock)
}

@(test)
test_format_detection_takes_the_majority_of_the_lines_it_reads :: proc(t: ^testing.T) {
	/*
	Real hosts lists carry the odd bare name, and real domain lists carry the
	odd line that looks like an address. The sniff is a majority rather than a
	first sighting, so one stray line does not change how the rest is read.
	*/
	mostly_hosts := "0.0.0.0 a.example\n0.0.0.0 b.example\n0.0.0.0 c.example\nstray.example\n"
	testing.expect_value(t, detect_format(mostly_hosts), Format.Hosts)

	mostly_domains := "a.example\nb.example\nc.example\n0.0.0.0 stray.example\n"
	testing.expect_value(t, detect_format(mostly_domains), Format.Domains)
}

@(test)
test_a_domain_line_may_carry_an_allow_prefix :: proc(t: ^testing.T) {
	// A leading `-` moves the name to the allow set, which is how several
	// published domain lists express an exception.
	src := "ads.example\n-good.ads.example\n"
	testing.expect_value(t, matches(src, .Domains, "ads.example."), Decision.Blocked)
	testing.expect_value(t, matches(src, .Domains, "tracker.ads.example."), Decision.Blocked)
	testing.expect_value(t, matches(src, .Domains, "good.ads.example."), Decision.Allowed)
}

@(test)
test_a_domain_line_covers_the_name_and_everything_under_it :: proc(t: ^testing.T) {
	// The difference from a hosts entry, and the reason the two formats are
	// told apart at all.
	src := "ads.example\n"
	testing.expect_value(t, matches(src, .Domains, "ads.example."), Decision.Blocked)
	testing.expect_value(t, matches(src, .Domains, "deep.sub.ads.example."), Decision.Blocked)
	testing.expect_value(t, matches(src, .Domains, "notads.example."), Decision.None)
	// A neighbouring name that merely ends the same way is not under it.
	testing.expect_value(t, matches(src, .Domains, "xads.example."), Decision.None)
}

@(test)
test_a_leading_dot_domain_line_covers_the_name_and_everything_under_it :: proc(t: ^testing.T) {
	/*
	Squid `dstdomain` and Privoxy lists mark a subtree with a leading dot, and
	both read `.ads.example` as `ads.example` itself and every name under it
	(#591): the subtree a bare line already covers here.
	*/
	src := ".ads.example\n"
	testing.expect_value(t, matches(src, .Domains, "ads.example."), Decision.Blocked)
	testing.expect_value(t, matches(src, .Domains, "x.ads.example."), Decision.Blocked)
	testing.expect_value(t, matches(src, .Domains, "xads.example."), Decision.None)
	block, allow := parsed(src, .Domains)
	testing.expect_value(t, block.count, 1)
	set_destroy(block)
	set_destroy(allow)
	// An allow line reads its dot the same way.
	allowed := "ads.example\n-.good.ads.example\n"
	testing.expect_value(t, matches(allowed, .Domains, "good.ads.example."), Decision.Allowed)
	testing.expect_value(t, matches(allowed, .Domains, "x.good.ads.example."), Decision.Allowed)
	testing.expect_value(t, matches(allowed, .Domains, "ads.example."), Decision.Blocked)
	// The dot is the line's mark, not a second one for the parser to strip, and
	// a hosts or adblock line gives it no meaning.
	testing.expect_value(t, matches("*..ads.example\n", .Domains, "x.ads.example."), Decision.None)
	testing.expect_value(t, matches("..ads.example\n", .Domains, "ads.example."), Decision.None)
	// A dot at both ends is Privoxy's unanchored pattern, not a subtree of the
	// name between them.
	testing.expect_value(t, matches(".ads.\n", .Domains, "x.ads."), Decision.None)
	testing.expect_value(t, matches(".ads.example.\n", .Domains, "ads.example."), Decision.None)
	testing.expect_value(t, matches("0.0.0.0 .ads.example\n", .Hosts, "ads.example."), Decision.None)
	testing.expect_value(t, matches(".ads.example\n", .Adblock, "x.ads.example."), Decision.None)
}

@(test)
test_a_domain_wildcard_prefix_covers_only_what_is_under_it :: proc(t: ^testing.T) {
	// `*.example` is the subtree without the name itself, which is a
	// distinction list authors make on purpose.
	src := "*.ads.example\n"
	testing.expect_value(t, matches(src, .Domains, "sub.ads.example."), Decision.Blocked)
	testing.expect_value(t, matches(src, .Domains, "ads.example."), Decision.None)
}

@(test)
test_an_anchored_wildcard_prefix_covers_only_what_is_under_it :: proc(t: ^testing.T) {
	/*
	`||*.example^` is how the AdGuard DNS filter writes "every host under
	example, not example itself" (#323). The `*.` sits after the anchor, so it
	has to be read there too, or the wildcard check drops the rule.
	*/
	src := "||*.exaapi.com^\n"
	testing.expect_value(t, matches(src, .Adblock, "x.exaapi.com."), Decision.Blocked)
	testing.expect_value(t, matches(src, .Adblock, "deep.x.exaapi.com."), Decision.Blocked)
	testing.expect_value(t, matches(src, .Adblock, "exaapi.com."), Decision.None)
	testing.expect_value(t, matches(src, .Adblock, "xexaapi.com."), Decision.None)
	// A domains list hands the line to the adblock parser, and reads it the same.
	testing.expect_value(t, matches(src, .Domains, "x.exaapi.com."), Decision.Blocked)
	testing.expect_value(t, matches(src, .Domains, "exaapi.com."), Decision.None)
	testing.expect_value(t, matches("@@||*.ok.example^\n", .Adblock, "a.ok.example."), Decision.Allowed)
	// The exception is subtree-only too, so it leaves a block on the apex standing.
	testing.expect_value(t, matches("||ok.example^\n@@||*.ok.example^\n", .Adblock, "ok.example."), Decision.Blocked)
	// A second wildcard is still a pattern DNS cannot express.
	testing.expect_value(t, matches("||*.*.exaapi.com^\n", .Adblock, "a.b.exaapi.com."), Decision.None)
	// `$badfilter` cancels it in either spelling of the same rule.
	testing.expect_value(t, matches("||*.exaapi.com^\n||*.exaapi.com^$badfilter\n", .Adblock, "x.exaapi.com."), Decision.None)
	testing.expect_value(t, matches("*.exaapi.com\n||*.exaapi.com^$badfilter\n", .Adblock, "x.exaapi.com."), Decision.None)
	// The trade-off `set_cancel` names: against a `||x^` it narrows the rule to its apex.
	narrowed := "||exaapi.com^\n||*.exaapi.com^$badfilter\n"
	testing.expect_value(t, matches(narrowed, .Adblock, "exaapi.com."), Decision.Blocked)
	testing.expect_value(t, matches(narrowed, .Adblock, "x.exaapi.com."), Decision.None)
}

@(test)
test_a_domain_list_still_understands_an_adblock_entry :: proc(t: ^testing.T) {
	// Mixed lists are common enough that the domain parser hands these over
	// rather than dropping them.
	src := "ordinary.example\n||anchored.example^\n@@||allowed.example^\n"
	testing.expect_value(t, matches(src, .Domains, "ordinary.example."), Decision.Blocked)
	testing.expect_value(t, matches(src, .Domains, "sub.anchored.example."), Decision.Blocked)
	testing.expect_value(t, matches(src, .Domains, "allowed.example."), Decision.Allowed)
}

@(test)
test_domain_lines_dns_cannot_express_are_skipped :: proc(t: ^testing.T) {
	/*
	A path, a scheme, or a wildcard in the middle of a name is a rule about a
	URL, and this server sees names rather than URLs. Storing the text anyway
	would put a key in the map that no query can ever equal - harmless - but
	counting it as a rule reports a list as loaded when part of it was not.
	*/
	block, allow := parsed("example.com/ads\nexa*ple.example\n*\n-\n\n", .Domains)
	defer set_destroy(block)
	defer set_destroy(allow)
	testing.expect_value(t, block.count, 0)
	testing.expect_value(t, allow.count, 0)
}

@(test)
test_a_rule_with_an_empty_label_is_skipped :: proc(t: ^testing.T) {
	// No label is empty, so `.com` names nothing (#431). Stored, it would count
	// toward a list that blocks nothing by it.
	Case :: struct {
		src:    string,
		format: Format,
	}
	for c in ([]Case {
			{"*..com\n", .Adblock},
			{"||.com^\n", .Adblock},
			{"||*..com^\n", .Adblock},
			{"a..com\n", .Adblock},
			{"||a..^\n", .Adblock},
			{"@@||.com^\n", .Adblock},
			{"0.0.0.0 .com\n", .Hosts},
			{"*..com\n", .Domains},
			{"..com\n", .Domains},
			{"*...com\n", .Domains},
			{".\n", .Domains},
		}) {
		block, allow := parsed(c.src, c.format)
		testing.expectf(t, block.count == 0 && allow.count == 0 && block.not_ascii == 0, "%q should store no rule", c.src)
		set_destroy(block)
		set_destroy(allow)
	}
	// A `$badfilter` naming such a key cancels nothing.
	{
		block, allow := parsed("||.com^$badfilter\n", .Adblock)
		testing.expect_value(t, block.cancels, 0)
		set_destroy(block)
		set_destroy(allow)
	}
	// The ideographic and fullwidth full stops end a label too, so these have no
	// punycode form a query carries either: refused, not counted as not ASCII.
	// The last dot is the root `normalise` strips, so a full stop before it
	// ends an empty label, as `a..` does.
	for src in ([]string{"a。。com\n", "。com\n", "a.。com\n", "a．．com\n", "é..\n", "é。.\n"}) {
		block, allow := parsed(src, .Domains)
		testing.expectf(t, block.count == 0 && block.not_ascii == 0, "%q should be refused outright", src)
		set_destroy(block)
		set_destroy(allow)
	}
	{
		block, allow := parsed("a。com\n", .Domains)
		testing.expect_value(t, block.not_ascii, 1)
		set_destroy(block)
		set_destroy(allow)
	}
	// An ordinary rule still loads.
	testing.expect_value(t, matches("||a.com^\n", .Adblock, "x.a.com."), Decision.Blocked)
}

@(test)
test_a_rule_the_wire_cannot_carry_is_skipped :: proc(t: ^testing.T) {
	// A query's label holds at most 63 bytes and its name 255 on the wire
	// (RFC 1035 section 2.3.4), and every escape in it is whole, so a key past
	// either, or with a broken escape, names nothing.
	label63 := strings.repeat("a", 63, context.temp_allocator)
	label64 := strings.repeat("a", 64, context.temp_allocator)
	// Four 63-byte labels and `com` are 4*64 + 4 + 1 = 261 bytes on the wire.
	too_long := strings.concatenate({label63, ".", label63, ".", label63, ".", label63, ".com"}, context.temp_allocator)
	for src in ([]string{
			strings.concatenate({label64, ".com\n"}, context.temp_allocator),
			strings.concatenate({too_long, "\n"}, context.temp_allocator),
			"a\\\n",
			"a\\99.com\n",
			"a\\999.com\n",
		}) {
		block, allow := parsed(src, .Domains)
		testing.expectf(t, block.count == 0, "%q should store no rule", src)
		set_destroy(block)
		set_destroy(allow)
	}
	fits := strings.concatenate({label63, ".com"}, context.temp_allocator)
	testing.expect_value(t, matches(strings.concatenate({fits, "\n"}, context.temp_allocator), .Domains, strings.concatenate({"x.", fits, "."}, context.temp_allocator)), Decision.Blocked)
	// A 63-byte label spelled with escapes is longer as text, and still fits.
	escaped := strings.concatenate({"\\032", strings.repeat("a", 62, context.temp_allocator), ".com"}, context.temp_allocator)
	testing.expect_value(t, matches(strings.concatenate({escaped, "\n"}, context.temp_allocator), .Domains, strings.concatenate({escaped, "."}, context.temp_allocator)), Decision.Blocked)
	// A query spells a byte one way: `\DDD` for a dot, a backslash, a control or
	// a byte past ASCII, and itself otherwise. Any other spelling names nothing.
	for src in ([]string{"a\\.b.com\n", "a\\\\b.com\n", "\\097ds.com\n", "\\065ds.com\n", "\\ads.com\n"}) {
		block, allow := parsed(src, .Domains)
		testing.expectf(t, block.count == 0, "%q should store no rule", src)
		set_destroy(block)
		set_destroy(allow)
	}
	testing.expect_value(t, matches("a\\046b.com\n", .Domains, "a\\046b.com."), Decision.Blocked)
	// A name past ASCII has no punycode form shorter than its ASCII, so a label
	// or a name the wire cannot carry is refused, not counted as not ASCII.
	for src in ([]string{
			strings.concatenate({label64, ".é.com\n"}, context.temp_allocator),
			strings.concatenate({too_long, ".é\n"}, context.temp_allocator),
		}) {
		block, allow := parsed(src, .Domains)
		testing.expectf(t, block.count == 0 && block.not_ascii == 0, "%q should be refused outright", src)
		set_destroy(block)
		set_destroy(allow)
	}
	{
		block, allow := parsed(strings.concatenate({label63, ".é.com\n"}, context.temp_allocator), .Domains)
		testing.expect_value(t, block.not_ascii, 1)
		set_destroy(block)
		set_destroy(allow)
	}
}

@(test)
test_normalise_folds_case_and_the_trailing_dot :: proc(t: ^testing.T) {
	// A query arrives in wire-presentation form with the root dot on the end;
	// a list is written without it. Both have to land on the same key.
	buf: [MAX_NORMALISED]u8
	out, ok := normalise("Ads.Example.COM.", buf[:])
	testing.expect(t, ok, "an ordinary name should normalise")
	testing.expect_value(t, out, "ads.example.com")

	plain, plain_ok := normalise("ads.example.com", buf[:])
	testing.expect(t, plain_ok, "and so should the same name without the dot")
	testing.expect_value(t, plain, "ads.example.com")
}

@(test)
test_normalise_refuses_what_cannot_be_a_domain :: proc(t: ^testing.T) {
	buf: [MAX_NORMALISED]u8
	for bad in ([]string{"", "."}) {
		_, ok := normalise(bad, buf[:])
		testing.expectf(t, !ok, "%q should not normalise", bad)
	}

	// A name too long for the buffer is refused rather than truncated: a
	// truncated key would be a different name, and could be one that matters.
	long := strings.repeat("a", MAX_NORMALISED + 1, context.temp_allocator)
	_, too_long := normalise(long, buf[:])
	testing.expect(t, !too_long, "a name past the buffer should be refused")

	// Exactly the buffer's width still fits.
	exact := strings.repeat("a", MAX_NORMALISED, context.temp_allocator)
	_, fits := normalise(exact, buf[:])
	testing.expect(t, fits, "a name exactly the buffer's width fits")
	free_all(context.temp_allocator)
}

@(test)
test_a_query_name_with_a_slash_is_still_matched :: proc(t: ^testing.T) {
	/*
	A label may carry any octet, and presentation form leaves `/` unescaped. A
	slash marks a mis-split rule, not a query name: refusing it at match time let
	`a/b.ads.example.com.` past a block on its parent and stripped an allowed name
	of its exception.
	*/
	src := "||ads.example.com^\n@@||safe.ads.example.com^\n"
	testing.expect_value(t, matches(src, .Adblock, "a/b.ads.example.com."), Decision.Blocked)
	testing.expect_value(t, matches(src, .Adblock, "/.safe.ads.example.com."), Decision.Allowed)
}

@(test)
test_a_rule_that_cannot_be_a_domain_is_refused :: proc(t: ^testing.T) {
	/*
	Whitespace and a slash are the marks of a line the parser has mis-split - a
	whole hosts line taken as a name, or a URL rule that got this far. A raw
	control or non-ASCII byte is one a query always spells as \DDD. Refusing
	them keeps such a thing from being stored as a rule that then never matches
	anything, and keeps the counts honest.
	*/
	s := set_make()
	defer set_destroy(s)
	for bad in ([]string{"ads example", "ads\texample", "example.com/path", "0.0.0.0 ads.example", "b\u00fccher.de", "a\x01b.example"}) {
		testing.expectf(t, !set_add(s, bad, {.Apex}), "%q should not be added", bad)
		set_cancel(s, bad, {.Apex})
	}
	testing.expect_value(t, s.count, 0)
	testing.expect_value(t, len(s.cancelled), 0)

	// A query spells these bytes as \DDD, so a rule holding one raw never matches.
	block, allow := parsed("0.0.0.0 b\u00fccher.de a\x01b.example ok.example\n", .Hosts)
	defer set_destroy(block)
	defer set_destroy(allow)
	testing.expect_value(t, block.count, 1)
}

@(test)
test_a_rule_written_as_a_query_spells_it_matches :: proc(t: ^testing.T) {
	// `\` is how presentation form escapes a byte, so a rule written that way is
	// the one that can match.
	testing.expect_value(t, matches("a\\032b.example\n", .Domains, "a\\032b.example."), Decision.Blocked)
}

@(test)
test_a_rule_a_badfilter_cancelled_is_not_stored :: proc(t: ^testing.T) {
	s := set_make()
	defer set_destroy(s)
	set_cancel(s, "x.example", {.Apex, .Subdomains})
	testing.expect(t, !set_add(s, "x.example", {.Apex, .Subdomains}), "a fully cancelled rule adds nothing")
	set_cancel(s, "y.example", {.Apex})
	testing.expect(t, set_add(s, "y.example", {.Apex, .Subdomains}), "what the cancel left is stored")
}

@(test)
test_a_dnsmasq_server_line_with_an_upstream_forwards_rather_than_blocks :: proc(t: ^testing.T) {
	// `server=/d/1.2.3.4` sends d to that server; only `server=/d/` keeps it local.
	testing.expect_value(t, matches("server=/corp.example/10.0.0.1\n", .Adblock, "corp.example."), Decision.None)
	testing.expect_value(t, matches("server=/ads.example/\n", .Adblock, "ads.example."), Decision.Blocked)
	testing.expect_value(t, matches("address=/ads.example/0.0.0.0\n", .Adblock, "ads.example."), Decision.Blocked)
	// The server is only what follows the last slash; every name before it is covered.
	testing.expect_value(t, matches("server=/ads.example/tracker.example/\n", .Adblock, "tracker.example."), Decision.Blocked)
	testing.expect_value(t, matches("server=/ads.example/tracker.example/\n", .Adblock, "ads.example."), Decision.Blocked)
	testing.expect_value(t, matches("server=/a.example/b.example/10.0.0.1\n", .Adblock, "b.example."), Decision.None)
	testing.expect_value(t, matches("address=/a.example/b.example/0.0.0.0\n", .Adblock, "b.example."), Decision.Blocked)
}

@(test)
test_a_refused_rule_is_not_counted_as_loaded :: proc(t: ^testing.T) {
	block, allow := set_make(), set_make()
	defer set_destroy(block)
	defer set_destroy(allow)
	added := parse_list(block, allow, "0.0.0.0 example.com/path b\u00fccher.de ok.example\n", .Hosts)
	testing.expect_value(t, added, 1)
	testing.expect_value(t, added, block.count)
}

@(test)
test_set_lookup_walks_the_parents_for_subdomain_rules :: proc(t: ^testing.T) {
	/*
	The lookup costs one probe per label rather than one per rule, which is what
	lets a list of a million names be matched in bounded time. The walk has to
	stop at the last label rather than running off the end of the name.
	*/
	s := set_make()
	defer set_destroy(s)
	set_add(s, "ads.example", {.Subdomains})
	set_add(s, "apex.example", {.Apex})

	testing.expect(t, set_lookup(s, "a.b.c.d.e.ads.example", .A), "a deep name is still under the rule")
	testing.expect(t, !set_lookup(s, "ads.example", .A), "a subdomains-only rule does not cover the name itself")
	testing.expect(t, set_lookup(s, "apex.example", .A), "an apex rule covers the name")
	testing.expect(t, !set_lookup(s, "sub.apex.example", .A), "and nothing below it")
	testing.expect(t, !set_lookup(s, "example", .A), "the walk does not match a bare parent label")
	testing.expect(t, !set_lookup(s, "unrelated.example", .A), "nor an unrelated name")
	testing.expect(t, !set_lookup(s, "", .A), "nor an empty one")

	// An empty set answers nothing, and neither does a nil one.
	empty := set_make()
	defer set_destroy(empty)
	testing.expect(t, !set_lookup(empty, "ads.example", .A), "an empty set matches nothing")
	testing.expect(t, !set_lookup(nil, "ads.example", .A), "and a missing one does not crash")
}

@(test)
test_set_add_merges_the_flags_of_a_repeated_name :: proc(t: ^testing.T) {
	/*
	The same name arrives from several lists, or twice in one - once as a hosts
	entry and once anchored. The rule has to end up covering both, and be
	counted once, or the reported rule count drifts from the number of names the
	engine will actually match.
	*/
	s := set_make()
	defer set_destroy(s)
	set_add(s, "ads.example", {.Apex})
	set_add(s, "ads.example", {.Subdomains})
	testing.expect_value(t, s.count, 1)
	testing.expect(t, set_lookup(s, "ads.example", .A), "the apex is covered")
	testing.expect(t, set_lookup(s, "sub.ads.example", .A), "and so is the subtree")

	// A name that will not normalise is not a rule, and must not be counted.
	set_add(s, "not a domain", {.Apex})
	set_add(s, "", {.Apex})
	testing.expect_value(t, s.count, 1)
}

@(test)
test_a_badfilter_rule_cancels_the_rule_it_names :: proc(t: ^testing.T) {
	/*
	`$badfilter` is a list author saying "not this one", most often about a rule
	some other list carries. The AdGuard DNS filter cancels `||pl.ua^` that way,
	and pl.ua is a public suffix: read as a plain block, it took every name under
	it off the air. It cancels its rule whichever comes first, and across lists,
	since the lists share one set.
	*/
	block, allow := set_make(), set_make()
	defer set_destroy(block)
	defer set_destroy(allow)
	parse_list(block, allow, "||pl.ua^$badfilter\n||linksprf.com^\n@@||ok.example^$badfilter\n", .Adblock)
	parse_list(block, allow, "||pl.ua^\n||kept.example^\n||linksprf.com^$badfilter\n@@||ok.example^\n", .Adblock)
	testing.expect_value(t, block.count, 1)
	testing.expect_value(t, allow.count, 0)
	testing.expect(t, !set_lookup(block, "www.pl.ua", .A), "a cancelled rule blocks nothing under it")
	testing.expect(t, !set_lookup(block, "pl.ua", .A), "nor the name itself")
	testing.expect(t, !set_lookup(block, "linksprf.com", .A), "cancelled when the rule came first, too")
	testing.expect(t, !set_lookup(allow, "ok.example", .A), "an allow rule can be cancelled as well")
	testing.expect(t, set_lookup(block, "kept.example", .A), "a rule nobody cancelled still blocks")

	// On its own, with nothing to cancel, it blocks nothing either.
	testing.expect_value(t, matches("wykop.pl$badfilter\n", .Adblock, "wykop.pl."), Decision.None)
}

@(test)
test_a_rule_narrowed_by_a_modifier_is_not_widened :: proc(t: ^testing.T) {
	/*
	These modifiers narrow a rule to one client, or turn it into something that
	is not a block at all. Dropping the modifier and keeping the rule would block
	every query from every client, so the rule is skipped - what AdGuard Home
	does with a modifier its DNS engine cannot honour. `$dnstype` is honoured;
	see dnstype_test.odin.
	*/
	narrowed := []string {
		"||narrow.example^$important,client=192.168.1.5",
		"||narrow.example^$ctag=device_phone",
		"||narrow.example^$denyallow=ok.narrow.example",
		"||narrow.example^$dnsrewrite=10.0.0.1",
		"@@||narrow.example^$client=10.0.0.1",
		// Narrowed to requests made from one site, or to one request type.
		"||narrow.example^$domain=news.example",
		"||narrow.example^$script,third-party",
		// Not blocks at all: a URL rewrite, a CSP header, a cosmetic exception.
		"||narrow.example^$removeparam=utm_source",
		"||narrow.example^$csp=script-src 'self'",
		"@@||narrow.example^$elemhide",
		"@@||narrow.example^$generichide",
		// An unknown modifier is not known to leave the rule as wide as it looks.
		"||narrow.example^$IMPORTANT",
		// urlfilter does not trim a modifier, so a spaced one is unknown too.
		"||narrow.example^$ important",
	}
	for rule in narrowed {
		testing.expectf(t, matches(rule, .Adblock, "narrow.example.") == .None, "%q matched", rule)
	}
	// Modifiers that do not narrow which queries are blocked keep the rule.
	testing.expect_value(t, matches("||wide.example^$important\n", .Adblock, "wide.example."), Decision.Blocked)
	testing.expect_value(t, matches("||wide.example^$important,\n", .Adblock, "wide.example."), Decision.Blocked)
	// `=x` names no modifier, and urlfilter refuses it.
	testing.expect_value(t, matches("||wide.example^$=x\n", .Adblock, "wide.example."), Decision.None)
	// A spaced `$badfilter` is skipped too, so it cancels nothing.
	testing.expect_value(t, matches("||wide.example^\n||wide.example^$important, badfilter\n", .Adblock, "wide.example."), Decision.Blocked)
}

@(test)
test_a_third_party_rule_blocks_nothing :: proc(t: ^testing.T) {
	/*
	AdGuard Home's DNS engine never loads a rule with `$third-party` set or
	negated (urlfilter's `IsHostLevelNetworkRule`), so neither blocks (#464).
	`3p` and `1p` are not aliases urlfilter knows, so they are skipped too.
	*/
	third_party := []string {
		"||narrow.example^$third-party",
		"||narrow.example^$~first-party",
		"||narrow.example^$~third-party",
		"||narrow.example^$first-party",
		"||narrow.example^$3p",
		"||narrow.example^$1p",
		"/narrow/$~third-party",
		"@@||narrow.example^$~third-party",
		"||narrow.example^$important,third-party",
		"/narrow/$third-party",
		"@@||narrow.example^$third-party",
		// urlfilter splits the options off at the last `$`, so a value does not
		// hide one.
		"||narrow.example^$important=$third-party",
	}
	for rule in third_party {
		testing.expectf(t, matches(rule, .Adblock, "narrow.example.") == .None, "%q matched", rule)
	}
	// Its `$badfilter` names a rule that is never added, so it cancels nothing.
	testing.expect_value(t, matches("||narrow.example^\n||narrow.example^$third-party,badfilter\n", .Adblock, "narrow.example."), Decision.Blocked)
	testing.expect_value(t, matches("||narrow.example^\n||narrow.example^$~third-party,badfilter\n", .Adblock, "narrow.example."), Decision.Blocked)
	testing.expect_value(t, matches("||narrow.example^\n||narrow.example^$badfilter=$third-party\n", .Adblock, "narrow.example."), Decision.Blocked)
	// A `\,` does not split, so this is one `important` whose value is `,badfilter`.
	testing.expect_value(t, matches("||narrow.example^\n||narrow.example^$important=\\,badfilter\n", .Adblock, "narrow.example."), Decision.Blocked)
	// Nor does a skipped `@@` rule allow what a plain rule blocks.
	testing.expect_value(t, matches("||narrow.example^\n@@||narrow.example^$first-party\n", .Adblock, "narrow.example."), Decision.Blocked)
	// What is left before the last `$` holds a `$`, which no name does.
	block, allow := set_make(), set_make()
	defer set_destroy(block)
	defer set_destroy(allow)
	testing.expect_value(t, parse_rule(block, allow, "||narrow.example^$third-party$important"), 0)
}

@(test)
test_a_cosmetic_rule_blocks_nothing :: proc(t: ^testing.T) {
	// HTML and CSS filtering rules name the site they apply on, not one to block.
	cosmetic := []string {
		`example.com$$script[tag-content="ads"]`,
		`example.com$@$script[tag-content="ads"]`,
		"example.com##.banner",
		"example.com#@#.banner",
		"example.com#$#body { color: red }",
		"example.com#?#div:has(> a)",
	}
	for rule in cosmetic {
		testing.expectf(t, matches(rule, .Adblock, "example.com.") == .None, "%q matched", rule)
	}
}

@(test)
test_a_rule_whose_name_is_not_ascii_is_counted :: proc(t: ^testing.T) {
	// A UTF-8 name never matches (a query spells those bytes as \DDD, and a stub
	// asks for the punycode form), so the loader is told how many it skipped
	// (#400), whichever syntax the list writes it in. Other refusals are not counted.
	cases := []struct {
		text:   string,
		format: Format,
	}{{"0.0.0.0 bücher.example ok.example\n", .Hosts}, {"bücher.example\nok.example\n", .Domains}, {"||bücher.example^\n||ok.example^\n", .Adblock}, {"||bücher.example^$badfilter\n||ok.example^\n", .Adblock}}
	for c in cases {
		block, allow := parsed(c.text, c.format)
		testing.expectf(t, block.not_ascii == 1, "%v: not_ascii = %d", c.format, block.not_ascii)
		testing.expect_value(t, block.count, 1)
		set_destroy(block)
		set_destroy(allow)
	}
	{
		// A digit or a mark past ASCII is in a label as well as a letter, and so
		// are the joiners and punctuation RFC 5892 appendix A admits in context:
		// a combining acute, a Devanagari vowel sign, Arabic-Indic digits, a
		// Persian ZWNJ and a Catalan middle dot. An ideographic, fullwidth or
		// halfwidth full stop is a dot (RFC 3490 section 3.1).
		block, allow := parsed(
			"0.0.0.0 éte.example किताब.example ١٢.example می‌خواهم.example col·legi.example 例え。テスト bücher．example bücher｡example\n",
			.Hosts,
		)
		defer set_destroy(block)
		defer set_destroy(allow)
		testing.expect_value(t, block.not_ascii, 8)
	}
	// A name refused for a `/` or a control byte is not counted even when it
	// holds a byte past ASCII too: punycode would not make it match. Nor is one
	// whose bytes past ASCII are no letter: a no-break or zero-width space, a
	// BOM, or a byte that is not UTF-8, as a Latin-1 file holds. Nor is one
	// holding ASCII no label holds, such as a `*` or a `:`.
	block, allow := parsed(
		"0.0.0.0 a\x01b.example example.com/path example.de/über ads.example\u00a0x.example \u200bads.example \ufeffads.example b\xfccher.example bü\x01cher.example bü*cher.example bücher.example:8080\n",
		.Hosts,
	)
	defer set_destroy(block)
	defer set_destroy(allow)
	testing.expect_value(t, block.not_ascii, 0)
}

@(test)
test_a_byte_order_mark_is_not_part_of_the_first_rule :: proc(t: ^testing.T) {
	// A list saved by a Windows editor opens with a UTF-8 BOM, and one built by
	// joining such files holds one at the start of each. Read as part of a
	// name, it would drop that rule.
	cases := []struct {
		text:   string,
		format: Format,
	}{{"\xef\xbb\xbf0.0.0.0 ads.example\n", .Hosts}, {"\xef\xbb\xbfads.example\n", .Domains}, {"\xef\xbb\xbf||ads.example^\n", .Adblock}, {"\xef\xbb\xbf||ads.example^\n", .Auto}, {"# a.txt\n\xef\xbb\xbfads.example\n", .Domains}, {"# a.txt\n\xef\xbb\xbf0.0.0.0 ads.example\n", .Auto}}
	for c in cases {
		block, allow := parsed(c.text, c.format)
		testing.expectf(t, block.count == 1, "%v: count = %d", c.format, block.count)
		testing.expectf(t, block.not_ascii == 0, "%v: not_ascii = %d", c.format, block.not_ascii)
		set_destroy(block)
		set_destroy(allow)
	}
}
