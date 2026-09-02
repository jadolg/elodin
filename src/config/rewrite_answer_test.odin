package config

import "core:strings"
import "core:testing"

/*
The zone-file form of `answers:`, which is the half of a rewrite rule that says
what the record is rather than which name it is for.

Every case here is written the way the operator's other documents write it - a
registrar's mail setup page, a SIP provider's instructions, an SPF generator -
because that is the whole argument for the syntax: the fields are in the order
the RFC prints them, so a rule can be copied across without being translated.
*/
@(private = "file")
rules_from :: proc(t: ^testing.T, answers: string) -> []Rewrite {
	src := strings.concatenate(
		{"upstream:\n  servers: [1.1.1.1]\nrewrites:\n  - domain: example.com\n    answers: ", answers, "\n"},
		context.temp_allocator,
	)
	cfg, err := load_string(src, context.temp_allocator)
	if e, has := err.?; has {
		testing.expectf(t, false, "config errors: %v", e.messages)
		return nil
	}
	return cfg.rewrites
}

// The message a bad answer produces, or "" when it was accepted.
@(private = "file")
error_from :: proc(answers: string) -> string {
	src := strings.concatenate(
		{"upstream:\n  servers: [1.1.1.1]\nrewrites:\n  - domain: example.com\n    answers: ", answers, "\n"},
		context.temp_allocator,
	)
	_, err := load_string(src, context.temp_allocator)
	e, has := err.?
	if !has {
		return ""
	}
	return e.messages[0]
}

@(test)
test_rewrite_mx_answer :: proc(t: ^testing.T) {
	rules := rules_from(t, `["MX 10 mail.example.com"]`)
	if !testing.expect(t, len(rules) == 1 && len(rules[0].answers) == 1, "expected one answer") {
		return
	}
	a := rules[0].answers[0]
	testing.expect_value(t, a.kind, Rewrite_Kind.MX)
	testing.expect_value(t, a.preference, u16(10))
	testing.expect_value(t, a.name, "mail.example.com.")

	// RFC 7505's null MX: the domain accepts no mail, and the root is a legal
	// exchange for saying so.
	null_mx := rules_from(t, `["MX 0 ."]`)
	if testing.expect(t, len(null_mx) == 1 && len(null_mx[0].answers) == 1, "expected one answer") {
		testing.expect_value(t, null_mx[0].answers[0].preference, u16(0))
		testing.expect_value(t, null_mx[0].answers[0].name, ".")
	}

	free_all(context.temp_allocator)
}

@(test)
test_rewrite_srv_answer :: proc(t: ^testing.T) {
	rules := rules_from(t, `["SRV 0 5 5060 sip.example.com"]`)
	if !testing.expect(t, len(rules) == 1 && len(rules[0].answers) == 1, "expected one answer") {
		return
	}
	a := rules[0].answers[0]
	testing.expect_value(t, a.kind, Rewrite_Kind.SRV)
	testing.expect_value(t, a.priority, u16(0))
	testing.expect_value(t, a.weight, u16(5))
	testing.expect_value(t, a.port, u16(5060))
	testing.expect_value(t, a.name, "sip.example.com.")

	free_all(context.temp_allocator)
}

/*
TXT in both of its shapes, and the reason there are two.

Unquoted is the whole of the rest, so the common one-line record needs no
ceremony. Quoted is a sequence, which is what a TXT record is and what anything
longer than 255 bytes has to be written as.
*/
@(test)
test_rewrite_txt_answer :: proc(t: ^testing.T) {
	bare := rules_from(t, `["TXT hello world"]`)
	if testing.expect(t, len(bare) == 1 && len(bare[0].answers) == 1, "expected one answer") {
		a := bare[0].answers[0]
		testing.expect_value(t, a.kind, Rewrite_Kind.TXT)
		if testing.expect_value(t, len(a.strings), 1) {
			testing.expect_value(t, a.strings[0], "hello world")
		}
	}

	quoted := rules_from(t, `['TXT "v=spf1 -all"']`)
	if testing.expect(t, len(quoted) == 1 && len(quoted[0].answers) == 1, "expected one answer") {
		if testing.expect_value(t, len(quoted[0].answers[0].strings), 1) {
			testing.expect_value(t, quoted[0].answers[0].strings[0], "v=spf1 -all")
		}
	}

	pair := rules_from(t, `['TXT "part one" "part two"']`)
	if testing.expect(t, len(pair) == 1 && len(pair[0].answers) == 1, "expected one answer") {
		strs := pair[0].answers[0].strings
		if testing.expect_value(t, len(strs), 2) {
			testing.expect_value(t, strs[0], "part one")
			testing.expect_value(t, strs[1], "part two")
		}
	}

	// A quote and a backslash, which is the whole of the escaping.
	escaped := rules_from(t, `['TXT "say \"hi\" \\ once"']`)
	if testing.expect(t, len(escaped) == 1 && len(escaped[0].answers) == 1, "expected one answer") {
		if testing.expect_value(t, len(escaped[0].answers[0].strings), 1) {
			testing.expect_value(t, escaped[0].answers[0].strings[0], `say "hi" \ once`)
		}
	}

	// An empty string is a legal TXT record and says something: the name has one
	// and it holds nothing.
	empty := rules_from(t, `['TXT ""']`)
	if testing.expect(t, len(empty) == 1 && len(empty[0].answers) == 1, "expected one answer") {
		if testing.expect_value(t, len(empty[0].answers[0].strings), 1) {
			testing.expect_value(t, empty[0].answers[0].strings[0], "")
		}
	}

	free_all(context.temp_allocator)
}

// The explicit spellings of the three kinds that already had a short form, which
// an operator who has learned the type token will reach for.
@(test)
test_rewrite_explicit_address_and_name_types :: proc(t: ^testing.T) {
	rules := rules_from(t, `["A 192.168.1.50", "AAAA fd00::1"]`)
	if !testing.expect(t, len(rules) == 1 && len(rules[0].answers) == 2, "expected two answers") {
		return
	}
	testing.expect_value(t, rules[0].answers[0].kind, Rewrite_Kind.A)
	testing.expect_value(t, rules[0].answers[0].v4, [4]u8{192, 168, 1, 50})
	testing.expect_value(t, rules[0].answers[1].kind, Rewrite_Kind.AAAA)
	testing.expect_value(
		t,
		rules[0].answers[1].v6,
		[16]u8{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
	)

	// On its own, an alias being the one answer that cannot share a name.
	alias := rules_from(t, `["CNAME new.example.com"]`)
	if testing.expect(t, len(alias) == 1 && len(alias[0].answers) == 1, "expected one answer") {
		testing.expect_value(t, alias[0].answers[0].kind, Rewrite_Kind.CNAME)
		testing.expect_value(t, alias[0].answers[0].name, "new.example.com.")
	}

	free_all(context.temp_allocator)
}

/*
A CNAME cannot sit beside other records at the same name (RFC 2181 section
10.1), and there cannot be two of them.

Barely writable before - a rule was an address, an alias or the sink - and the
natural thing to write now that a rule can carry several types, which is why the
check arrives with them. A resolver meeting a CNAME beside an MX has met a
malformed answer, and what it does with one is its own business: some take the
first record, some refuse the lot.
*/
@(test)
test_a_cname_cannot_share_its_name :: proc(t: ^testing.T) {
	answers := [?]string {
		`["CNAME web.example.com", 'TXT "v=spf1 -all"']`,
		`["CNAME web.example.com", "MX 10 mail.example.com"]`,
		`[new.example.com, 192.168.1.50]`,
		`["CNAME one.example.com", "CNAME two.example.com"]`,
	}
	for a in answers {
		msg := error_from(a)
		if testing.expectf(t, msg != "", "%s was accepted", a) {
			testing.expectf(
				t,
				strings.contains(msg, "CNAME"),
				"%s: message %q should say which record is the problem",
				a,
				msg,
			)
		}
	}

	// `block` is not a record and answers before the rest of the rule is looked
	// at, so it may sit anywhere.
	with_block := rules_from(t, `[block, new.example.com]`)
	testing.expect(t, len(with_block) == 1, "block beside a CNAME should load")

	free_all(context.temp_allocator)
}

/*
The short form is untouched, which is most of what is in anybody's file.

Pinned here beside the typed form because the two share a parser now: a bare
address is still an address, a bare name is still a CNAME, and `block` is still
the name sunk.
*/
@(test)
test_rewrite_short_form_unchanged :: proc(t: ^testing.T) {
	rules := rules_from(t, `[192.168.1.50, "fd00::10", block]`)
	if !testing.expect(t, len(rules) == 1 && len(rules[0].answers) == 3, "expected three answers") {
		return
	}
	testing.expect_value(t, rules[0].answers[0].kind, Rewrite_Kind.A)
	testing.expect_value(t, rules[0].answers[1].kind, Rewrite_Kind.AAAA)
	testing.expect_value(t, rules[0].answers[2].kind, Rewrite_Kind.Block)

	alias := rules_from(t, `[new.example.com]`)
	if testing.expect(t, len(alias) == 1 && len(alias[0].answers) == 1, "expected one answer") {
		testing.expect_value(t, alias[0].answers[0].kind, Rewrite_Kind.CNAME)
		testing.expect_value(t, alias[0].answers[0].name, "new.example.com.")
	}

	free_all(context.temp_allocator)
}

/*
An error names the key the rule actually used.

`answer:` and `answers:` are both accepted, so a file that says the first and is
told about `answers[0]` is being pointed at a key it does not contain. A scalar
has no index to name either.
*/
@(test)
test_rewrite_errors_name_the_key_that_was_used :: proc(t: ^testing.T) {
	singular := "upstream:\n  servers: [1.1.1.1]\nrewrites:\n  - domain: example.com\n    answer: \"MX ten mail.example.com\"\n"
	_, serr := load_string(singular, context.temp_allocator)
	if e, has := serr.?; testing.expect(t, has, "a bad singular answer was accepted") {
		testing.expectf(
			t,
			strings.contains(e.messages[0], "rewrites[0].answer:"),
			"message %q should name the `answer` key with no index",
			e.messages[0],
		)
	}

	// A list keeps its index, however long it is.
	msg := error_from(`["MX ten mail.example.com"]`)
	if testing.expect(t, msg != "", "a bad listed answer was accepted") {
		testing.expect(t, strings.contains(msg, "rewrites[0].answers[0]"), "a list names its index")
	}

	free_all(context.temp_allocator)
}

/*
A bare type token is a name, not a type, and a host really can be called `mx`.

This is what keeps the two forms from colliding, and it is the one case where
being wrong would be silent: read as a type, `answer: mx` would be an MX record
with no preference and no exchange, and there is no such thing.
*/
@(test)
test_a_bare_type_token_is_a_cname :: proc(t: ^testing.T) {
	tokens := [?]string{"mx", "txt", "srv", "a", "cname"}
	for name in tokens {
		rules := rules_from(t, strings.concatenate({"[", name, "]"}, context.temp_allocator))
		if testing.expectf(t, len(rules) == 1 && len(rules[0].answers) == 1, "%s: expected one answer", name) {
			a := rules[0].answers[0]
			testing.expectf(t, a.kind == .CNAME, "%s should be a CNAME, got %v", name, a.kind)
			testing.expect_value(
				t,
				a.name,
				strings.concatenate({name, "."}, context.temp_allocator),
			)
		}
	}
	free_all(context.temp_allocator)
}

/*
What the typed form buys: a mistake in it is an error with the rule named,
rather than a CNAME to something nobody meant.

Each of these is a plausible slip - a word where a number goes, a field left
out, one too many, an unterminated quote, a string over the wire's limit - and
each has exactly one reading, which is why it can be refused.
*/
@(test)
test_rewrite_typed_answers_are_checked :: proc(t: ^testing.T) {
	Case :: struct {
		answers: string,
		wants:   string,
	}
	cases := [?]Case {
		{`["MX ten mail.example.com"]`, "preference"},
		{`["MX 70000 mail.example.com"]`, "preference"},
		{`["MX 10"]`, "MX takes a preference and a host"},
		{`["MX 10 mail.example.com extra"]`, "MX takes a preference and a host"},
		{`["SRV 0 5 sip.example.com"]`, "SRV takes a priority"},
		{`["SRV 0 5 notaport sip.example.com"]`, "port"},
		{`["SRV 0 five 5060 sip.example.com"]`, "weight"},
		{`["A not.an.address"]`, "A needs an IPv4 address"},
		{`["A fd00::1"]`, "A needs an IPv4 address"},
		{`["AAAA 192.168.1.50"]`, "AAAA needs an IPv6 address"},
		{`['TXT "never closed']`, "never closed"},
		{`['TXT "one" two']`, "outside a quoted string"},
	}
	for c in cases {
		msg := error_from(c.answers)
		if testing.expectf(t, msg != "", "%s was accepted", c.answers) {
			testing.expectf(
				t,
				strings.contains(msg, c.wants),
				"%s: message %q does not mention %q",
				c.answers,
				msg,
				c.wants,
			)
			// Every one of them names the rule and the answer that was wrong.
			testing.expectf(
				t,
				strings.contains(msg, "rewrites[0].answers[0]"),
				"%s: message %q does not say which answer",
				c.answers,
				msg,
			)
		}
	}
	free_all(context.temp_allocator)
}

/*
A type this does not answer, and a type that does not exist, are both errors
rather than a CNAME to a name with a space in it.

`PTR nas.home` is the plausible one - the reverse synthesis is documented right
beside this - and without the check it became an alias to the name
`ptr nas.home`, which `encode_name` puts on the wire quite happily, so every
client asking that name got it, whatever type they asked for. A typo has the
same non-reading and so gets the same refusal.
*/
@(test)
test_rewrite_unknown_type_token_is_refused :: proc(t: ^testing.T) {
	answers := [?]string {
		`["PTR nas.home"]`,
		`["NS ns1.internal"]`,
		`["CAA 0 issue letsencrypt.org"]`,
		`["HTTPS 1 . alpn=h2"]`,
		`["MXX 10 mail.example.com"]`,
		// No type at all, several fields: the shape that has always become a
		// nonsense CNAME.
		`["some random text"]`,
	}
	for a in answers {
		msg := error_from(a)
		if testing.expectf(t, msg != "", "%s was accepted", a) {
			testing.expectf(
				t,
				strings.contains(msg, "record type"),
				"%s: message %q should say a type comes first",
				a,
				msg,
			)
		}
	}

	// And the six it does answer are still answered, so the refusal is about the
	// token rather than about anything having a space in it.
	rules := rules_from(t, `["MX 10 mail.example.com"]`)
	testing.expect(t, len(rules) == 1 && len(rules[0].answers) == 1, "MX should still parse")

	free_all(context.temp_allocator)
}

/*
`block` and `deny` fold case like the type tokens beside them.

`Block` read as a name is a CNAME to the host `block`, which is not merely
different from what was asked for but the opposite of it: the name resolves
instead of being sunk.
*/
@(test)
test_rewrite_block_folds_case :: proc(t: ^testing.T) {
	spellings := [?]string{"block", "Block", "BLOCK", "deny", "DENY"}
	for s in spellings {
		rules := rules_from(t, strings.concatenate({"[", s, "]"}, context.temp_allocator))
		if testing.expectf(t, len(rules) == 1 && len(rules[0].answers) == 1, "%s: expected one answer", s) {
			testing.expectf(
				t,
				rules[0].answers[0].kind == .Block,
				"%s should sink the name, got %v",
				s,
				rules[0].answers[0].kind,
			)
		}
	}
	free_all(context.temp_allocator)
}

/*
A name the wire cannot carry is a startup error, not a rule that quietly does
nothing.

What made this worth a check at load time is where the failure went: the record
fails to encode at query time, `apply_rewrite` gives up, and the query carries
on to the upstream - so the internal name the rule was written for leaves the
building and the public answer comes back, with nothing logged. A 64-byte label
and a name over 255 bytes are the two ways to write one.
*/
@(test)
test_rewrite_names_must_fit_on_the_wire :: proc(t: ^testing.T) {
	long_label := strings.concatenate(
		{strings.repeat("a", 64, context.temp_allocator), ".example.com"},
		context.temp_allocator,
	)
	deep := strings.repeat("abcdefghij.", 26, context.temp_allocator)

	answers := [?]string {
		strings.concatenate({`["MX 10 `, long_label, `"]`}, context.temp_allocator),
		// An empty label, which is the same class of unencodable name and the
		// one an operator actually produces, by typing a dot twice.
		`["MX 10 mail..example.org"]`,
		strings.concatenate({`["SRV 0 5 5060 `, long_label, `"]`}, context.temp_allocator),
		strings.concatenate({`["CNAME `, long_label, `"]`}, context.temp_allocator),
		strings.concatenate({`[`, long_label, `]`}, context.temp_allocator),
		strings.concatenate({`["MX 10 `, deep, `"]`}, context.temp_allocator),
	}
	for a in answers {
		msg := error_from(a)
		if testing.expectf(t, msg != "", "an unencodable name was accepted: %s", a) {
			testing.expectf(
				t,
				strings.contains(msg, "cannot be put on the wire"),
				"message %q should say the name cannot be sent",
				msg,
			)
		}
	}

	// 63 bytes is the label limit, so one of exactly that is fine.
	ok_label := strings.concatenate(
		{strings.repeat("a", 63, context.temp_allocator), ".example.com"},
		context.temp_allocator,
	)
	rules := rules_from(t, strings.concatenate({`["MX 10 `, ok_label, `"]`}, context.temp_allocator))
	testing.expect(t, len(rules) == 1 && len(rules[0].answers) == 1, "a 63-byte label should parse")

	free_all(context.temp_allocator)
}

/*
Both keys on one rule is refused rather than resolved in silence.

`answer:` won and `answers:` was dropped, and with rules that can hold several
records the obvious way to add an MX to a rule that has an address is to write
the second key under the first - which threw the MX away and passed `--check`
while doing it.
*/
@(test)
test_a_rule_may_not_have_both_answer_keys :: proc(t: ^testing.T) {
	src := "upstream:\n  servers: [1.1.1.1]\nrewrites:\n  - domain: example.com\n    answer: 192.168.1.50\n    answers: [\"MX 10 mail.example.com\"]\n"
	_, err := load_string(src, context.temp_allocator)
	if e, has := err.?; testing.expect(t, has, "both keys were accepted") {
		testing.expect(t, strings.contains(e.messages[0], "both"), "the message should say which mistake this is")
	}
	free_all(context.temp_allocator)
}

/*
The rule's own `domain:` is held to the wire's limits too.

A rule is matched against a name that came off the wire, so a domain the wire
cannot carry is a rule no query can ever equal: it sits in a configuration
`--check` passed, matching nothing, which is the outcome the answer-side check
was added to prevent.
*/
@(test)
test_rewrite_domain_must_fit_the_wire :: proc(t: ^testing.T) {
	long_label := strings.concatenate(
		{strings.repeat("a", 64, context.temp_allocator), ".home"},
		context.temp_allocator,
	)
	src := strings.concatenate(
		{
			"upstream:\n  servers: [1.1.1.1]\nrewrites:\n  - domain: ",
			long_label,
			"\n    answer: 192.168.1.50\n",
		},
		context.temp_allocator,
	)
	_, err := load_string(src, context.temp_allocator)
	if e, has := err.?; testing.expect(t, has, "an unencodable domain was accepted") {
		testing.expect(
			t,
			strings.contains(e.messages[0], "rewrites[0].domain"),
			"the message should name the domain",
		)
	}

	// A wildcard's suffix is a name as well, and is checked the same way.
	wild := strings.concatenate(
		{
			"upstream:\n  servers: [1.1.1.1]\nrewrites:\n  - domain: \"*.",
			long_label,
			"\"\n    answer: 192.168.1.50\n",
		},
		context.temp_allocator,
	)
	_, werr := load_string(wild, context.temp_allocator)
	_, whas := werr.?
	testing.expect(t, whas, "an unencodable wildcard suffix was accepted")

	free_all(context.temp_allocator)
}

/*
Records that each fit and together do not.

A rule answers with all of its records of the queried type at once, and the
encoder's response to a message it cannot fill is to truncate rather than to
complain - at the same 65535 over TCP as over UDP, so the client has nowhere
larger to retry. It takes hundreds of records at one name to reach, which is not
an answer anybody can use anyway.
*/
@(test)
test_a_rule_may_not_hold_more_than_a_message :: proc(t: ^testing.T) {
	long := strings.repeat("x", 255, context.temp_allocator)
	b := strings.builder_make(context.temp_allocator)
	strings.write_string(&b, "[")
	for i in 0 ..< 300 {
		if i > 0 {
			strings.write_string(&b, ", ")
		}
		strings.write_string(&b, "\"TXT ")
		strings.write_string(&b, long)
		strings.write_string(&b, "\"")
	}
	strings.write_string(&b, "]")

	msg := error_from(strings.to_string(b))
	if testing.expect(t, msg != "", "300 full-length TXT records were accepted") {
		testing.expect(t, strings.contains(msg, "at most"), "the message should name the limit")
	}

	// A handful of the same records is fine, the limit being about hundreds.
	ok_rules := rules_from(t, `["TXT one", "TXT two", "TXT three"]`)
	testing.expect(t, len(ok_rules) == 1, "three TXT records should load")

	free_all(context.temp_allocator)
}

/*
An answer that cannot be parsed takes its whole rule with it.

Only `load_string` treating these errors as fatal kept a half-parsed rule out of
the resolver, and that became load-bearing when a rule with no usable answers
started reading to the server as a record-only rule it should step over. The
rule is dropped here instead, the way every other failure in `load_rewrites`
drops one.
*/
@(test)
test_a_bad_answer_drops_its_rule :: proc(t: ^testing.T) {
	src := "upstream:\n  servers: [1.1.1.1]\nrewrites:\n  - domain: example.com\n    answers: [\"MX ten mail.example.com\", 192.168.1.50]\n  - domain: other.example\n    answer: 192.168.1.51\n"
	cfg, err := load_string(src, context.temp_allocator)
	if _, has := err.?; !testing.expect(t, has, "a bad answer was accepted") {
		return
	}
	// The rule with the bad answer is gone rather than standing with one answer
	// missing; the rule after it is untouched.
	for rule in cfg.rewrites {
		testing.expectf(
			t,
			rule.domain != "example.com.",
			"the rule with the unparseable answer was kept: %v",
			rule,
		)
	}

	free_all(context.temp_allocator)
}

/*
The 255-byte limit on one <character-string>, which is the length octet in front
of it and not a policy of this file's.

Refused rather than split, because splitting changes what the record says: where
the pieces join is the client's business, and a DKIM key cut somewhere this
server chose is a mail domain that fails to verify with nothing in the log.
*/
@(test)
test_rewrite_txt_string_length_limit :: proc(t: ^testing.T) {
	long := strings.repeat("x", 256, context.temp_allocator)
	msg := error_from(strings.concatenate({`["TXT `, long, `"]`}, context.temp_allocator))
	if testing.expect(t, msg != "", "a 256-byte TXT string was accepted") {
		testing.expect(t, strings.contains(msg, "255"), "the message should name the limit")
	}

	// And 255 exactly is fine, the limit being inclusive.
	ok_len := strings.repeat("x", 255, context.temp_allocator)
	rules := rules_from(t, strings.concatenate({`["TXT `, ok_len, `"]`}, context.temp_allocator))
	if testing.expect(t, len(rules) == 1 && len(rules[0].answers) == 1, "expected one answer") {
		testing.expect_value(t, len(rules[0].answers[0].strings[0]), 255)
	}

	free_all(context.temp_allocator)
}
