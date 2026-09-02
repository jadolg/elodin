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
	rules := rules_from(t, `["A 192.168.1.50", "AAAA fd00::1", "CNAME new.example.com"]`)
	if !testing.expect(t, len(rules) == 1 && len(rules[0].answers) == 3, "expected three answers") {
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
	testing.expect_value(t, rules[0].answers[2].kind, Rewrite_Kind.CNAME)
	testing.expect_value(t, rules[0].answers[2].name, "new.example.com.")

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
	rules := rules_from(t, `[192.168.1.50, "fd00::10", new.example.com, block]`)
	if !testing.expect(t, len(rules) == 1 && len(rules[0].answers) == 4, "expected four answers") {
		return
	}
	testing.expect_value(t, rules[0].answers[0].kind, Rewrite_Kind.A)
	testing.expect_value(t, rules[0].answers[1].kind, Rewrite_Kind.AAAA)
	testing.expect_value(t, rules[0].answers[2].kind, Rewrite_Kind.CNAME)
	testing.expect_value(t, rules[0].answers[2].name, "new.example.com.")
	testing.expect_value(t, rules[0].answers[3].kind, Rewrite_Kind.Block)

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
