package server

import "core:mem"
import "core:testing"
import "core:time"
import "elodin:config"
import "elodin:dns"
import "elodin:loop"

@(private = "file")
keeper :: proc(secret_hex: string) -> Cookie_Keeper {
	key: [COOKIE_SECRET_LEN]u8
	copy(key[:], unhex(secret_hex))
	return secret_keeper(key)
}

@(private = "file")
request :: proc(client_cookie_hex: string, ip: string) -> (req: Cookie_Request) {
	copy(req.client[:], unhex(client_cookie_hex))
	n, ok := cookie_client_ip(ip, req.ip[:])
	if !ok {
		return {}
	}
	req.ip_len = n
	req.verdict = .Unproven
	return req
}

/*
RFC 9018 appendix A.1: a client that has not been here before gets a server
cookie built from its client cookie, the time and its address.
*/
@(test)
test_cookie_rfc9018_a1 :: proc(t: ^testing.T) {
	k := keeper(RFC9018_SECRET)
	req := request(RFC9018_CLIENT_COOKIE, RFC9018_CLIENT)
	got := make_cookie(&k, req, 1559731985)
	want := unhex("2464c4abcf10c957010000005cf79f111f8130c3eee29480")
	testing.expect(t, mem.compare(got[:], want) == 0, "the server cookie does not match RFC 9018 A.1")
	free_all(context.temp_allocator)
}

// A.2: the cookie handed out in A.1 comes back forty minutes later and is ours.
@(test)
test_cookie_rfc9018_a2 :: proc(t: ^testing.T) {
	k := keeper(RFC9018_SECRET)
	req := request(RFC9018_CLIENT_COOKIE, RFC9018_CLIENT)

	sent := unhex("2464c4abcf10c957010000005cf79f111f8130c3eee29480")
	testing.expect(t, verify_cookie(&k, sent, req, 1559734385), "a cookie we issued was rejected")

	got := make_cookie(&k, req, 1559734385)
	want := unhex("2464c4abcf10c957010000005cf7a871d4a564a1442aca77")
	testing.expect(t, mem.compare(got[:], want) == 0, "the renewed cookie does not match RFC 9018 A.2")
	free_all(context.temp_allocator)
}

/*
A.3: the reserved bytes are not ours to assume. They go into the hash as they
arrived, or a cookie some other member of an anycast set issued stops verifying.
*/
@(test)
test_cookie_rfc9018_a3_reserved_bytes :: proc(t: ^testing.T) {
	k := keeper(RFC9018_SECRET)
	req := request("fc93fc62807ddb86", "203.0.113.203:9999")

	sent := unhex("fc93fc62807ddb8601abcdef5cf78f71a314227b6679ebf5")
	// Checked just after the cookie was minted, so only the hash is under test;
	// the age this one has in the RFC's narration is a separate matter.
	testing.expect(t, verify_cookie(&k, sent, req, 1559727985 + 60), "reserved bytes were not hashed as received")

	// What we hand back has them zeroed, as this version requires.
	got := make_cookie(&k, req, 1559734700)
	want := unhex("fc93fc62807ddb86010000005cf7a9acf73a7810aca2381e")
	testing.expect(t, mem.compare(got[:], want) == 0, "the renewed cookie does not match RFC 9018 A.3")
	free_all(context.temp_allocator)
}

// A.4: an IPv6 client, so the hash input is 32 bytes rather than 20.
@(test)
test_cookie_rfc9018_a4_ipv6 :: proc(t: ^testing.T) {
	k := keeper("445536bcd2513298075a5d379663c962")
	req := request("22681ab97d52c298", "[2001:db8:220:1:59de:d0f4:8769:82b8]:9999")
	testing.expect_value(t, req.ip_len, 16)

	got := make_cookie(&k, req, 1559741961)
	want := unhex("22681ab97d52c298010000005cf7c609a6bb79d16625507a")
	testing.expect(t, mem.compare(got[:], want) == 0, "the server cookie does not match RFC 9018 A.4")

	// Issued under a secret this keeper does not hold.
	stale := unhex("22681ab97d52c298010000005cf7c57926556bd0934c72f8")
	testing.expect(t, !verify_cookie(&k, stale, req, 1559741961), "a cookie from a retired secret verified")
	free_all(context.temp_allocator)
}

@(test)
test_cookie_rejects_another_address :: proc(t: ^testing.T) {
	k := keeper(RFC9018_SECRET)
	issued := make_cookie(&k, request(RFC9018_CLIENT_COOKIE, RFC9018_CLIENT), 1559731985)

	elsewhere := request(RFC9018_CLIENT_COOKIE, "203.0.113.203:9999")
	testing.expect(
		t,
		!verify_cookie(&k, issued[:], elsewhere, 1559731985),
		"a cookie issued to one address verified for another",
	)
	free_all(context.temp_allocator)
}

@(test)
test_cookie_time_window :: proc(t: ^testing.T) {
	k := keeper(RFC9018_SECRET)
	req := request(RFC9018_CLIENT_COOKIE, RFC9018_CLIENT)
	issued := make_cookie(&k, req, 1_000_000)

	testing.expect(t, verify_cookie(&k, issued[:], req, 1_000_000 + COOKIE_MAX_AGE), "a cookie inside the window failed")
	testing.expect(
		t,
		!verify_cookie(&k, issued[:], req, 1_000_000 + COOKIE_MAX_AGE + 1),
		"an expired cookie verified",
	)
	testing.expect(
		t,
		verify_cookie(&k, issued[:], req, 1_000_000 - COOKIE_MAX_SKEW),
		"a cookie from a slightly fast peer failed",
	)
	testing.expect(
		t,
		!verify_cookie(&k, issued[:], req, 1_000_000 - COOKIE_MAX_SKEW - 1),
		"a cookie from the future verified",
	)
	free_all(context.temp_allocator)
}

@(test)
test_cookie_rejects_odd_lengths :: proc(t: ^testing.T) {
	k := keeper(RFC9018_SECRET)
	req := request(RFC9018_CLIENT_COOKIE, RFC9018_CLIENT)
	issued := make_cookie(&k, req, 1_000_000)

	// RFC 9018 section 4.4 requires exactly 24 bytes before a version 1 cookie
	// may be verified at all, so the hash input stays an injective function of
	// its parts.
	testing.expect(t, !verify_cookie(&k, issued[:23], req, 1_000_000), "a short cookie verified")

	padded := make([]u8, 25, context.temp_allocator)
	copy(padded, issued[:])
	testing.expect(t, !verify_cookie(&k, padded, req, 1_000_000), "an over-long cookie verified")

	wrong_version := make([]u8, 24, context.temp_allocator)
	copy(wrong_version, issued[:])
	wrong_version[8] = 2
	testing.expect(t, !verify_cookie(&k, wrong_version, req, 1_000_000), "an unknown cookie version verified")
	free_all(context.temp_allocator)
}

@(private = "file")
query_with_cookie :: proc(cookie: []u8) -> dns.Message {
	questions := make([]dns.Question, 1, context.temp_allocator)
	questions[0] = dns.Question {
		name  = "example.com.",
		type  = .A,
		class = .IN,
	}
	opt := dns.make_opt(1232, false) if cookie == nil else opt_with(.Cookie, cookie)
	additional := make([]dns.Record, 1, context.temp_allocator)
	additional[0] = opt
	return dns.Message{id = 1, question = questions, additional = additional}
}

@(test)
test_cookie_inspection :: proc(t: ^testing.T) {
	k := keeper(RFC9018_SECRET)
	client := RFC9018_CLIENT

	no_cookie := inspect_cookie(&k, query_with_cookie(nil), client)
	testing.expect_value(t, no_cookie.verdict, Cookie_Verdict.Absent)

	// Eight bytes is a client cookie on its own: legal, but nothing to check.
	only_client := inspect_cookie(&k, query_with_cookie(unhex(RFC9018_CLIENT_COOKIE)), client)
	testing.expect_value(t, only_client.verdict, Cookie_Verdict.Unproven)

	// Shorter than 8, between 9 and 15, or beyond 40 is malformed (RFC 7873
	// section 5.2.2).
	bad_lengths := []int{1, 7, 9, 15, 41}
	for bad in bad_lengths {
		req := inspect_cookie(&k, query_with_cookie(make([]u8, bad, context.temp_allocator)), client)
		testing.expectf(t, req.verdict == .Malformed, "a %d-byte cookie was accepted", bad)
	}

	issued := make_cookie(&k, request(RFC9018_CLIENT_COOKIE, client), cookie_now())
	good := inspect_cookie(&k, query_with_cookie(issued[:]), client)
	testing.expect_value(t, good.verdict, Cookie_Verdict.Valid)

	forged := make([]u8, 24, context.temp_allocator)
	copy(forged, issued[:])
	forged[23] ~= 0xff
	testing.expect_value(t, inspect_cookie(&k, query_with_cookie(forged), client).verdict, Cookie_Verdict.Unproven)

	free_all(context.temp_allocator)
}

@(private = "file")
Roundtrip :: struct {
	// The COOKIE option as the client sent it; nil for a query without one.
	cookie:   []u8,
	client:   string,
	proto:    Protocol,
	disabled: bool,
	require:  bool,
	// How many copies of the question the query carries; nil is the usual one.
	// Zero is the RFC 7873 section 5.4 priming shape.
	questions: Maybe(int),
	id:        Maybe(u16),
}

/*
Answer one query from the cache, so the whole client-facing path runs without an
upstream behind it.
*/
@(private = "file")
roundtrip :: proc(t: ^testing.T, c: Roundtrip) -> (out: []u8, ok: bool) {
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question {
		name  = "example.com.",
		type  = .A,
		class = .IN,
	}

	answer := make([]dns.Record, 1, context.temp_allocator)
	answer[0] = a_record("example.com.", {192, 0, 2, 1}, ttl = 300)
	stored_opt := make([]dns.Record, 1, context.temp_allocator)
	stored_opt[0] = dns.make_opt(1232, false)
	stored := dns.Message {
		id         = 0x4242,
		question   = question,
		answer     = answer,
		additional = stored_opt,
	}
	stored.flags.qr = true
	stored.flags.ra = true
	stored_wire, _, senc := dns.encode_message(stored, context.temp_allocator)
	if !testing.expect_value(t, senc, dns.Encode_Error.None) {
		return nil, false
	}

	query := query_with_cookie(c.cookie)
	query.flags.rd = true
	if n, set := c.questions.?; set {
		qs := make([]dns.Question, n, context.temp_allocator)
		for &q in qs {
			q = question[0]
		}
		query.question = qs
	}
	if id, set := c.id.?; set {
		query.id = id
	}
	query_wire, _, qenc := dns.encode_message(query, context.temp_allocator)
	if !testing.expect_value(t, qenc, dns.Encode_Error.None) {
		return nil, false
	}
	return cookie_roundtrip(t, "example.com.", stored_wire, query_wire, c.proto, c.client, enabled = !c.disabled, require = c.require)
}

@(private = "file")
response_rcode :: proc(wire: []u8) -> dns.Rcode {
	m, err := dns.decode_message(wire, context.temp_allocator)
	if err != .None {
		// No rcode at all, so that a reply that does not decode can never pass
		// for the FORMERR a case expects.
		return dns.Rcode(max(u16))
	}
	return dns.rcode_of(m)
}

// A client that has never been here sends eight bytes and gets twenty-four back.
@(test)
test_cookie_roundtrip_issues_one :: proc(t: ^testing.T) {
	client := RFC9018_CLIENT
	sent := unhex(RFC9018_CLIENT_COOKIE)
	out, ok := roundtrip(t, Roundtrip{cookie = sent, client = client, proto = .UDP})
	if !testing.expect(t, ok, "no response") {
		return
	}
	testing.expect_value(t, response_rcode(out), dns.Rcode.No_Error)

	got, found := dns.peek_edns_option(out, .Cookie)
	if !testing.expect(t, found, "the answer carries no cookie") {
		return
	}
	testing.expect_value(t, len(got), COOKIE_REPLY_LEN)
	testing.expect(t, mem.compare(got[:8], sent) == 0, "the client cookie was not echoed")

	// And it is one this server would accept back.
	k := keeper(RFC9018_SECRET)
	testing.expect(t, verify_cookie(&k, got, request(RFC9018_CLIENT_COOKIE, client), cookie_now()), "the issued cookie does not verify")

	free_all(context.temp_allocator)
}

@(test)
test_cookie_roundtrip_leaves_plain_clients_alone :: proc(t: ^testing.T) {
	out, ok := roundtrip(t, Roundtrip{client = RFC9018_CLIENT, proto = .UDP})
	if !testing.expect(t, ok, "no response") {
		return
	}
	_, found := dns.peek_edns_option(out, .Cookie)
	testing.expect(t, !found, "a client that sent no cookie got one back")
	free_all(context.temp_allocator)
}

@(test)
test_cookie_roundtrip_disabled :: proc(t: ^testing.T) {
	out, ok := roundtrip(
		t,
		Roundtrip{cookie = unhex(RFC9018_CLIENT_COOKIE), client = RFC9018_CLIENT, proto = .UDP, disabled = true},
	)
	if !testing.expect(t, ok, "no response") {
		return
	}
	_, found := dns.peek_edns_option(out, .Cookie)
	testing.expect(t, !found, "cookies are off but one was sent anyway")
	free_all(context.temp_allocator)
}

@(test)
test_cookie_roundtrip_malformed_is_formerr :: proc(t: ^testing.T) {
	out, ok := roundtrip(
		t,
		Roundtrip{cookie = make([]u8, 9, context.temp_allocator), client = RFC9018_CLIENT, proto = .UDP},
	)
	if !testing.expect(t, ok, "no response") {
		return
	}
	testing.expect_value(t, response_rcode(out), dns.Rcode.Form_Err)
	// There is no telling which bytes were the client cookie, so none go back.
	_, found := dns.peek_edns_option(out, .Cookie)
	testing.expect(t, !found, "a cookie was invented for a malformed one")
	free_all(context.temp_allocator)
}

@(test)
test_cookie_require_turns_away_unproven_udp :: proc(t: ^testing.T) {
	client := RFC9018_CLIENT
	out, ok := roundtrip(
		t,
		Roundtrip{cookie = unhex(RFC9018_CLIENT_COOKIE), client = client, proto = .UDP, require = true},
	)
	if !testing.expect(t, ok, "no response") {
		return
	}
	testing.expect_value(t, response_rcode(out), dns.Rcode.Bad_Cookie)

	m, derr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	testing.expect_value(t, len(m.answer), 0)

	// The refusal has to carry the cookie to come back with, or the client has
	// no way past it.
	got, found := dns.peek_edns_option(out, .Cookie)
	if !testing.expect(t, found, "BADCOOKIE without a cookie leaves the client stuck") {
		return
	}
	k := keeper(RFC9018_SECRET)
	req := request(RFC9018_CLIENT_COOKIE, client)
	testing.expect(t, verify_cookie(&k, got, req, cookie_now()), "the cookie handed out with BADCOOKIE does not verify")

	// Coming back with it gets an answer.
	second, second_ok := roundtrip(t, Roundtrip{cookie = got, client = client, proto = .UDP, require = true})
	if !testing.expect(t, second_ok, "no response to the retry") {
		return
	}
	testing.expect_value(t, response_rcode(second), dns.Rcode.No_Error)

	free_all(context.temp_allocator)
}

@(test)
test_cookie_require_spares_plain_and_stream_clients :: proc(t: ^testing.T) {
	client := RFC9018_CLIENT

	// No cookie at all: not what this setting is about.
	plain, plain_ok := roundtrip(t, Roundtrip{client = client, proto = .UDP, require = true})
	if testing.expect(t, plain_ok, "no response") {
		testing.expect_value(t, response_rcode(plain), dns.Rcode.No_Error)
	}

	// Over TCP the client already proved it can receive at this address.
	stream, stream_ok := roundtrip(
		t,
		Roundtrip{cookie = unhex(RFC9018_CLIENT_COOKIE), client = client, proto = .TCP, require = true},
	)
	if testing.expect(t, stream_ok, "no response") {
		testing.expect_value(t, response_rcode(stream), dns.Rcode.No_Error)
	}

	free_all(context.temp_allocator)
}

/*
The cookie belongs to the client, not to the answer, so a cached entry must not
carry one client's cookie out to the next.
*/
@(test)
test_cookie_is_not_shared_through_the_cache :: proc(t: ^testing.T) {
	first, first_ok := roundtrip(
		t,
		Roundtrip{cookie = unhex(RFC9018_CLIENT_COOKIE), client = RFC9018_CLIENT, proto = .UDP},
	)
	second, second_ok := roundtrip(
		t,
		Roundtrip{cookie = unhex("fc93fc62807ddb86"), client = "203.0.113.203:9999", proto = .UDP},
	)
	if !testing.expect(t, first_ok && second_ok, "no response") {
		return
	}
	a, a_found := dns.peek_edns_option(first, .Cookie)
	b, b_found := dns.peek_edns_option(second, .Cookie)
	if !testing.expect(t, a_found && b_found, "an answer went out without a cookie") {
		return
	}
	testing.expect(t, mem.compare(a, b) != 0, "two clients were handed the same cookie")
	free_all(context.temp_allocator)
}

@(test)
test_cookie_secret_parsing :: proc(t: ^testing.T) {
	secret: [COOKIE_SECRET_LEN]u8
	testing.expect(t, config.parse_cookie_secret(RFC9018_SECRET, &secret), "a valid secret was refused")
	want := RFC9018_SECRET_KEY
	testing.expect(t, secret == want, "the secret was decoded wrongly")
	testing.expect(t, config.parse_cookie_secret("E5E973E5A6B2A43F48E7DC849E37BFCF", &secret), "an upper-case secret was refused")
	testing.expect(t, secret == want, "the upper-case secret was decoded wrongly")

	testing.expect(t, !config.parse_cookie_secret("e5e973", &secret), "a short secret was accepted")
	testing.expect(t, !config.parse_cookie_secret("e5e973e5a6b2a43f48e7dc849e37bfcg", &secret), "a non-hex secret was accepted")
	// `hex.decode_sequence`, which reads each pair, takes a `0x` prefix off
	// before it looks: a pair that is the prefix is not a byte.
	testing.expect(t, !config.parse_cookie_secret("0xe973e5a6b2a43f48e7dc849e37bfcf", &secret), "a 0x pair was accepted")
	testing.expect(t, !config.parse_cookie_secret("e5e973e5a6b2a43f48e7dc849e37bf0X", &secret), "a 0X pair was accepted")
	testing.expect(t, !config.parse_cookie_secret("+5e973e5a6b2a43f48e7dc849e37bfcf", &secret), "a sign was accepted")
	free_all(context.temp_allocator)
}

/*
An address the hash cannot be taken over is not the same as no cookie at all.

Both mean no cookie goes back - there is nothing to bind one to - but the client
did send one, and `require` is a promise not to answer a UDP query this server
cannot vouch for. Read as no cookie, an unbindable address would be answered
under `require`, which is the promise failing open on the one input that cannot
be checked.
*/
@(test)
test_cookie_unbindable_address_is_kept_apart :: proc(t: ^testing.T) {
	k := keeper(RFC9018_SECRET)
	sent := unhex(RFC9018_CLIENT_COOKIE)

	// An unclosed bracket is in here so a bracketed form is: `[::1]` binds as
	// `::1` does.
	unbindable := []string{"", "not-an-address", "[::1", "999.1.1.1", "/run/elodin.sock"}
	for client in unbindable {
		req := inspect_cookie(&k, query_with_cookie(sent), client)
		testing.expectf(t, req.verdict == .Unbindable, "%q gave verdict %v", client, req.verdict)
	}

	// A missing port is not a missing address, and only the host is hashed.
	bindable := []string{"198.51.100.100", "::1", RFC9018_CLIENT, "[::1]:53", "[::1]"}
	for client in bindable {
		req := inspect_cookie(&k, query_with_cookie(sent), client)
		testing.expectf(t, req.verdict == .Unproven, "%q gave verdict %v", client, req.verdict)
	}

	// No COOKIE option is still Absent, whatever the address.
	testing.expect_value(t, inspect_cookie(&k, query_with_cookie(nil), "").verdict, Cookie_Verdict.Absent)

	free_all(context.temp_allocator)
}

// The gate is asked as "not proven", so a verdict it cannot vouch for is refused
// rather than having to be listed.
@(test)
test_cookie_require_refuses_everything_unproven :: proc(t: ^testing.T) {
	k := Cookie_Keeper {
		require = true,
	}
	testing.expect(t, cookie_must_be_refused(&k, Cookie_Request{verdict = .Unproven}, .UDP), "Unproven was let through")
	testing.expect(
		t,
		cookie_must_be_refused(&k, Cookie_Request{verdict = .Unbindable}, .UDP),
		"an address no cookie can be bound to was let through",
	)
	testing.expect(t, !cookie_must_be_refused(&k, Cookie_Request{verdict = .Valid}, .UDP), "a valid cookie was refused")
	testing.expect(
		t,
		!cookie_must_be_refused(&k, Cookie_Request{verdict = .Absent}, .UDP),
		"a client that sent no cookie was refused",
	)

	// Only UDP, and only when asked for.
	testing.expect(t, !cookie_must_be_refused(&k, Cookie_Request{verdict = .Unproven}, .TCP), "TCP was gated")
	off := Cookie_Keeper{}
	testing.expect(t, !cookie_must_be_refused(&off, Cookie_Request{verdict = .Unproven}, .UDP), "require is off")
	testing.expect(t, !cookie_must_be_refused(nil, Cookie_Request{verdict = .Unproven}, .UDP), "cookies are off")
}

// End to end: the whole client-facing path, with an address the listener could
// not have written but the gate must survive anyway.
@(test)
test_cookie_require_turns_away_an_unbindable_address :: proc(t: ^testing.T) {
	out, ok := roundtrip(
		t,
		Roundtrip{cookie = unhex(RFC9018_CLIENT_COOKIE), client = "not-an-address", proto = .UDP, require = true},
	)
	if !testing.expect(t, ok, "no response") {
		return
	}
	testing.expect_value(t, response_rcode(out), dns.Rcode.Bad_Cookie)

	m, derr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	testing.expect_value(t, len(m.answer), 0)

	// And no cookie with it: there is no address to bind one to, so there is
	// nothing honest to hand back.
	_, found := dns.peek_edns_option(out, .Cookie)
	testing.expect(t, !found, "a cookie was minted for an address it cannot be bound to")

	free_all(context.temp_allocator)
}

// With `require` off the query is still answered, just without a cookie.
@(test)
test_cookie_unbindable_address_is_answered_when_not_required :: proc(t: ^testing.T) {
	out, ok := roundtrip(
		t,
		Roundtrip{cookie = unhex(RFC9018_CLIENT_COOKIE), client = "not-an-address", proto = .UDP},
	)
	if !testing.expect(t, ok, "no response") {
		return
	}
	testing.expect_value(t, response_rcode(out), dns.Rcode.No_Error)
	_, found := dns.peek_edns_option(out, .Cookie)
	testing.expect(t, !found, "a cookie was minted for an address it cannot be bound to")
	free_all(context.temp_allocator)
}

/*
A cookie is bound to the client's address as the socket reported it.

`cookie_client_ip` hashes `::ffff:a.b.c.d` as the sixteen bytes it arrived as,
and is the one place in the server that does not undo the mapping - `netx.unmap_bytes`
undoes it for the rate limiter and for loopback, and `config.address_bytes` for
the ACL. What is decided here is only whether a cookie this server issued came
back from the address it was issued to, and a client returns to the socket that
issued it, which reports it the same way both times.

So both halves are asserted: a mapped client's own cookie verifies, and the two
spellings are not interchangeable. The second is the deliberate part. Unmapping
would make them interchangeable, would be harmless, and would invalidate every
cookie in flight at the upgrade - so if a later change unmaps here for
consistency's sake, this is the test that should be read before it is deleted.
*/
@(test)
test_a_cookie_is_bound_to_the_address_as_reported :: proc(t: ^testing.T) {
	k := keeper(RFC9018_SECRET)

	client := request(RFC9018_CLIENT_COOKIE, "[::ffff:198.51.100.100]:9999")
	// Sixteen, so the mapping really did survive the parse: a four-byte input
	// here would mean this test was about an IPv4 client and proved nothing.
	testing.expect_value(t, client.ip_len, 16)

	issued := make_cookie(&k, client, 1559731985)
	testing.expect(t, verify_cookie(&k, issued[:], client, 1559731985), "a mapped client's own cookie was rejected")

	unmapped := request(RFC9018_CLIENT_COOKIE, RFC9018_CLIENT)
	testing.expect_value(t, unmapped.ip_len, 4)
	testing.expect(
		t,
		!verify_cookie(&k, issued[:], unmapped, 1559731985),
		"the two forms hash alike, so something here is undoing the mapping after all",
	)
	free_all(context.temp_allocator)
}

/*
RFC 7873 section 5.4: a QUERY with no question and a COOKIE option asks for a
server cookie and nothing else. A client cookie alone, or one with a valid
server cookie behind it, SHALL be answered NOERROR; one with a server cookie
that does not check out SHALL be answered BADCOOKIE. Either way the answer is
empty and carries a fresh cookie.
*/
@(private = "file")
expect_primed :: proc(t: ^testing.T, out: []u8, rcode: dns.Rcode, client: string, loc := #caller_location) {
	m, derr := dns.decode_message(out, context.temp_allocator)
	if !testing.expect_value(t, derr, dns.Decode_Error.None, loc) {
		return
	}
	testing.expect_value(t, dns.rcode_of(m), rcode, loc)
	testing.expect_value(t, len(m.question), 0, loc)
	testing.expect_value(t, len(m.answer), 0, loc)
	testing.expect_value(t, len(m.authority), 0, loc)
	got, found := dns.find_edns_option(m, .Cookie)
	if !testing.expect(t, found, "a priming answer carries no cookie", loc = loc) {
		return
	}
	testing.expect_value(t, len(got), COOKIE_REPLY_LEN, loc)
	k := keeper(RFC9018_SECRET)
	testing.expect(t, verify_cookie(&k, got, request(RFC9018_CLIENT_COOKIE, client), cookie_now()), "the primed cookie does not verify", loc = loc)
}

@(test)
test_cookie_priming_query :: proc(t: ^testing.T) {
	client := RFC9018_CLIENT
	sent := unhex(RFC9018_CLIENT_COOKIE)

	out, ok := roundtrip(t, Roundtrip{cookie = sent, client = client, proto = .UDP, questions = 0})
	if testing.expect(t, ok, "no response") {
		expect_primed(t, out, .No_Error, client)
	}

	// `require` has nothing to protect when nothing is looked up, and the SHALL
	// above leaves no room for BADCOOKIE on a client cookie alone.
	required, required_ok := roundtrip(t, Roundtrip{cookie = sent, client = client, proto = .UDP, questions = 0, require = true})
	if testing.expect(t, required_ok, "no response under require") {
		expect_primed(t, required, .No_Error, client)
	}

	// An id of zero takes `error_response` down its header-only fallback, which
	// has no OPT record for the cookie to go into until one is made for it.
	zero, zero_ok := roundtrip(t, Roundtrip{cookie = sent, client = client, proto = .UDP, questions = 0, id = 0})
	if testing.expect(t, zero_ok, "no response to id 0") {
		expect_primed(t, zero, .No_Error, client)
	}

	// Confirming a server cookie already held.
	k := keeper(RFC9018_SECRET)
	issued := make_cookie(&k, request(RFC9018_CLIENT_COOKIE, client), cookie_now())
	valid, valid_ok := roundtrip(t, Roundtrip{cookie = issued[:], client = client, proto = .UDP, questions = 0})
	if testing.expect(t, valid_ok, "no response to a valid cookie") {
		expect_primed(t, valid, .No_Error, client)
	}

	forged := make([]u8, COOKIE_REPLY_LEN, context.temp_allocator)
	copy(forged, issued[:])
	forged[23] ~= 0xff
	bad, bad_ok := roundtrip(t, Roundtrip{cookie = forged, client = client, proto = .UDP, questions = 0})
	if testing.expect(t, bad_ok, "no response to a forged cookie") {
		expect_primed(t, bad, .Bad_Cookie, client)
	}

	free_all(context.temp_allocator)
}

// Section 5.4 extends QUERY for a cookie and nothing else: any other question
// count, or no cookie to give - cookies off, or a client address none can be
// bound to - is still FORMERR.
@(test)
test_cookie_priming_needs_a_cookie_and_no_question :: proc(t: ^testing.T) {
	client := RFC9018_CLIENT
	sent := unhex(RFC9018_CLIENT_COOKIE)
	cases := []Roundtrip {
		{client = client, proto = .UDP, questions = 0},
		{cookie = sent, client = client, proto = .UDP, questions = 0, disabled = true},
		{cookie = sent, client = client, proto = .UDP, questions = 2},
		{cookie = make([]u8, 9, context.temp_allocator), client = client, proto = .UDP, questions = 0},
		{cookie = sent, client = "not-an-address", proto = .UDP, questions = 0},
	}
	for c, i in cases {
		out, ok := roundtrip(t, c)
		if testing.expectf(t, ok, "case %d: no response", i) {
			rcode := response_rcode(out)
			testing.expectf(t, rcode == .Form_Err, "case %d: rcode %v", i, rcode)
		}
	}
	free_all(context.temp_allocator)
}

/*
A drawn secret is replaced once its lifetime is up (RFC 7873 section 7.1). The
cookie issued after that is under the new secret, the one issued before it is
still correct for `COOKIE_ROLLOVER_GRACE` seconds and not a second more, and
the next rollover is a lifetime away, less the jitter.
*/
@(test)
test_a_drawn_secret_rolls_over :: proc(t: ^testing.T) {
	ROLL :: u32(1_000_000)
	k := keeper(RFC9018_SECRET)
	k.secrets.next_roll = loop.moment_add(loop.moment_now(), time.Hour)
	req := request(RFC9018_CLIENT_COOKIE, RFC9018_CLIENT)

	// Due an hour from now on the boot clock: the wall clock reading a day
	// later, as after a step, does not bring it forward.
	before := make_cookie(&k, req, ROLL - 1)
	testing.expect_value(t, k.secrets.epoch, 0)
	_ = make_cookie(&k, req, ROLL - 1 + 86_400) // lint:allow only the epoch it leaves is under test
	testing.expect_value(t, k.secrets.epoch, 0)

	k.secrets.next_roll = loop.moment_add(loop.moment_now(), -time.Second)
	after := make_cookie(&k, req, ROLL)
	testing.expect_value(t, k.secrets.epoch, 1)
	unrolled := keeper(RFC9018_SECRET)
	under_old := make_cookie(&unrolled, req, ROLL)
	testing.expect(t, mem.compare(after[16:], under_old[16:]) != 0, "the cookie after the rollover is under the old secret")

	lifetime := time.Duration(dns.COOKIE_SECRET_LIFETIME) * time.Second
	shortest := lifetime * (100 - dns.COOKIE_SECRET_JITTER) / 100
	next := time.Duration(k.secrets.next_roll - loop.moment_now())
	testing.expectf(t, next >= shortest - time.Minute && next <= lifetime, "the next rollover is %v away", next)

	testing.expect(t, verify_cookie(&k, before[:], req, ROLL + COOKIE_ROLLOVER_GRACE), "a cookie under the previous secret failed inside the grace")
	testing.expect(t, !verify_cookie(&k, before[:], req, ROLL + COOKIE_ROLLOVER_GRACE + 1), "a cookie under the previous secret verified past the grace")
	testing.expect(t, verify_cookie(&k, after[:], req, ROLL + COOKIE_ROLLOVER_GRACE + 1), "a cookie under the new secret failed")
	// A thread whose clock read came a moment before the rolling thread's.
	testing.expect(t, verify_cookie(&k, before[:], req, ROLL - 1), "a cookie under the previous secret failed for a reader a second behind the rollover")
	// A clock stepped back further than the skew cookies allow does not
	// stretch the grace.
	testing.expect(t, !verify_cookie(&k, before[:], req, ROLL - COOKIE_MAX_SKEW - 1), "the grace stretched over a clock stepped back")

	// A configured secret has no rollover scheduled, and is never replaced.
	configured := keeper(RFC9018_SECRET)
	far := make_cookie(&configured, req, ROLL * 4000)
	testing.expect_value(t, configured.secrets.epoch, 0)
	far_unrolled := make_cookie(&unrolled, req, ROLL * 4000)
	testing.expect(t, mem.compare(far[:], far_unrolled[:]) == 0, "a configured secret was replaced")
	free_all(context.temp_allocator)
}

/*
`cookies.previous_secret` is accepted on the cookies clients return and never
issued under: RFC 9018 section 5's stages 1 and 2 of a shared secret's change.
*/
@(test)
test_a_previous_secret_is_accepted_and_not_issued :: proc(t: ^testing.T) {
	req := request(RFC9018_CLIENT_COOKIE, RFC9018_CLIENT)
	other := keeper("000102030405060708090a0b0c0d0e0f")
	from_other := make_cookie(&other, req, 1_000_000)

	k := keeper(RFC9018_SECRET)
	testing.expect(t, !verify_cookie(&k, from_other[:], req, 1_000_000), "the premise: a cookie under another secret verified")
	copy(k.accepted[:], unhex("000102030405060708090a0b0c0d0e0f"))
	k.has_accepted = true
	testing.expect(t, verify_cookie(&k, from_other[:], req, 1_000_000), "a cookie under the previous secret was refused")

	issued := make_cookie(&k, req, 1_000_000)
	plain := keeper(RFC9018_SECRET)
	want := make_cookie(&plain, req, 1_000_000)
	testing.expect(t, mem.compare(issued[:], want[:]) == 0, "a cookie was issued under the previous secret")
	free_all(context.temp_allocator)
}
