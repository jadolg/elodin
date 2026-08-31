package server

import "core:mem"
import "core:testing"
import "elodin:cache"
import "elodin:config"
import "elodin:dns"

@(private = "file")
unhex :: proc(text: string, allocator := context.temp_allocator) -> []u8 {
	value :: proc(c: u8) -> u8 {
		switch c {
		case '0' ..= '9':
			return c - '0'
		case 'a' ..= 'f':
			return c - 'a' + 10
		case 'A' ..= 'F':
			return c - 'A' + 10
		}
		return 0
	}
	out := make([]u8, len(text) / 2, allocator)
	for i in 0 ..< len(out) {
		out[i] = value(text[i * 2]) << 4 | value(text[i * 2 + 1])
	}
	return out
}

@(private = "file")
keeper :: proc(secret_hex: string) -> Cookie_Keeper {
	k: Cookie_Keeper
	copy(k.secret[:], unhex(secret_hex))
	return k
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
	k := keeper("e5e973e5a6b2a43f48e7dc849e37bfcf")
	req := request("2464c4abcf10c957", "198.51.100.100:9999")
	got := make_cookie(&k, req, 1559731985)
	want := unhex("2464c4abcf10c957010000005cf79f111f8130c3eee29480")
	testing.expect(t, mem.compare(got[:], want) == 0, "the server cookie does not match RFC 9018 A.1")
	free_all(context.temp_allocator)
}

// A.2: the cookie handed out in A.1 comes back forty minutes later and is ours.
@(test)
test_cookie_rfc9018_a2 :: proc(t: ^testing.T) {
	k := keeper("e5e973e5a6b2a43f48e7dc849e37bfcf")
	req := request("2464c4abcf10c957", "198.51.100.100:9999")

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
	k := keeper("e5e973e5a6b2a43f48e7dc849e37bfcf")
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

	// The secret has rolled since this one was issued, and we keep no history.
	stale := unhex("22681ab97d52c298010000005cf7c57926556bd0934c72f8")
	testing.expect(t, !verify_cookie(&k, stale, req, 1559741961), "a cookie from a retired secret verified")
	free_all(context.temp_allocator)
}

@(test)
test_cookie_rejects_another_address :: proc(t: ^testing.T) {
	k := keeper("e5e973e5a6b2a43f48e7dc849e37bfcf")
	issued := make_cookie(&k, request("2464c4abcf10c957", "198.51.100.100:9999"), 1559731985)

	elsewhere := request("2464c4abcf10c957", "203.0.113.203:9999")
	testing.expect(
		t,
		!verify_cookie(&k, issued[:], elsewhere, 1559731985),
		"a cookie issued to one address verified for another",
	)
	free_all(context.temp_allocator)
}

@(test)
test_cookie_time_window :: proc(t: ^testing.T) {
	k := keeper("e5e973e5a6b2a43f48e7dc849e37bfcf")
	req := request("2464c4abcf10c957", "198.51.100.100:9999")
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
	k := keeper("e5e973e5a6b2a43f48e7dc849e37bfcf")
	req := request("2464c4abcf10c957", "198.51.100.100:9999")
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
	opt := dns.make_opt(1232, false)
	if cookie != nil {
		options := make([]dns.EDNS_Option, 1, context.temp_allocator)
		options[0] = dns.EDNS_Option {
			code = u16(dns.EDNS_Option_Code.Cookie),
			data = cookie,
		}
		opt.data = dns.Rdata_OPT{options = options}
	}
	additional := make([]dns.Record, 1, context.temp_allocator)
	additional[0] = opt
	return dns.Message{id = 1, question = questions, additional = additional}
}

@(test)
test_cookie_inspection :: proc(t: ^testing.T) {
	k := keeper("e5e973e5a6b2a43f48e7dc849e37bfcf")
	client := "198.51.100.100:9999"

	no_cookie := inspect_cookie(&k, query_with_cookie(nil), client)
	testing.expect_value(t, no_cookie.verdict, Cookie_Verdict.Absent)

	// Eight bytes is a client cookie on its own: legal, but nothing to check.
	only_client := inspect_cookie(&k, query_with_cookie(unhex("2464c4abcf10c957")), client)
	testing.expect_value(t, only_client.verdict, Cookie_Verdict.Unproven)

	// Between 9 and 15 bytes, and beyond 40, is malformed (RFC 7873 section 5.2.2).
	bad_lengths := []int{1, 7, 9, 15, 41}
	for bad in bad_lengths {
		req := inspect_cookie(&k, query_with_cookie(make([]u8, bad, context.temp_allocator)), client)
		testing.expectf(t, req.verdict == .Malformed, "a %d-byte cookie was accepted", bad)
	}

	issued := make_cookie(&k, request("2464c4abcf10c957", client), cookie_now())
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
	answer[0] = dns.Record {
		name  = "example.com.",
		type  = .A,
		class = .IN,
		ttl   = 300,
		data  = dns.Rdata_A{addr = {192, 0, 2, 1}},
	}
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
	testing.expect_value(t, senc, dns.Encode_Error.None)

	query := query_with_cookie(c.cookie)
	query.flags.rd = true
	query_wire, _, qenc := dns.encode_message(query, context.temp_allocator)
	testing.expect_value(t, qenc, dns.Encode_Error.None)

	cfg := config.default_config()
	cfg.log.queries = false
	cfg.blocking.enabled = false
	cfg.dnssec.enabled = false
	cfg.cookies.enabled = !c.disabled
	cfg.cookies.require = c.require
	cfg.cookies.secret = "e5e973e5a6b2a43f48e7dc849e37bfcf"

	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600})
	defer cache.destroy(answers)

	s := Server {
		cfg     = &cfg,
		answers = answers,
	}
	if !start_cookies(&s) {
		testing.expect(t, false, "the cookie keeper would not start")
		return nil, false
	}
	defer stop_cookies(&s)

	key_buf: [cache.KEY_MAX]u8
	key := cache.make_key(key_buf[:], "example.com.", .A, .IN, false, false)
	decoded, derr := dns.decode_message(stored_wire, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	if !cache.put(answers, key, stored_wire, decoded) {
		testing.expect(t, false, "the answer was not cached")
		return nil, false
	}

	response, _, served := handle_query(&s, query_wire, c.proto, c.client, context.temp_allocator)
	return response, served
}

@(private = "file")
response_cookie :: proc(wire: []u8) -> (data: []u8, found: bool) {
	m, err := dns.decode_message(wire, context.temp_allocator)
	if err != .None {
		return nil, false
	}
	return dns.find_edns_option(m, .Cookie)
}

@(private = "file")
response_rcode :: proc(wire: []u8) -> dns.Rcode {
	m, err := dns.decode_message(wire, context.temp_allocator)
	if err != .None {
		return .Form_Err
	}
	return dns.rcode_of(m)
}

// A client that has never been here sends eight bytes and gets twenty-four back.
@(test)
test_cookie_roundtrip_issues_one :: proc(t: ^testing.T) {
	client := "198.51.100.100:9999"
	sent := unhex("2464c4abcf10c957")
	out, ok := roundtrip(t, Roundtrip{cookie = sent, client = client, proto = .UDP})
	if !testing.expect(t, ok, "no response") {
		return
	}
	testing.expect_value(t, response_rcode(out), dns.Rcode.No_Error)

	got, found := response_cookie(out)
	if !testing.expect(t, found, "the answer carries no cookie") {
		return
	}
	testing.expect_value(t, len(got), COOKIE_REPLY_LEN)
	testing.expect(t, mem.compare(got[:8], sent) == 0, "the client cookie was not echoed")

	// And it is one this server would accept back.
	k := keeper("e5e973e5a6b2a43f48e7dc849e37bfcf")
	testing.expect(t, verify_cookie(&k, got, request("2464c4abcf10c957", client), cookie_now()), "the issued cookie does not verify")

	free_all(context.temp_allocator)
}

@(test)
test_cookie_roundtrip_leaves_plain_clients_alone :: proc(t: ^testing.T) {
	out, ok := roundtrip(t, Roundtrip{client = "198.51.100.100:9999", proto = .UDP})
	if !testing.expect(t, ok, "no response") {
		return
	}
	_, found := response_cookie(out)
	testing.expect(t, !found, "a client that sent no cookie got one back")
	free_all(context.temp_allocator)
}

@(test)
test_cookie_roundtrip_disabled :: proc(t: ^testing.T) {
	out, ok := roundtrip(
		t,
		Roundtrip{cookie = unhex("2464c4abcf10c957"), client = "198.51.100.100:9999", proto = .UDP, disabled = true},
	)
	if !testing.expect(t, ok, "no response") {
		return
	}
	_, found := response_cookie(out)
	testing.expect(t, !found, "cookies are off but one was sent anyway")
	free_all(context.temp_allocator)
}

@(test)
test_cookie_roundtrip_malformed_is_formerr :: proc(t: ^testing.T) {
	out, ok := roundtrip(
		t,
		Roundtrip{cookie = make([]u8, 9, context.temp_allocator), client = "198.51.100.100:9999", proto = .UDP},
	)
	if !testing.expect(t, ok, "no response") {
		return
	}
	testing.expect_value(t, response_rcode(out), dns.Rcode.Form_Err)
	// There is no telling which bytes were the client cookie, so none go back.
	_, found := response_cookie(out)
	testing.expect(t, !found, "a cookie was invented for a malformed one")
	free_all(context.temp_allocator)
}

@(test)
test_cookie_require_turns_away_unproven_udp :: proc(t: ^testing.T) {
	client := "198.51.100.100:9999"
	out, ok := roundtrip(
		t,
		Roundtrip{cookie = unhex("2464c4abcf10c957"), client = client, proto = .UDP, require = true},
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
	got, found := response_cookie(out)
	if !testing.expect(t, found, "BADCOOKIE without a cookie leaves the client stuck") {
		return
	}
	k := keeper("e5e973e5a6b2a43f48e7dc849e37bfcf")
	req := request("2464c4abcf10c957", client)
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
	client := "198.51.100.100:9999"

	// No cookie at all: not what this setting is about.
	plain, plain_ok := roundtrip(t, Roundtrip{client = client, proto = .UDP, require = true})
	if testing.expect(t, plain_ok, "no response") {
		testing.expect_value(t, response_rcode(plain), dns.Rcode.No_Error)
	}

	// Over TCP the client already proved it can receive at this address.
	stream, stream_ok := roundtrip(
		t,
		Roundtrip{cookie = unhex("2464c4abcf10c957"), client = client, proto = .TCP, require = true},
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
		Roundtrip{cookie = unhex("2464c4abcf10c957"), client = "198.51.100.100:9999", proto = .UDP},
	)
	second, second_ok := roundtrip(
		t,
		Roundtrip{cookie = unhex("fc93fc62807ddb86"), client = "203.0.113.203:9999", proto = .UDP},
	)
	if !testing.expect(t, first_ok && second_ok, "no response") {
		return
	}
	a, a_found := response_cookie(first)
	b, b_found := response_cookie(second)
	if !testing.expect(t, a_found && b_found, "an answer went out without a cookie") {
		return
	}
	testing.expect(t, mem.compare(a, b) != 0, "two clients were handed the same cookie")
	free_all(context.temp_allocator)
}

@(test)
test_cookie_secret_parsing :: proc(t: ^testing.T) {
	secret: [COOKIE_SECRET_LEN]u8
	testing.expect(t, config.parse_cookie_secret("e5e973e5a6b2a43f48e7dc849e37bfcf", &secret), "a valid secret was refused")
	testing.expect(
		t,
		mem.compare(secret[:], unhex("e5e973e5a6b2a43f48e7dc849e37bfcf")) == 0,
		"the secret was decoded wrongly",
	)

	testing.expect(t, !config.parse_cookie_secret("e5e973", &secret), "a short secret was accepted")
	testing.expect(t, !config.parse_cookie_secret("e5e973e5a6b2a43f48e7dc849e37bfcg", &secret), "a non-hex secret was accepted")
	free_all(context.temp_allocator)
}

/*
An address the hash cannot be taken over is not the same as no cookie at all.

Both mean no cookie goes back - there is nothing to bind one to - but the client
did send one, and `require` is a promise not to answer a UDP query this server
cannot vouch for. Folding the two together made that promise fail open on the
one input that cannot be checked.
*/
@(test)
test_cookie_unbindable_address_is_kept_apart :: proc(t: ^testing.T) {
	k := keeper("e5e973e5a6b2a43f48e7dc849e37bfcf")
	sent := unhex("2464c4abcf10c957")

	// A bracketed IPv6 address with no port is in here because `parse_endpoint`
	// takes bare `::1` and refuses `[::1]`, so this is not only reachable
	// through a listener that has lost its mind.
	unbindable := []string{"", "not-an-address", "[::1]", "999.1.1.1", "/run/elodin.sock"}
	for client in unbindable {
		req := inspect_cookie(&k, query_with_cookie(sent), client)
		testing.expectf(t, req.verdict == .Unbindable, "%q gave verdict %v", client, req.verdict)
	}

	// A missing port is not a missing address, and only the host is hashed.
	bindable := []string{"198.51.100.100", "::1", "198.51.100.100:9999", "[::1]:53"}
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
		Roundtrip{cookie = unhex("2464c4abcf10c957"), client = "not-an-address", proto = .UDP, require = true},
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
	_, found := response_cookie(out)
	testing.expect(t, !found, "a cookie was minted for an address it cannot be bound to")

	free_all(context.temp_allocator)
}

// With `require` off the query is still answered, just without a cookie.
@(test)
test_cookie_unbindable_address_is_answered_when_not_required :: proc(t: ^testing.T) {
	out, ok := roundtrip(
		t,
		Roundtrip{cookie = unhex("2464c4abcf10c957"), client = "not-an-address", proto = .UDP},
	)
	if !testing.expect(t, ok, "no response") {
		return
	}
	testing.expect_value(t, response_rcode(out), dns.Rcode.No_Error)
	_, found := response_cookie(out)
	testing.expect(t, !found, "a cookie was minted for an address it cannot be bound to")
	free_all(context.temp_allocator)
}

/*
A cookie is bound to the client's address as the socket reported it.

`cookie_client_ip` hashes `::ffff:a.b.c.d` as the sixteen bytes it arrived as,
and is the one place in the server that does not undo the mapping - `unmap_v4`
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
	k := keeper("e5e973e5a6b2a43f48e7dc849e37bfcf")

	client := request("2464c4abcf10c957", "[::ffff:198.51.100.100]:9999")
	// Sixteen, so the mapping really did survive the parse: a four-byte input
	// here would mean this test was about an IPv4 client and proved nothing.
	testing.expect_value(t, client.ip_len, 16)

	issued := make_cookie(&k, client, 1559731985)
	testing.expect(t, verify_cookie(&k, issued[:], client, 1559731985), "a mapped client's own cookie was rejected")

	unmapped := request("2464c4abcf10c957", "198.51.100.100:9999")
	testing.expect_value(t, unmapped.ip_len, 4)
	testing.expect(
		t,
		!verify_cookie(&k, issued[:], unmapped, 1559731985),
		"the two forms hash alike, so something here is undoing the mapping after all",
	)
	free_all(context.temp_allocator)
}
