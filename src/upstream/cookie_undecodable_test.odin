package upstream

import "core:mem"
import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:dns"

/*
The cookie check must not be one a reply can shape its way out of.

`response_matches` reads the header and the first question and stops, so the set
of replies this server accepts is wider than the set that decodes. Every message
below sits in the gap: well formed as far as the matcher looks, unreadable after
that. If the cookie check only judges what decodes, an attacker that has guessed
the transaction ID and the source port truncates the body and is never asked for
the 64 bits the cookie was added to demand.

Built byte by byte rather than encoded, because what is under test is exactly the
messages an encoder will not produce.
*/

@(private = "file")
QNAME :: []u8{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}

@(private = "file")
CLIENT_COOKIE :: []u8{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7}

@(private = "file")
SERVER_COOKIE :: []u8{0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7}

// A reply to "example.com. A IN", with whatever the caller wants behind the
// question and whatever section counts it wants to claim.
@(private = "file")
crafted :: proc(qdcount, ancount, arcount: u16, tail: ..[]u8) -> []u8 {
	b := make([dynamic]u8, 0, 128, context.temp_allocator)
	append(&b, 0x2a, 0x2a) // id, the one `probe_query` sends
	append(&b, 0x81, 0x80) // QR RD RA
	append(&b, u8(qdcount >> 8), u8(qdcount))
	append(&b, u8(ancount >> 8), u8(ancount))
	append(&b, 0x00, 0x00) // nscount
	append(&b, u8(arcount >> 8), u8(arcount))
	append(&b, ..QNAME)
	append(&b, 0x00, 0x01, 0x00, 0x01) // A IN
	for part in tail {
		append(&b, ..part)
	}
	return b[:]
}

// An A record answering the question, with the RDLENGTH the caller asks for in
// front of its four bytes of address.
@(private = "file")
crafted_a :: proc(rdlength: u16) -> []u8 {
	b := make([dynamic]u8, 0, 32, context.temp_allocator)
	append(&b, 0xc0, 0x0c)             // owner: a pointer at the question
	append(&b, 0x00, 0x01, 0x00, 0x01) // A IN
	append(&b, 0x00, 0x00, 0x00, 0x3c) // ttl 60
	append(&b, u8(rdlength >> 8), u8(rdlength))
	append(&b, 192, 0, 2, 1)
	return b[:]
}

/*
The same record with an owner name that is a compression pointer aimed forwards.

RFC 1035 4.1.4 pointers go backwards, so the decoder refuses it - while a walk
over the record boundaries steps across the two bytes without following them.
The message is therefore readable to everything that matches a reply and
unreadable to everything that decodes one, which is the gap itself.
*/
@(private = "file")
crafted_forward_pointer :: proc() -> []u8 {
	b := make([dynamic]u8, 0, 32, context.temp_allocator)
	append(&b, 0xc0, 0xff)             // owner: a pointer past its own position
	append(&b, 0x00, 0x01, 0x00, 0x01) // A IN
	append(&b, 0x00, 0x00, 0x00, 0x3c) // ttl 60
	append(&b, 0x00, 0x04)
	append(&b, 192, 0, 2, 1)
	return b[:]
}

// An OPT record whose RDATA is exactly the bytes given, so an option list that
// does not tile can be written on purpose.
@(private = "file")
crafted_opt :: proc(rdlength: Maybe(u16), options: ..[]u8) -> []u8 {
	b := make([dynamic]u8, 0, 48, context.temp_allocator)
	append(&b, 0)                      // root owner name
	append(&b, 0x00, 0x29)             // OPT
	append(&b, 0x04, 0xd0)             // 1232
	append(&b, 0x00, 0x00, 0x00, 0x00) // extended rcode, version, flags
	n := 0
	for part in options {
		n += len(part)
	}
	claimed := rdlength.? or_else u16(n)
	append(&b, u8(claimed >> 8), u8(claimed))
	for part in options {
		append(&b, ..part)
	}
	return b[:]
}

@(private = "file")
crafted_cookie_option :: proc(parts: ..[]u8) -> []u8 {
	b := make([dynamic]u8, 0, 48, context.temp_allocator)
	n := 0
	for part in parts {
		n += len(part)
	}
	append(&b, 0x00, 0x0a) // COOKIE
	append(&b, u8(n >> 8), u8(n))
	for part in parts {
		append(&b, ..part)
	}
	return b[:]
}

// The query these replies are answers to: "example.com. A IN" with an OPT
// record, which is what a cookie needs somewhere to live.
@(private = "file")
probe_query :: proc() -> []u8 {
	questions := make([]dns.Question, 1, context.temp_allocator)
	questions[0] = dns.Question {
		name  = "example.com.",
		type  = .A,
		class = .IN,
	}
	additional := make([]dns.Record, 1, context.temp_allocator)
	additional[0] = dns.make_opt(1232, false)
	q := dns.Message {
		id         = 0x2A2A,
		question   = questions,
		additional = additional,
	}
	q.flags.rd = true
	wire, _, _ := dns.encode_message(q, context.temp_allocator)
	return wire
}

// An upstream that has already been issued a server cookie, so every reply after
// it owes one.
@(private = "file")
probe_upstream :: proc() -> Upstream {
	u := Upstream {
		cookies = true,
		spec    = config.Upstream_Spec{kind = .UDP},
	}
	copy(u.cookie.client[:], CLIENT_COOKIE)
	u.cookie.server_len = copy(u.cookie.server[:], SERVER_COOKIE)
	return u
}

@(private = "file")
Shape :: struct {
	what: string,
	wire: []u8,
}

/*
Every way of being unreadable after the question that is still a reply this
server accepts.

Each is checked twice over: that the premise holds - the matcher takes it and a
decode does not - and then that the cookie check turns it away regardless.
*/
@(private = "file")
undecodable_shapes :: proc() -> []Shape {
	shapes := make([dynamic]Shape, 0, 8, context.temp_allocator)
	append(
		&shapes,
		Shape{"an RDLENGTH that runs off the end of the message", crafted(1, 1, 0, crafted_a(0xffff))},
		Shape{"an answer count promising a record that is not there", crafted(1, 1, 0)},
		Shape{"an owner name that is a compression pointer aimed forwards", crafted(1, 1, 0, crafted_forward_pointer())},
		Shape{"a question count promising a second question that is not there", crafted(2, 0, 0)},
		Shape{"an owner name whose label runs off the end", crafted(1, 1, 0, []u8{63, 'x', 'y'})},
		Shape{"an OPT record whose RDLENGTH runs off the end", crafted(1, 0, 1, crafted_opt(0xffff))},
		Shape {
			"an answer record that stops in the middle of its fixed fields",
			crafted(1, 1, 0, []u8{0xc0, 0x0c, 0x00, 0x01, 0x00}),
		},
	)
	return shapes[:]
}

/*
The reported issue, over every shape of it.

A reply the matcher accepts and a decode refuses used to be one the cookie check
declined to judge - and declining meant accepting. That put the whole mechanism
behind a property the sender chooses: truncate the body after the question, and
64 bits that were never on the attacker's path stop being asked for.
*/
@(test)
test_upstream_cookie_check_is_not_skipped_on_a_reply_that_does_not_decode :: proc(t: ^testing.T) {
	u := probe_upstream()
	query := probe_query()

	for shape in undecodable_shapes() {
		// The premise: this really is a reply the server would otherwise take.
		testing.expectf(t, response_matches(query, shape.wire), "%s: the matcher rejected it, so it proves nothing", shape.what)
		_, derr := dns.decode_message(shape.wire, context.temp_allocator)
		testing.expectf(t, derr != .None, "%s: it decoded after all, so it proves nothing", shape.what)

		// And the judgement, at both the check itself and the gate around it.
		testing.expectf(t, !cookie_matches(&u, shape.wire), "%s: accepted with no cookie, bypassing the check", shape.what)
		testing.expectf(t, !response_accepted(&u, query, shape.wire), "%s: the gate let it through", shape.what)
	}
	free_all(context.temp_allocator)
}

/*
The control: the same check on a reply that does decode.

Without this, a check that rejected everything would pass the test above while
turning away every genuine answer.
*/
@(test)
test_upstream_cookie_check_still_reads_a_reply_that_decodes :: proc(t: ^testing.T) {
	u := probe_upstream()
	query := probe_query()

	with_cookie := crafted(1, 1, 1, crafted_a(4), crafted_opt(nil, crafted_cookie_option(CLIENT_COOKIE, SERVER_COOKIE)))
	_, derr := dns.decode_message(with_cookie, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	testing.expect(t, cookie_matches(&u, with_cookie), "a well-formed reply carrying our cookie was rejected")
	testing.expect(t, response_accepted(&u, query, with_cookie), "the gate turned away a good reply")

	without := crafted(1, 1, 1, crafted_a(4), crafted_opt(nil))
	_, werr := dns.decode_message(without, context.temp_allocator)
	testing.expect_value(t, werr, dns.Decode_Error.None)
	testing.expect(t, !cookie_matches(&u, without), "a well-formed reply with no cookie was accepted")
	free_all(context.temp_allocator)
}

/*
A reply that does not decode is judged on its cookie, not turned away for not
decoding.

The two are easy to confuse and only one of them is the fix. A server whose
reply this resolver cannot parse - a record type it models badly, a name it
refuses - still authenticated itself with the 64 bits it was asked for, and
discarding its answer would be the check inventing a second reason to fail.
*/
@(test)
test_upstream_cookie_in_a_reply_that_does_not_decode_is_honoured :: proc(t: ^testing.T) {
	u := probe_upstream()
	query := probe_query()

	ours := crafted(
		1,
		1,
		1,
		crafted_forward_pointer(),
		crafted_opt(nil, crafted_cookie_option(CLIENT_COOKIE, SERVER_COOKIE)),
	)
	_, derr := dns.decode_message(ours, context.temp_allocator)
	testing.expect(t, derr != .None, "the fixture decoded, so it tests nothing")
	testing.expect(t, response_matches(query, ours), "the matcher rejected the fixture")
	testing.expect(t, cookie_matches(&u, ours), "a reply carrying our cookie was rejected for not decoding")
	testing.expect(t, response_accepted(&u, query, ours), "the gate turned it away")

	// The same message with somebody else's client cookie, which is what a
	// forgery would have to echo.
	forged := crafted(
		1,
		1,
		1,
		crafted_forward_pointer(),
		crafted_opt(nil, crafted_cookie_option([]u8{0, 1, 2, 3, 4, 5, 6, 7}, SERVER_COOKIE)),
	)
	testing.expect(t, !cookie_matches(&u, forged), "a forged client cookie was accepted")

	// And with a cookie that is not a legal length (RFC 7873 section 5.3).
	short := crafted(
		1,
		1,
		1,
		crafted_forward_pointer(),
		crafted_opt(nil, crafted_cookie_option(CLIENT_COOKIE, []u8{0xb0, 0xb1, 0xb2})),
	)
	testing.expect(t, !cookie_matches(&u, short), "an illegal cookie length was accepted")
	free_all(context.temp_allocator)
}

/*
An OPT record the walk cannot make sense of carries no cookie.

The option list below claims more bytes than the RDATA holds, so there is no
"first option" to read and stop at - which of the bytes behind it a reader lands
on would be the sender's choice. Reported as absent, and absent is refused once a
cookie is owed.
*/
@(test)
test_upstream_cookie_unreadable_option_list_carries_no_cookie :: proc(t: ^testing.T) {
	u := probe_upstream()

	// A cookie option whose length says eight bytes more than are there.
	overlong := crafted(1, 0, 1, crafted_opt(nil, crafted_cookie_option(CLIENT_COOKIE)[:2], []u8{0x00, 0x10}, CLIENT_COOKIE))
	testing.expect(t, !cookie_matches(&u, overlong), "a cookie was read out of an option list that does not tile")

	// Three bytes after a good cookie: the start of an option header and not an
	// option.
	trailing := crafted(
		1,
		0,
		1,
		crafted_opt(nil, crafted_cookie_option(CLIENT_COOKIE, SERVER_COOKIE), []u8{0x00, 0x0a, 0x00}),
	)
	testing.expect(t, !cookie_matches(&u, trailing), "a cookie was read out of a list with a trailing stub")
	free_all(context.temp_allocator)
}

/*
A server that has never issued a cookie is one that does not implement them, and
RFC 7873 has the exchange carry on without.

Failing closed on a reply that does not decode must not become failing closed on
every such reply from every server: nothing is owed until the server has shown it
does cookies, and a check that forgot that would refuse the answers of every
cookie-less upstream this resolver talks to.
*/
@(test)
test_upstream_cookie_undecodable_reply_is_tolerated_before_a_cookie_is_owed :: proc(t: ^testing.T) {
	u := probe_upstream()
	u.cookie.server_len = 0
	query := probe_query()

	for shape in undecodable_shapes() {
		testing.expectf(t, cookie_matches(&u, shape.wire), "%s: refused by a check that is owed nothing yet", shape.what)
		testing.expectf(t, response_accepted(&u, query, shape.wire), "%s: the gate refused it", shape.what)
	}

	// And with cookies switched off entirely, the check has no opinion at all.
	off := probe_upstream()
	off.cookies = false
	for shape in undecodable_shapes() {
		testing.expectf(t, cookie_matches(&off, shape.wire), "%s: refused with cookies disabled", shape.what)
	}
	free_all(context.temp_allocator)
}

/*
The cookie in a reply that does not decode still has to be taken back out.

`exchange_with_cookie` asks `reply_cookie` whether there is one to strip, and a
reply that got past the matcher without decoding is one this server is about to
hand to a client. Answering "no cookie here" for it would send the cookie on -
the one thing the strip exists to prevent.
*/
@(test)
test_upstream_reply_cookie_reads_a_reply_that_does_not_decode :: proc(t: ^testing.T) {
	wire := crafted(
		1,
		1,
		1,
		crafted_forward_pointer(),
		crafted_opt(nil, crafted_cookie_option(CLIENT_COOKIE, SERVER_COOKIE)),
	)
	_, derr := dns.decode_message(wire, context.temp_allocator)
	testing.expect(t, derr != .None, "the fixture decoded, so it tests nothing")

	raw, found := reply_cookie(wire)
	testing.expect(t, found, "the cookie in an undecodable reply was not found, so it would be passed on")
	if found {
		testing.expect_value(t, len(raw), COOKIE_CLIENT_LEN + len(SERVER_COOKIE))
		testing.expect(t, mem.compare(raw[COOKIE_CLIENT_LEN:], SERVER_COOKIE) == 0, "the wrong bytes were read")
	}

	// And `remove_edns_option` agrees there is one to take out, so the guard and
	// the strip cannot disagree about which replies get stripped.
	stripped, ok := dns.remove_edns_option(wire, .Cookie, context.temp_allocator)
	testing.expect(t, ok, "the cookie the guard found could not be stripped")
	if ok {
		_, still := reply_cookie(stripped)
		testing.expect(t, !still, "the cookie survived the strip")
	}

	// The same walk feeds `learn_cookie`, so the server cookie such a reply
	// carries is kept for the next query.
	u := probe_upstream()
	u.cookie.server_len = 0
	learn_cookie(&u, wire)
	testing.expect_value(t, u.cookie.server_len, len(SERVER_COOKIE))
	testing.expect(t, mem.compare(u.cookie.server[:u.cookie.server_len], SERVER_COOKIE) == 0, "the wrong server cookie was kept")
	free_all(context.temp_allocator)
}

/*
A responder that answers properly for a while and then sends bytes of its own
choosing.

The unit tests above judge `cookie_matches` in isolation; this one plays the
attack out over a socket, because the property that matters is what
`exchange_udp` does with the datagram - it stops waiting and hands the forged
bytes back, discarding the genuine reply still in flight, or it passes the
datagram over and keeps waiting.
*/
@(private = "file")
Probe_Mock :: struct {
	socket:      net.UDP_Socket,
	stop:        bool,
	// Put a COOKIE option in the replies, which is what teaches the upstream
	// this server does cookies and makes one owed on everything after.
	issue:       bool,
	// From this query on, send `wire` in place of a reply of its own.
	forge_at:    int,
	wire:        [512]u8,
	wire_len:    int,
	mu:          sync.Mutex,
	queries:     int,
}

@(private = "file")
probe_mock_loop :: proc(m: ^Probe_Mock) {
	buf: [1500]u8
	for !sync.atomic_load(&m.stop) {
		n, client, err := net.recv_udp(m.socket, buf[:])
		if err != nil || n < dns.HEADER_SIZE {
			continue
		}

		sync.mutex_lock(&m.mu)
		m.queries += 1
		count := m.queries
		sync.mutex_unlock(&m.mu)

		if m.wire_len > 0 && count >= m.forge_at {
			out := make([]u8, m.wire_len, context.temp_allocator)
			copy(out, m.wire[:m.wire_len])
			// Echo the transaction ID the query carried, so the forgery is
			// turned away by the cookie check and not by the matcher.
			out[0] = buf[0]
			out[1] = buf[1]
			_, _ = net.send_udp(m.socket, out, client)
		} else if reply, ok := probe_mock_reply(m, buf[:n]); ok {
			_, _ = net.send_udp(m.socket, reply, client)
		}
		free_all(context.temp_allocator)
	}
}

@(private = "file")
probe_mock_reply :: proc(m: ^Probe_Mock, query: []u8) -> (reply: []u8, ok: bool) {
	msg, derr := dns.decode_message(query, context.temp_allocator)
	if derr != .None {
		return nil, false
	}
	resp := dns.make_response(msg, .No_Error, context.temp_allocator)
	wire, _, eerr := dns.encode_message(resp, context.temp_allocator)
	if eerr != .None {
		return nil, false
	}

	sent, has_cookie := dns.find_edns_option(msg, .Cookie)
	if !m.issue || !has_cookie {
		return wire, true
	}
	option: [16]u8
	copy(option[:8], sent[:min(8, len(sent))])
	copy(option[8:], SERVER_COOKIE)
	out, set_ok := dns.set_edns_option(wire, .Cookie, option[:], context.temp_allocator)
	if !set_ok {
		return wire, true
	}
	return out, true
}

@(private = "file")
start_probe_mock :: proc(t: ^testing.T, m: ^Probe_Mock) -> (u: ^Upstream, worker: ^thread.Thread, ok: bool) {
	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if serr != nil {
		testing.expectf(t, false, "cannot bind a loopback responder: %v", serr)
		return nil, nil, false
	}
	m.socket = socket
	// Without this the responder would sit in recv_udp and never see `stop`.
	set_socket_timeouts(socket, 50 * time.Millisecond)

	bound, berr := net.bound_endpoint(socket)
	if berr != nil {
		net.close(socket)
		testing.expectf(t, false, "cannot read the responder's port: %v", berr)
		return nil, nil, false
	}

	worker = thread.create_and_start_with_poly_data(m, probe_mock_loop)
	built, uerr := make_upstream(
		config.Upstream_Spec{name = "mock", kind = .UDP, address = "127.0.0.1", port = bound.port},
		0,
		time.Second,
		context.allocator,
		cookies = true,
	)
	if uerr != .None {
		sync.atomic_store(&m.stop, true)
		thread.join(worker)
		thread.destroy(worker)
		net.close(socket)
		testing.expectf(t, false, "cannot build the upstream: %v", uerr)
		return nil, nil, false
	}
	return built, worker, true
}

@(private = "file")
stop_probe_mock :: proc(m: ^Probe_Mock, u: ^Upstream, worker: ^thread.Thread) {
	sync.atomic_store(&m.stop, true)
	thread.join(worker)
	thread.destroy(worker)
	net.close(m.socket)
	destroy(u)
}

@(private = "file")
mock_queries :: proc(m: ^Probe_Mock) -> int {
	sync.mutex_lock(&m.mu)
	defer sync.mutex_unlock(&m.mu)
	return m.queries
}

/*
The attack, end to end.

The first exchange teaches the upstream a server cookie, so from then on a reply
without one is a forgery. The second is answered by a datagram that carries no
cookie and stops making sense after the question - the shape that used to walk
straight through the check. `exchange_udp` has to pass it over and keep waiting
for the genuine reply, which never comes here, so the exchange times out. What it
must not do is hand those bytes back as the answer.
*/
@(test)
test_upstream_cookie_undecodable_forgery_is_not_taken_as_an_answer :: proc(t: ^testing.T) {
	m := Probe_Mock {
		issue    = true,
		forge_at = 2,
	}
	forged := crafted(1, 1, 0, crafted_a(0xffff))
	m.wire_len = copy(m.wire[:], forged)

	u, worker, ok := start_probe_mock(t, &m)
	if !ok {
		return
	}
	defer stop_probe_mock(&m, u, worker)

	_, err := exchange(u, probe_query(), time.Second, context.temp_allocator)
	testing.expectf(t, err == .None, "the first exchange failed: %v", err)
	sync.mutex_lock(&u.mu)
	learned := u.cookie.server_len
	sync.mutex_unlock(&u.mu)
	testing.expect(t, learned > 0, "no server cookie was learned, so nothing is owed and the test proves nothing")

	response, err2 := exchange(u, probe_query(), 300 * time.Millisecond, context.temp_allocator)
	testing.expectf(t, err2 == .Timeout, "an undecodable forgery was taken as the answer (%v)", err2)
	testing.expect(t, response == nil, "the forged bytes were handed back")

	// It really did answer; the datagram was passed over rather than never sent.
	testing.expect(t, mock_queries(&m) > 1, "the responder never saw the second query")
	free_all(context.temp_allocator)
}

/*
The control: the same datagram, from a server that has never issued a cookie.

Nothing is owed there, so the reply is accepted - which is what makes the refusal
above the cookie check doing its work rather than the crafted bytes failing to be
a plausible reply at all.
*/
@(test)
test_upstream_cookie_undecodable_reply_is_accepted_when_none_is_owed :: proc(t: ^testing.T) {
	m := Probe_Mock {
		forge_at = 1,
	}
	forged := crafted(1, 1, 0, crafted_a(0xffff))
	m.wire_len = copy(m.wire[:], forged)

	u, worker, ok := start_probe_mock(t, &m)
	if !ok {
		return
	}
	defer stop_probe_mock(&m, u, worker)

	response, err := exchange(u, probe_query(), time.Second, context.temp_allocator)
	testing.expectf(t, err == .None, "a cookie-less server's reply was refused: %v", err)
	testing.expect(t, response != nil, "nothing came back")
	if response != nil {
		testing.expect(t, mem.compare(response[2:], forged[2:]) == 0, "the bytes that came back are not the ones sent")
	}
	free_all(context.temp_allocator)
}
