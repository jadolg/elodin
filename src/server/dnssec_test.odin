package server

import "core:net"
import "core:testing"
import "core:thread"
import "elodin:cache"
import "elodin:config"
import "elodin:dns"
import "elodin:dnssec"
import "elodin:upstream"

/*
The parts of the DNSSEC path that shape what the client sees.

The validator's own verdicts are checked in `src/dnssec` against captured
chains, and the running server's behaviour in the integration suite. What is
left is the presentation: which records survive, what the AD bit says, and what
goes out on the wire to ask the upstream in the first place.
*/

// A slice literal lives only as long as the scope that wrote it, so anything a
// helper hands back has to be allocated rather than composed in place.
@(private = "file")
question :: proc() -> []dns.Question {
	out := make([]dns.Question, 1, context.temp_allocator)
	out[0] = dns.Question {
		name  = "www.example.com.",
		type  = .A,
		class = .IN,
	}
	return out
}

@(private = "file")
signed_response :: proc() -> dns.Message {
	answer := make([]dns.Record, 2, context.temp_allocator)
	answer[0] = dns.Record {
		name = "www.example.com.",
		type = .A,
		class = .IN,
		ttl = 300,
		data = dns.Rdata_A{addr = {93, 184, 216, 34}},
	}
	answer[1] = dns.Record {
		name = "www.example.com.",
		type = .RRSIG,
		class = .IN,
		ttl = 300,
		data = dns.Rdata_Raw{data = make([]u8, 40, context.temp_allocator)},
	}
	authority := make([]dns.Record, 1, context.temp_allocator)
	authority[0] = dns.Record {
		name = "example.com.",
		type = .NSEC,
		class = .IN,
		ttl = 300,
		data = dns.Rdata_Raw{data = make([]u8, 12, context.temp_allocator)},
	}
	additional := make([]dns.Record, 1, context.temp_allocator)
	additional[0] = dns.make_opt(4096, true)

	msg := dns.Message {
		id         = 0x2b2b,
		question   = question(),
		answer     = answer,
		authority  = authority,
		additional = additional,
	}
	msg.flags.qr = true
	msg.flags.ra = true
	return msg
}

/*
The verdict a validator would have reached over `signed_response`.

Spelled out rather than reduced to "secure", because that is what a verdict is
now: `present_response` cuts a secure answer down to the RRsets the validator
names, so a `Result` that names nothing strips the message to its OPT record.
*/
@(private = "file")
secure_verdict :: proc() -> dnssec.Result {
	answer := make([]dns.Question, 1, context.temp_allocator)
	answer[0] = dns.Question {
		name  = "www.example.com.",
		type  = .A,
		class = .IN,
	}
	authority := make([]dns.Question, 1, context.temp_allocator)
	authority[0] = dns.Question {
		name  = "example.com.",
		type  = .NSEC,
		class = .IN,
	}
	return dnssec.Result{status = .Secure, answer = answer, authority = authority}
}

@(private = "file")
client_query :: proc(dnssec_ok: bool, with_edns := true) -> dns.Message {
	msg := dns.Message {
		id       = 0x2b2b,
		question = question(),
	}
	msg.flags.rd = true
	if with_edns {
		additional := make([]dns.Record, 1, context.temp_allocator)
		additional[0] = dns.make_opt(1232, dnssec_ok)
		msg.additional = additional
	}
	return msg
}

@(test)
test_strip_removes_dnssec_records :: proc(t: ^testing.T) {
	wire, _, err := dns.encode_message(signed_response(), context.temp_allocator)
	testing.expect_value(t, err, dns.Encode_Error.None)

	stripped := strip_dnssec_records(wire, client_query(false), .A, context.temp_allocator, dns.MAX_MESSAGE)
	msg, derr := dns.decode_message(stripped, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)

	testing.expect_value(t, len(msg.answer), 1)
	testing.expect_value(t, msg.answer[0].type, dns.Type.A)
	testing.expect_value(t, len(msg.authority), 0)

	// The client's own EDNS parameters come back, with DO clear because it
	// never asked for the records that bit requests.
	testing.expect(t, dns.edns_present(msg), "the OPT record should survive")
	testing.expect(t, !dns.edns_do(msg), "DO should be clear for a client that did not set it")
	testing.expect_value(t, dns.edns_udp_size(msg), u16(1232))
	free_all(context.temp_allocator)
}

@(test)
test_strip_keeps_records_that_were_asked_for :: proc(t: ^testing.T) {
	// A client asking for RRSIG records wants RRSIG records.
	wire, _, _ := dns.encode_message(signed_response(), context.temp_allocator)
	stripped := strip_dnssec_records(wire, client_query(false), .RRSIG, context.temp_allocator, dns.MAX_MESSAGE)

	msg, derr := dns.decode_message(stripped, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	testing.expect_value(t, len(msg.answer), 2)
	free_all(context.temp_allocator)
}

@(test)
test_strip_omits_opt_for_a_client_without_edns :: proc(t: ^testing.T) {
	wire, _, _ := dns.encode_message(signed_response(), context.temp_allocator)
	stripped := strip_dnssec_records(
		wire,
		client_query(false, with_edns = false),
		.A,
		context.temp_allocator,
		dns.MAX_MESSAGE,
	)

	msg, derr := dns.decode_message(stripped, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	testing.expect(t, !dns.edns_present(msg), "a client that sent no OPT should get none back")
	free_all(context.temp_allocator)
}

@(test)
test_ad_bit_records_the_verdict :: proc(t: ^testing.T) {
	// What goes into the cache says what was established, whoever asked.
	wire, _, _ := dns.encode_message(signed_response(), context.temp_allocator)
	secure := present_response(wire, client_query(false), .A, secure_verdict(), context.temp_allocator)
	testing.expect(t, secure[3] & 0x20 != 0, "AD should record a secure verdict")

	// Not secure: the bit must come off even though the upstream may have set it.
	insecure_wire, _, _ := dns.encode_message(signed_response(), context.temp_allocator)
	insecure_wire[3] |= 0x20
	insecure := present_response(
		insecure_wire,
		client_query(true),
		.A,
		dnssec.Result{status = .Insecure},
		context.temp_allocator,
	)
	testing.expect(t, insecure[3] & 0x20 == 0, "AD must not survive an unauthenticated answer")
	free_all(context.temp_allocator)
}

@(test)
test_ad_bit_only_reaches_clients_that_asked :: proc(t: ^testing.T) {
	// RFC 6840 section 5.8. The same stored bytes, three clients.
	wire, _, _ := dns.encode_message(signed_response(), context.temp_allocator)
	wire[3] |= 0x20

	with_do := make([]u8, len(wire), context.temp_allocator)
	copy(with_do, wire)
	apply_ad_policy(with_do, client_query(true))
	testing.expect(t, with_do[3] & 0x20 != 0, "a DO client asked and should be told")

	asked_ad := make([]u8, len(wire), context.temp_allocator)
	copy(asked_ad, wire)
	query_with_ad := client_query(false)
	query_with_ad.flags.ad = true
	apply_ad_policy(asked_ad, query_with_ad)
	testing.expect(t, asked_ad[3] & 0x20 != 0, "a client setting AD asked and should be told")

	silent := make([]u8, len(wire), context.temp_allocator)
	copy(silent, wire)
	apply_ad_policy(silent, client_query(false))
	testing.expect(t, silent[3] & 0x20 == 0, "a client that asked nothing should be told nothing")
	free_all(context.temp_allocator)
}

@(test)
test_cd_bit_is_not_echoed_back :: proc(t: ^testing.T) {
	// Our own upstream query sets CD, and the upstream echoes it. Passing that
	// on would tell a client that its answer went unchecked.
	wire, _, _ := dns.encode_message(signed_response(), context.temp_allocator)
	wire[3] |= 0x10

	out := present_response(wire, client_query(true), .A, secure_verdict(), context.temp_allocator)
	testing.expect(t, out[3] & 0x10 == 0, "CD should be clear for a client that did not set it")

	stripped_wire, _, _ := dns.encode_message(signed_response(), context.temp_allocator)
	stripped_wire[3] |= 0x10
	stripped := present_response(stripped_wire, client_query(false), .A, secure_verdict(), context.temp_allocator)
	testing.expect(t, stripped[3] & 0x10 == 0, "CD should be clear on a stripped answer too")
	free_all(context.temp_allocator)
}

@(test)
test_ad_never_goes_out_over_records_the_verdict_missed :: proc(t: ^testing.T) {
	/*
	RFC 4035 section 3.2.3. The verdict names the RRsets that were checked, and
	this is the last place the rest can be taken out - after it, the AD bit goes
	on and the message goes into the cache for every later client to be given.

	The DO client is the one to check, because it is the one whose message is
	otherwise passed through byte for byte: `strip_dnssec_records` would have
	taken the forgery below out of a non-DO client's copy by accident, being
	interested in a different question entirely.
	*/
	msg := signed_response()
	authority := make([dynamic]dns.Record, 0, len(msg.authority) + 1, context.temp_allocator)
	append(&authority, ..msg.authority)
	append(
		&authority,
		dns.Record {
			name = "example.com.",
			type = .NS,
			class = .IN,
			ttl = 86400,
			data = dns.Rdata_Name{name = "ns.attacker.example."},
		},
	)
	/*
	And the same question asked sideways: an address for the name that *was*
	authenticated, in the section that was not. The verdict names an RRset in a
	section, so this one has no credentials of its own to be waved through on -
	the signature that held up was checked over the answer section's records and
	says nothing about these.
	*/
	append(
		&authority,
		dns.Record {
			name = "www.example.com.",
			type = .A,
			class = .IN,
			ttl = 300,
			data = dns.Rdata_A{addr = {203, 0, 113, 67}},
		},
	)
	msg.authority = authority[:]

	additional := make([dynamic]dns.Record, 0, len(msg.additional) + 1, context.temp_allocator)
	append(&additional, ..msg.additional)
	append(
		&additional,
		dns.Record {
			name = "ns.attacker.example.",
			type = .A,
			class = .IN,
			ttl = 86400,
			data = dns.Rdata_A{addr = {203, 0, 113, 66}},
		},
	)
	msg.additional = additional[:]

	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	testing.expect_value(t, err, dns.Encode_Error.None)

	out := present_response(wire, client_query(true), .A, secure_verdict(), context.temp_allocator)
	testing.expect(t, out[3] & 0x20 != 0, "AD should record the secure verdict")

	decoded, derr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)

	for rec in decoded.authority {
		testing.expectf(t, rec.type != .NS, "an unsigned NS RRset went out under AD as %v", rec.name)
	}
	testing.expect_value(t, len(decoded.authority), 1)
	testing.expect_value(t, decoded.authority[0].type, dns.Type.NSEC)

	// The glue goes with it, and the OPT record - which is not data anybody
	// signs - stays.
	testing.expect_value(t, len(decoded.additional), 1)
	testing.expect(t, dns.edns_present(decoded), "the OPT record should survive")
	testing.expect_value(t, len(decoded.answer), 1)
	testing.expect_value(t, decoded.answer[0].type, dns.Type.A)
	free_all(context.temp_allocator)
}

@(test)
test_upstream_query_asks_for_signatures :: proc(t: ^testing.T) {
	query := client_query(false)
	wire, ok := dnssec_upstream_query(query, context.temp_allocator)
	testing.expect(t, ok, "the upstream query should build")

	msg, err := dns.decode_message(wire, context.temp_allocator)
	testing.expect_value(t, err, dns.Decode_Error.None)
	testing.expect(t, msg.flags.cd, "CD should be set so the upstream's verdict is not inherited")
	testing.expect(t, dns.edns_do(msg), "DO should be set so signatures come back")
	testing.expect_value(t, dns.edns_udp_size(msg), u16(UPSTREAM_UDP_SIZE))

	testing.expect_value(t, len(msg.question), 1)
	testing.expect_value(t, msg.question[0].name, "www.example.com.")
	testing.expect_value(t, msg.question[0].type, dns.Type.A)

	/*
	Nothing is asserted about the transaction ID here on purpose. This procedure
	leaves it as the client wrote it, and `resolve_query` replaces it with a
	fresh one once this path and the plain forwarding path have converged - so
	the ID a client chose surviving this far is expected, and the ID reaching an
	upstream is what has to be checked. `query_id_test.odin` checks it, through
	the whole server.
	*/
	free_all(context.temp_allocator)
}

/*
An answer we did not check ourselves must not claim to have been checked.

The AD bit says "this resolver authenticated this data". When validation is off,
or the client asked us to leave it alone with CD, we authenticated nothing — so
whatever the upstream put in that bit is its claim, not ours, and passing it on
lends it our name. RFC 6840 section 5.8 and RFC 4035 section 3.2.2.

Driven through `handle_query` on the cache path rather than against
`apply_ad_policy` directly, because the defect was not in that procedure: it
was in only calling it when we had validated.
*/

@(private = "file")
Ad_Case :: struct {
	name:      string,
	validator: bool,
	cd:        bool,
}

@(private = "file")
serve_cached_with_ad :: proc(t: ^testing.T, c: Ad_Case) -> (response: []u8, ok: bool) {
	// The answer as an upstream sent it, AD set. Nothing here established that.
	stored := signed_response()
	stored.flags.ad = true
	wire, _, enc := dns.encode_message(stored, context.temp_allocator)
	testing.expect_value(t, enc, dns.Encode_Error.None)

	cfg := config.default_config()
	cfg.log.queries = false
	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600})
	defer cache.destroy(answers)

	s := Server {
		cfg     = &cfg,
		answers = answers,
	}
	if c.validator {
		// A validator that is never asked anything: with CD set, nothing
		// reaches it.
		s.validator = dnssec.make_validator(nil, nil, dnssec.Options{})
	}
	defer if s.validator != nil {
		dnssec.destroy_validator(s.validator)
	}

	query := client_query(false, with_edns = false)
	query.flags.cd = c.cd
	query_wire, _, qenc := dns.encode_message(query, context.temp_allocator)
	testing.expect_value(t, qenc, dns.Encode_Error.None)

	key_buf: [cache.KEY_MAX]u8
	key := cache.make_key(
		key_buf[:],
		query.question[0].name,
		query.question[0].type,
		query.question[0].class,
		dns.edns_do(query),
		query.flags.cd,
	)
	decoded, derr := dns.decode_message(wire, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	if !cache.put(answers, key, wire, decoded) {
		testing.expectf(t, false, "%s: the answer was not cached, so the served path was never taken", c.name)
		return nil, false
	}

	out, outcome, served := handle_query(&s, query_wire, .UDP, "test", context.temp_allocator)
	testing.expectf(t, served, "%s: no response was produced", c.name)
	testing.expectf(t, outcome == .Cached, "%s: expected the cached path, got %v", c.name, outcome)
	return out, served && outcome == .Cached
}

@(test)
test_ad_bit_is_not_forwarded_when_we_did_not_validate :: proc(t: ^testing.T) {
	cases := []Ad_Case {
		// DNSSEC off entirely: there is no verdict to report.
		{name = "no validator", validator = false, cd = false},
		// DNSSEC on, but the client set CD, which is a request to leave the
		// checking alone. We do, so we have nothing to attest either.
		{name = "checking disabled by the client", validator = true, cd = true},
	}
	for c in cases {
		out, ok := serve_cached_with_ad(t, c)
		if !ok {
			continue
		}
		testing.expectf(
			t,
			len(out) >= dns.HEADER_SIZE && out[3] & 0x20 == 0,
			"%s: the upstream's AD bit reached the client as ours",
			c.name,
		)
		free_all(context.temp_allocator)
	}
}

/*
A reply to a query we could not parse still has to be recognisable as a reply.

`make_response` builds from the decoded message, and a query that did not decode
leaves that empty — id zero, no question. Encoding an empty message succeeds, so
`error_response` returned those twelve bytes and never reached the fallback that
was written to patch the request's own header. The client is waiting on its own
transaction ID, so what came back was dropped as unsolicited and the query
waited out its full timeout instead.
*/
@(test)
test_formerr_for_an_unparseable_query_carries_its_id :: proc(t: ^testing.T) {
	// A header claiming a question that is not there: enough to fail the decode
	// while still being a header we can answer from.
	query := make([]u8, dns.HEADER_SIZE, context.temp_allocator)
	query[0], query[1] = 0xab, 0xcd
	query[2] = 0x01 // RD
	query[5] = 1 // qdcount, with no question following it

	_, derr := dns.decode_message(query, context.temp_allocator)
	testing.expect(t, derr != .None, "the fixture parsed, so it is not testing the unparseable path")

	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	s := Server {
		cfg = &cfg,
	}

	out, outcome, ok := handle_query(&s, query, .UDP, "test", context.temp_allocator)
	testing.expect(t, ok, "no response was produced for a malformed query")
	testing.expect_value(t, outcome, Outcome.Failed)
	if !ok || len(out) < dns.HEADER_SIZE {
		return
	}

	id, id_ok := dns.peek_id(out)
	testing.expect(t, id_ok, "the response is too short to carry an id")
	testing.expectf(t, id == 0xabcd, "the reply carries id %04x, not the query's abcd", id)
	testing.expect(t, out[2] & 0x80 != 0, "the reply is not marked as a response")
	testing.expect_value(t, out[3] & 0xf, u8(dns.Rcode.Form_Err))

	free_all(context.temp_allocator)
}

/*
An answer we did not check must not be stored carrying a claim that we did.

`validating` is recomputed for every request, so nothing ties the AD bit an
entry carries to whether that entry was ever validated. The two agree today only
because the cache key carries CD and the class, which keeps the entries a
non-validating request writes away from the requests that would trust them -
an accident of the key rather than a property of the cache, and one that stops
holding the moment `validating` is turned off after the key is built, as it is
when the upstream query cannot be rebuilt.

So the bit is settled before the entry goes in, and this drives the real store
path to check it: a miss, forwarded to an upstream that sets AD, with CD on the
client's query so no verdict of ours is ever reached.
*/

@(private = "file")
Udp_Mock :: struct {
	socket: net.UDP_Socket,
	reply:  []u8,
}

@(private = "file")
udp_mock_once :: proc(m: ^Udp_Mock) {
	buf: [4096]u8
	n, remote, err := net.recv_udp(m.socket, buf[:])
	if err != nil || n < dns.HEADER_SIZE || len(m.reply) > len(buf) {
		return
	}
	out: [4096]u8
	copy(out[:], m.reply)
	// Echo the query's transaction id, so the reply is matched to it.
	out[0], out[1] = buf[0], buf[1]
	_, _ = net.send_udp(m.socket, out[:len(m.reply)], remote)
}

@(test)
test_unvalidated_answer_is_not_cached_with_ad :: proc(t: ^testing.T) {
	// The answer as an upstream sent it, AD set. Nothing here established that.
	from_upstream := signed_response()
	from_upstream.flags.ad = true
	reply, _, enc := dns.encode_message(from_upstream, context.temp_allocator)
	testing.expect_value(t, enc, dns.Encode_Error.None)

	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if serr != nil {
		testing.expectf(t, false, "cannot bind the mock upstream: %v", serr)
		return
	}
	defer net.close(socket)
	bound, berr := net.bound_endpoint(socket)
	if berr != nil {
		testing.expectf(t, false, "cannot read the mock's port: %v", berr)
		return
	}

	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = true
	cfg.dnssec.enabled = true
	cfg.upstream.strategy = .Failover
	servers := make([]config.Upstream_Spec, 1, context.temp_allocator)
	servers[0] = config.Upstream_Spec {
		name    = "mock",
		kind    = .UDP,
		address = "127.0.0.1",
		port    = bound.port,
	}
	cfg.upstream.servers = servers

	g, gerr := upstream.make_group(cfg.upstream, nil)
	if gerr != .None {
		testing.expectf(t, false, "cannot build the upstream group: %v", gerr)
		return
	}
	defer upstream.destroy_group(g)

	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600})
	defer cache.destroy(answers)

	s := Server {
		cfg     = &cfg,
		group   = g,
		answers = answers,
	}
	// A validator that is never asked anything: CD below keeps it out of the way.
	s.validator = dnssec.make_validator(nil, nil, dnssec.Options{})
	defer dnssec.destroy_validator(s.validator)

	// CD set, so `validating` is false and we reach no verdict of our own.
	query := client_query(false, with_edns = false)
	query.flags.cd = true
	query_wire, _, qenc := dns.encode_message(query, context.temp_allocator)
	testing.expect_value(t, qenc, dns.Encode_Error.None)

	m := Udp_Mock {
		socket = socket,
		reply  = reply,
	}
	server := thread.create_and_start_with_poly_data(&m, udp_mock_once)
	out, outcome, served := handle_query(&s, query_wire, .UDP, "test", context.temp_allocator)
	// Joined here rather than deferred: the mock reads `reply` out of the scratch
	// arena this test resets on its way out.
	thread.join(server)
	thread.destroy(server)

	testing.expect(t, served, "no response was produced")
	testing.expectf(t, outcome == .Forwarded, "expected the forwarded path, got %v", outcome)
	// Already right, and the reason this went unnoticed: the client is told nothing.
	testing.expect(
		t,
		len(out) >= dns.HEADER_SIZE && out[3] & 0x20 == 0,
		"the upstream's AD bit reached the client as ours",
	)

	// What the entry carries is the point.
	key_buf: [cache.KEY_MAX]u8
	key := cache.make_key(
		key_buf[:],
		query.question[0].name,
		query.question[0].type,
		query.question[0].class,
		dns.edns_do(query),
		query.flags.cd,
	)
	stored, _, found := cache.get(answers, key, context.temp_allocator)
	testing.expect(t, found, "the answer was not cached, so nothing was stored to check")
	if found {
		testing.expect(
			t,
			len(stored) >= dns.HEADER_SIZE && stored[3] & 0x20 == 0,
			"an answer we never validated was cached carrying AD",
		)
	}
	free_all(context.temp_allocator)
}
