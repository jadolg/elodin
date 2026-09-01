package upstream

import "core:net"
import "core:sync"
import "core:sys/posix"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:dns"
import "elodin:tlsx"

/*
EDNS(0) padding on the way out to an upstream (RFC 8467 section 4.1).

The claim is about bytes on a wire, so the wire is where it is read: a real DoT
server, holding a real certificate, reporting the length of what actually
arrived. A test that asked `pad_query` the same question would only be checking
that the padding procedure pads - it would not notice `exchange` never calling
it, which is the whole of what was missing.

The mock answers with a padded reply of its own, which is what a padding-aware
upstream does with a padded query, so the same exchange also pins the other half:
the padding stops here rather than travelling on into the cache.
*/

@(private = "file")
Dot_Padding_Mock :: struct {
	listener: net.TCP_Socket,
	ctx:      ^tlsx.Context,
	// Length of the query as it arrived, and whether it carried the option.
	asked:    int,
	option:   bool,
	served:   int,
}

@(private = "file")
dot_padding_serve :: proc(m: ^Dot_Padding_Mock) {
	sock, _, aerr := net.accept_tcp(m.listener)
	if aerr != nil {
		return
	}
	_ = net.set_option(sock, .Receive_Timeout, 3 * time.Second)
	_ = net.set_option(sock, .Send_Timeout, 3 * time.Second)
	conn, terr := tlsx.server_accept(m.ctx, sock)
	if terr != .None {
		net.close(sock)
		return
	}
	defer tlsx.close(conn)

	length: [2]u8
	if tlsx.read_full(conn, length[:]) != .None {
		return
	}
	n := int(length[0]) << 8 | int(length[1])
	if n < dns.HEADER_SIZE || n > 4096 {
		return
	}
	buf: [4096]u8
	if tlsx.read_full(conn, buf[:n]) != .None {
		return
	}
	sync.atomic_store(&m.asked, n)
	_, found := dns.peek_edns_option(buf[:n], .Padding)
	sync.atomic_store(&m.option, found)

	/*
	The query echoed back with QR set, which is all `response_matches` asks of a
	reply, and padded the way RFC 8467 section 4.2 has a responder pad one.
	Whatever the query carried is replaced rather than added to, so the reply is
	padded exactly once.
	*/
	buf[2] |= 0x80
	reply, padded := dns.pad_response(
		buf[:n],
		dns.PAD_RESPONSE_BLOCK,
		dns.MAX_MESSAGE,
		1232,
		context.temp_allocator,
	)
	if !padded {
		return
	}
	framed := make([]u8, 2 + len(reply), context.temp_allocator)
	framed[0] = u8(len(reply) >> 8)
	framed[1] = u8(len(reply))
	copy(framed[2:], reply)
	if _, werr := tlsx.write(conn, framed); werr != .None {
		return
	}
	sync.atomic_add(&m.served, 1)
	free_all(context.temp_allocator)
}

@(private = "file")
padding_query :: proc(opt: bool) -> []u8 {
	questions := make([]dns.Question, 1, context.temp_allocator)
	questions[0] = dns.Question {
		name  = "example.com.",
		type  = .A,
		class = .IN,
	}
	msg := dns.Message {
		id       = 0x5151,
		question = questions,
	}
	msg.flags.rd = true
	if opt {
		additional := make([]dns.Record, 1, context.temp_allocator)
		additional[0] = dns.make_opt(1232, false)
		msg.additional = additional
	}
	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

@(test)
test_a_dot_query_goes_out_padded_and_its_reply_comes_back_stripped :: proc(t: ^testing.T) {
	// As in the DoT retry test: a peer that hangs up mid-handshake raises
	// SIGPIPE on the write that follows, which the server ignores and the test
	// runner does not.
	posix.sigignore(.SIGPIPE)

	sync.once_do(&dot_cert_once, generate_dot_certs)
	if !dot_cert_ok {
		testing.expect(t, false, "no certificate available and openssl could not make one")
		return
	}

	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.expectf(t, false, "cannot listen on loopback: %v", lerr)
		return
	}
	defer net.close(listener)
	bound, berr := net.bound_endpoint(listener)
	if berr != nil {
		testing.expectf(t, false, "cannot read the listener's port: %v", berr)
		return
	}
	// So a query that never arrives ends the accept rather than hanging the suite.
	_ = net.set_option(listener, .Receive_Timeout, 3 * time.Second)

	sctx, serr := tlsx.server_context(dot_cert_path, dot_key_path)
	if serr != .None {
		testing.expectf(t, false, "server_context: %v", serr)
		return
	}
	defer tlsx.context_destroy(sctx)

	m := Dot_Padding_Mock {
		listener = listener,
		ctx      = sctx,
	}
	mock_thread := thread.create_and_start_with_poly_data(&m, dot_padding_serve)
	defer {
		thread.join(mock_thread)
		thread.destroy(mock_thread)
	}

	u, uerr := make_upstream(
		// Unverified: the mock's certificate is self-signed, and what is under
		// test is the padding rather than the trust decision.
		config.Upstream_Spec{name = "mock", kind = .TLS, address = "127.0.0.1", port = bound.port},
		0,
		2 * time.Second,
		context.allocator,
	)
	testing.expectf(t, uerr == .None, "cannot build the upstream: %v", uerr)
	if uerr != .None {
		return
	}
	defer destroy(u)

	wire := padding_query(true)
	if !testing.expect(t, wire != nil, "could not build the query") {
		return
	}

	resp, xerr := exchange(u, wire, 2 * time.Second, context.temp_allocator)
	if !testing.expectf(t, xerr == .None, "the exchange failed: %v", xerr) {
		return
	}
	testing.expect_value(t, sync.atomic_load(&m.served), 1)

	asked := sync.atomic_load(&m.asked)
	testing.expect(t, sync.atomic_load(&m.option), "the query reached the upstream without a padding option")
	testing.expectf(
		t,
		asked % dns.PAD_QUERY_BLOCK == 0,
		"a %d-byte query arrived %d bytes past a 128-octet block",
		asked,
		asked % dns.PAD_QUERY_BLOCK,
	)
	testing.expectf(t, asked > len(wire), "the query arrived at its natural %d bytes", len(wire))

	/*
	And the reply's padding stops here. The mock padded to 468; what this server
	keeps is the answer, because the copy it keeps goes into a cache that is
	shared with clients on transports where those bytes are a cost and not a
	mitigation.
	*/
	_, carried := dns.peek_edns_option(resp, .Padding)
	testing.expect(t, !carried, "the upstream's padding was passed on rather than stripped")
	testing.expectf(
		t,
		len(resp) < dns.PAD_RESPONSE_BLOCK,
		"the stripped reply is still %d bytes",
		len(resp),
	)
	testing.expect(t, response_matches(wire, resp), "the stripped reply no longer answers the query")

	free_all(context.temp_allocator)
}

@(test)
test_only_the_encrypted_transports_pad :: proc(t: ^testing.T) {
	/*
	RFC 8467 section 5. On UDP the padding would be added to the datagrams an
	amplifier reflects, buying nothing back: anyone able to measure a cleartext
	query can read it.

	Read through `padding_wanted` rather than by exchanging over each transport,
	because what it pins is the rule and not one query's length - and the same
	disjointness is what lets `exchange` treat cookies and padding as a choice
	between two.
	*/
	for kind in ([]config.Upstream_Kind{.UDP, .TCP, .TLS, .HTTPS}) {
		u := Upstream {
			spec = config.Upstream_Spec{name = "mock", kind = kind},
			// Cookies are configured on, so a kind that wanted both would show
			// up here rather than in whichever branch `exchange` reached first.
			cookies = true,
		}
		encrypted := kind == .TLS || kind == .HTTPS
		testing.expectf(t, padding_wanted(&u) == encrypted, "%v: padding_wanted is not %v", kind, encrypted)
		testing.expectf(t, cookies_wanted(&u) == !encrypted, "%v: cookies_wanted is not %v", kind, !encrypted)
	}
}
