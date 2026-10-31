package upstream

import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:dns"

/*
Issue #353: a reply carrying an OPT record outside the additional section is
malformed (RFC 6891 section 6.1.1), and so is one whose OPT is owned by a name
other than the root (section 6.1.2, issue #301). The group goes on to a member
that answers properly - the reading Unbound and BIND give both.
*/

@(private = "file")
Opt_Mock :: struct {
	socket: net.UDP_Socket,
	stop:   bool,
	hits:   int,
	stray:  bool,
	// Where set, the reply's OPT record in the additional section is owned by
	// this name rather than the root.
	owner:  string,
	// Where set, the reply carries two OPT records, the first holding the
	// query's client cookie back with a server cookie behind it.
	doubled: bool,
}

// Answers with an A record, with an OPT record in the answer section beside it
// where `stray` is set, and with one owned by `owner` where that is set.
@(private = "file")
opt_loop :: proc(m: ^Opt_Mock) {
	buf: [512]u8
	for !sync.atomic_load(&m.stop) {
		n, client, err := net.recv_udp(m.socket, buf[:])
		if err != nil || n < dns.HEADER_SIZE {
			continue
		}
		q, derr := dns.decode_message(buf[:n], context.temp_allocator)
		if derr != .None || len(q.question) != 1 {
			continue
		}
		sync.atomic_add(&m.hits, 1)
		answer := make([dynamic]dns.Record, context.temp_allocator)
		append(&answer, dns.Record{name = q.question[0].name, type = .A, class = .IN, ttl = 300, data = dns.Rdata_A{addr = {192, 0, 2, 1}}})
		if m.stray {
			append(&answer, dns.make_opt(4096, false))
		}
		additional: []dns.Record
		if m.owner != "" {
			additional = make([]dns.Record, 1, context.temp_allocator)
			additional[0] = dns.make_opt(4096, false)
			additional[0].name = m.owner
		}
		reply := dns.Message {
			id         = q.id,
			question   = q.question,
			answer     = answer[:],
			additional = additional,
		}
		reply.flags.qr = true
		reply.flags.rd = q.flags.rd
		reply.flags.ra = true
		if m.doubled {
			reply.additional = doubled_cookie_opts(buf[:n])
		}
		wire, _, _ := dns.encode_with_every_opt(reply, context.temp_allocator)
		_, _ = net.send_udp(m.socket, wire, client)
		free_all(context.temp_allocator)
	}
}

// The query's client cookie with a server cookie behind it, in the first of two
// OPT records.
@(private = "file")
doubled_cookie_opts :: proc(query: []u8) -> []dns.Record {
	client, asked := dns.peek_edns_option(query, .Cookie)
	cookie := make([]u8, COOKIE_CLIENT_LEN + 8, context.temp_allocator)
	if asked && len(client) >= COOKIE_CLIENT_LEN {
		copy(cookie, client[:COOKIE_CLIENT_LEN])
	}
	options := make([]dns.EDNS_Option, 1, context.temp_allocator)
	options[0] = dns.EDNS_Option{code = u16(dns.EDNS_Option_Code.Cookie), data = cookie}
	first := dns.make_opt(4096, false)
	first.data = dns.Rdata_OPT{options = options}
	opts := make([]dns.Record, 2, context.temp_allocator)
	opts[0] = first
	opts[1] = dns.make_opt(4096, false)
	return opts
}

@(private = "file")
start_mock :: proc(t: ^testing.T, m: ^Opt_Mock, name: string, cookies := false) -> (^Upstream, ^thread.Thread, bool) {
	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, serr == nil, "bind: %v", serr) {
		return nil, nil, false
	}
	m.socket = socket
	set_socket_timeouts(socket, 50 * time.Millisecond)
	bound, berr := net.bound_endpoint(socket)
	if !testing.expectf(t, berr == nil, "cannot read the responder's port: %v", berr) {
		net.close(socket)
		return nil, nil, false
	}
	u, uerr := make_upstream(
		config.Upstream_Spec{name = name, kind = .UDP, address = "127.0.0.1", port = bound.port},
		0,
		time.Second,
		context.allocator,
		cookies,
	)
	if !testing.expectf(t, uerr == .None, "upstream: %v", uerr) {
		net.close(socket)
		return nil, nil, false
	}
	return u, thread.create_and_start_with_poly_data(m, opt_loop), true
}

@(test)
test_a_stray_opt_record_is_swept_past :: proc(t: ^testing.T) {
	stray := Opt_Mock {
		stray = true,
	}
	expect_swept_past(t, &stray)
}

@(test)
test_an_opt_owned_by_a_name_other_than_root_is_swept_past :: proc(t: ^testing.T) {
	owned := Opt_Mock {
		owner = "example.",
	}
	expect_swept_past(t, &owned)
}

/*
A reply with a cookie in the first of two OPT records is swept past like any
other second OPT record, after the cookie strip as before it: the strip has to
rebuild the message to take the cookie out, and a rebuild that kept only the
first record would hand on a reply the check above no longer sees.
*/
@(test)
test_a_second_opt_record_survives_the_cookie_strip :: proc(t: ^testing.T) {
	doubled := Opt_Mock {
		doubled = true,
	}
	expect_swept_past(t, &doubled, cookies = true)
}

// A group of `stray`'s member first and a plain one behind it settles on the
// plain one, for a client's question and for the chain walk.
@(private = "file")
expect_swept_past :: proc(t: ^testing.T, stray: ^Opt_Mock, cookies := false) {
	plain: Opt_Mock
	// Neither started means neither closed: a zero socket here is fd 0, which
	// under `odin test` is another test's.
	bad, bad_thread, bad_ok := start_mock(t, stray, "stray", cookies)
	if !bad_ok {
		return
	}
	good, good_thread, good_ok := start_mock(t, &plain, "plain")
	if !good_ok {
		sync.atomic_store(&stray.stop, true)
		thread.join(bad_thread)
		thread.destroy(bad_thread)
		net.close(stray.socket)
		destroy(bad)
		return
	}
	defer {
		sync.atomic_store(&stray.stop, true)
		sync.atomic_store(&plain.stop, true)
		thread.join(bad_thread)
		thread.join(good_thread)
		thread.destroy(bad_thread)
		thread.destroy(good_thread)
		net.close(stray.socket)
		net.close(plain.socket)
		destroy(bad)
		destroy(good)
	}

	g := Group {
		servers   = []^Upstream{bad, good},
		strategy  = .Failover,
		timeout   = time.Second,
		attempts  = 1,
		allocator = context.allocator,
	}
	query := dns.Message{id = 0x3530, question = []dns.Question{{name = "www.example.com.", type = .A, class = .IN}}}
	query.flags.rd = true
	// An OPT record for the cookie to be attached to, where one is.
	if cookies {
		query.additional = {dns.make_opt(1232, false)}
	}
	wire, _, _ := dns.encode_message(query, context.temp_allocator)

	// A client's own question.
	resp, winner, err := resolve_readable(&g, wire, context.allocator)
	testing.expect_value(t, err, Error.None)
	testing.expect(t, winner == good, "resolve_readable took the reply with the stray OPT record")
	testing.expect(t, !dns.peek_opt_unreadable(resp), "the reply handed back carries the stray OPT record")
	delete(resp, context.allocator)

	// The chain walk's sweep.
	chain, chain_winner, chain_err := resolve_answerable(&g, wire, context.allocator)
	testing.expect_value(t, chain_err, Error.None)
	testing.expect(t, chain_winner == good, "resolve_answerable took the reply with the stray OPT record")
	delete(chain, context.allocator)

	testing.expect(t, sync.atomic_load(&stray.hits) >= 2, "the stray member was not asked first each time")
	free_all(context.temp_allocator)
}
