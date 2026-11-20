package loop

import "core:net"
import "core:sys/linux"
import "core:testing"

// All of 127.0.0.0/8 is local on Linux: a second local address with no setup.
@(private = "file")
SECOND_LOOPBACK :: net.IP4_Address{127, 0, 0, 2}

/*
A wildcard socket, a client, and a datagram from the client to `asked`. The
server socket reports `asked` as the local end, and a reply sent from it reaches
the client from `asked`; a reply sent from no local end leaves from the address
the route picks, which for a loopback client is 127.0.0.1.
*/
@(test)
test_a_wildcard_socket_answers_from_the_address_asked :: proc(t: ^testing.T) {
	for family in ([]net.Address_Family{.IP4, .IP6}) {
		server, err := net.make_unbound_udp_socket(family)
		if !testing.expectf(t, err == nil, "socket: %v", err) {
			return
		}
		defer net.close(server)
		testing.expect_value(t, want_destination(server, v6 = family == .IP6), linux.Errno.NONE)
		wildcard: net.Address = net.IP4_Address{} if family == .IP4 else net.IP6_Address{}
		if berr := net.bind(server, {wildcard, 0}); !testing.expectf(t, berr == nil, "bind: %v", berr) {
			return
		}
		bound, bound_err := net.bound_endpoint(server)
		if !testing.expectf(t, bound_err == nil, "bound_endpoint: %v", bound_err) {
			return
		}
		if serr := net.set_blocking(server, false); !testing.expectf(t, serr == nil, "set_blocking: %v", serr) {
			return
		}

		client, cerr := net.make_unbound_udp_socket(.IP4)
		if !testing.expectf(t, cerr == nil, "client socket: %v", cerr) {
			return
		}
		defer net.close(client)
		if oerr := net.set_option(client, .Receive_Timeout, WAIT); !testing.expectf(t, oerr == nil, "set_option: %v", oerr) {
			return
		}

		cases := []struct {
			asked:    net.IP4_Address,
			from:     bool,
			expected: net.IP4_Address,
		} {
			{asked = SECOND_LOOPBACK, from = true, expected = SECOND_LOOPBACK},
			{asked = net.IP4_Loopback, from = true, expected = net.IP4_Loopback},
			// The premise: without the local end, the route picks 127.0.0.1.
			{asked = SECOND_LOOPBACK, from = false, expected = net.IP4_Loopback},
		}
		for c in cases {
			if _, err := net.send_udp(client, []u8{1, 2, 3}, {c.asked, bound.port}); !testing.expectf(t, err == nil, "send: %v", err) {
				return
			}
			buf: [16]u8
			local: Udp_Local
			n, peer, rerr := recv_udp(server, buf[:], &local)
			if !testing.expectf(t, rerr == nil && n == 3, "recv: %d bytes, %v", n, rerr) {
				return
			}
			got, ok := unmapped_v4(local.address)
			testing.expectf(t, ok && got == c.asked, "%v: local end %v, want %v", family, local.address, c.asked)
			if !c.from {
				local = {}
			}
			if _, err := send_udp(server, []u8{4, 5}, peer, local); !testing.expectf(t, err == nil, "reply: %v", err) {
				return
			}
			_, source, cerr := net.recv_udp(client, buf[:])
			if !testing.expectf(t, cerr == nil, "client recv: %v", cerr) {
				return
			}
			testing.expectf(t, source.address == net.Address(c.expected), "%v: asked %v, answered from %v, want %v", family, c.asked, source.address, c.expected)
		}
	}
}

/*
An IPv6 datagram on a wildcard IPv6 socket: `IPV6_PKTINFO` names the destination
and the interface it came in on, which for `::1` is the loopback's, never 0.
*/
@(test)
test_an_ipv6_datagram_reports_its_destination_and_interface :: proc(t: ^testing.T) {
	server, err := net.make_unbound_udp_socket(.IP6)
	if !testing.expectf(t, err == nil, "socket: %v", err) {
		return
	}
	defer net.close(server)
	testing.expect_value(t, want_destination(server, v6 = true), linux.Errno.NONE)
	if berr := net.bind(server, {net.IP6_Address{}, 0}); !testing.expectf(t, berr == nil, "bind: %v", berr) {
		return
	}
	bound, bound_err := net.bound_endpoint(server)
	if !testing.expectf(t, bound_err == nil, "bound_endpoint: %v", bound_err) {
		return
	}
	if serr := net.set_blocking(server, false); !testing.expectf(t, serr == nil, "set_blocking: %v", serr) {
		return
	}
	client, cerr := net.make_unbound_udp_socket(.IP6)
	if !testing.expectf(t, cerr == nil, "client socket: %v", cerr) {
		return
	}
	defer net.close(client)
	if _, err := net.send_udp(client, []u8{1}, {net.IP6_Loopback, bound.port}); !testing.expectf(t, err == nil, "send: %v", err) {
		return
	}
	buf: [16]u8
	local: Udp_Local
	_, _, rerr := recv_udp(server, buf[:], &local)
	if !testing.expectf(t, rerr == nil, "recv: %v", rerr) {
		return
	}
	testing.expectf(t, local.address == net.Address(net.IP6_Loopback) && local.ifindex != 0, "local end %v", local)
}

@(private = "file")
unmapped_v4 :: proc(a: net.Address) -> (net.IP4_Address, bool) {
	switch x in a {
	case net.IP4_Address:
		return x, true
	case net.IP6_Address:
		b := transmute([16]u8)x
		for i in 0 ..< 10 {
			if b[i] != 0 {
				return {}, false
			}
		}
		if b[10] == 0xff && b[11] == 0xff {
			return {b[12], b[13], b[14], b[15]}, true
		}
	}
	return {}, false
}

/*
What `local_of` takes from the control messages: `ipi_spec_dst` and not
`ipi_addr`, an IPv6 destination with its interface, and neither a mapped IPv4
address nor a multicast one from `IPV6_PKTINFO`. A message whose length runs
short of its header or past the buffer ends the walk.
*/
@(test)
test_local_of_reads_the_pktinfo_messages :: proc(t: ^testing.T) {
	unicast6 := [16]u8{0 = 0x20, 1 = 0x01, 2 = 0x0d, 3 = 0xb8, 15 = 1}
	mapped := [16]u8{10 = 0xff, 11 = 0xff, 12 = 192, 13 = 0, 14 = 2, 15 = 1}
	multicast := [16]u8{0 = 0xff, 1 = 0x02, 15 = 1}

	control: [CONTROL_WORDS]uint
	bytes := ([^]u8)(&control)

	n := put_cmsg(bytes, IPPROTO_IP, IP_PKTINFO, In_Pktinfo{ifindex = 3, spec_dst = {192, 0, 2, 1}, addr = {255, 255, 255, 255}})
	got := local_of(bytes[:n])
	testing.expectf(t, got.address == net.Address(net.IP4_Address{192, 0, 2, 1}) && got.ifindex == 0, "IP_PKTINFO: %v", got)

	n = put_cmsg(bytes, IPPROTO_IPV6, IPV6_PKTINFO, In6_Pktinfo{addr = unicast6, ifindex = 7})
	got = local_of(bytes[:n])
	testing.expectf(t, got.address == net.Address(transmute(net.IP6_Address)unicast6) && got.ifindex == 7, "IPV6_PKTINFO: %v", got)

	for skipped in ([][16]u8{mapped, multicast}) {
		n = put_cmsg(bytes, IPPROTO_IPV6, IPV6_PKTINFO, In6_Pktinfo{addr = skipped, ifindex = 7})
		got = local_of(bytes[:n])
		testing.expectf(t, got.address == nil, "IPV6_PKTINFO for %v: %v", skipped, got)
	}

	// Both kinds, as a dual-stack socket gets them for an IPv4 datagram: the
	// mapped IPv6 one is passed over, in either order.
	first := put_cmsg(bytes, IPPROTO_IPV6, IPV6_PKTINFO, In6_Pktinfo{addr = mapped, ifindex = 7})
	n = first + put_cmsg(bytes[first:], IPPROTO_IP, IP_PKTINFO, In_Pktinfo{spec_dst = {192, 0, 2, 1}})
	got = local_of(bytes[:n])
	testing.expectf(t, got.address == net.Address(net.IP4_Address{192, 0, 2, 1}), "both kinds: %v", got)

	// Lengths the walk must not follow.
	n = put_cmsg(bytes, IPPROTO_IP, IP_PKTINFO, In_Pktinfo{spec_dst = {192, 0, 2, 1}})
	testing.expectf(t, local_of(bytes[:CMSG_DATA + size_of(In_Pktinfo) - 1]).address == nil, "a message cut short was read")
	control[0] = uint(CMSG_DATA - 1)
	testing.expectf(t, local_of(bytes[:n]).address == nil, "a length short of the header was read")
}
