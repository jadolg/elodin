package server

import "core:net"
import "core:testing"

// Only `0.0.0.0`, `::` and `::ffff:0.0.0.0` are wildcard binds, which ask for each datagram's
// local end; a concrete address answers from itself.
@(test)
test_is_wildcard_is_only_the_unspecified_address :: proc(t: ^testing.T) {
	cases := []struct {
		address:  net.Address,
		wildcard: bool,
	} {
		{address = net.IP4_Address{}, wildcard = true},
		{address = net.IP6_Address{}, wildcard = true},
		{address = net.IP4_Loopback, wildcard = false},
		{address = net.IP6_Loopback, wildcard = false},
		{address = net.IP4_Address{192, 0, 2, 1}, wildcard = false},
		// Linux binds `::ffff:0.0.0.0` as the IPv4 wildcard on an IPv6 socket.
		{address = net.IP6_Address{5 = 0xffff}, wildcard = true},
		{address = net.IP6_Address{5 = 0xffff, 7 = 1}, wildcard = false},
	}
	for c in cases {
		testing.expectf(t, is_wildcard(c.address) == c.wildcard, "%v: wildcard %v", c.address, is_wildcard(c.address))
	}
}
