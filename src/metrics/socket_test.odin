package metrics

import "core:net"
import "core:os"
import "core:testing"

/*
Two lines of a real `/proc/net/udp`, with the header the kernel writes above
them.

Kept verbatim, including the alignment: the fields are positional and the header
is a line that has to be skipped by not parsing rather than by being recognised,
so a fixture tidied into single spaces would not exercise what the parser
actually meets.
*/
@(private = "file")
UDP_TABLE ::
`  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   72: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 25089 2 0000000000000000 1234
   73: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 25090 2 0000000000000000 0
   99: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 19832 2 0000000000000000 77
`

// The counter is read per socket, and a socket that dropped nothing is not the
// same as one that is not in the table.
@(test)
test_socket_drops_are_read_per_inode :: proc(t: ^testing.T) {
	inodes := []u64{25089, 25090}
	drops := []u64{9, 9}
	matched := add_socket_drops(UDP_TABLE, inodes, drops)
	testing.expect_value(t, matched, 2)
	testing.expect_value(t, drops[0], 1234)
	testing.expect_value(t, drops[1], 0)
}

/*
A socket that is not in the table leaves the answer incomplete.

The reason `socket_drops` reports that as "cannot say" rather than as a total: a
figure that quietly left one reader out would be too small, and too small is the
direction that makes an operator stop looking.
*/
@(test)
test_a_missing_socket_is_not_a_zero :: proc(t: ^testing.T) {
	inodes := []u64{25089, 40404}
	drops := []u64{0, 0}
	testing.expect_value(t, add_socket_drops(UDP_TABLE, inodes, drops), 1)

	// And the whole answer is withheld rather than published short. 0 is an
	// inode that could not be read, which is the same case.
	unread := []u64{0}
	out := []u64{0}
	testing.expect(t, !socket_drops(unread, out), "a socket with no inode was reported as measured")
	testing.expect(t, !socket_drops({}, {}), "a listener with no readers was reported as measured")
}

/*
The header, and anything else that is not a socket, is not a socket.

The header line has ten fields and the parser wants at least thirteen; without
that check its tenth field is the word `inode`, which parses as nothing and
would leave a line matching whichever socket happened to have inode 0.
*/
@(test)
test_lines_that_are_not_sockets_are_skipped :: proc(t: ^testing.T) {
	inodes := []u64{25089}
	drops := []u64{0}
	testing.expect_value(t, add_socket_drops("", inodes, drops), 0)
	testing.expect_value(t, add_socket_drops("  sl  local_address rem_address\n", inodes, drops), 0)
	testing.expect_value(t, add_socket_drops("not a table at all\n\n\n", inodes, drops), 0)
	testing.expect_value(t, drops[0], 0)
}

/*
The inode of a socket this process holds is the one `/proc/net/udp` lists it
under.

Asserted against the table rather than against a number, because the number is
whatever the kernel allocated: a socket bound here is looked up by the inode
this reports, and finding its line is what says the two agree. Without it the
drop counter could be read for the wrong socket, or for none, and would report
zero either way.
*/
@(test)
test_a_bound_socket_is_found_by_its_inode :: proc(t: ^testing.T) {
	socket, err := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if err != nil {
		testing.expectf(t, false, "cannot bind a loopback socket: %v", err)
		return
	}
	defer net.close(socket)

	inode := socket_inode(int(socket))
	if !testing.expect(t, inode != 0, "the socket's inode could not be read") {
		return
	}
	drops := []u64{0}
	inodes := []u64{inode}
	testing.expect(t, socket_drops(inodes, drops), "a socket this process holds was not in /proc/net/udp")
	// Nothing has been sent to it, so the kernel has dropped nothing on it.
	testing.expect_value(t, drops[0], 0)

	free_all(context.temp_allocator)
}

// A descriptor that is not a socket has no inode to report, and neither has one
// that is not open.
@(test)
test_socket_inode_says_nothing_about_what_is_not_a_socket :: proc(t: ^testing.T) {
	testing.expect_value(t, socket_inode(-1), 0)

	/*
	A descriptor this test opened, rather than one it inherited.

	Standard input would be the obvious open non-socket, and usually is - but
	whoever started the process decides that, and a runner using socket
	activation or an inetd-style supervisor hands its child a socket on fd 0.
	That would fail this case for a reason that has nothing to do with the
	parser.
	*/
	f, err := os.open("/dev/null")
	if !testing.expectf(t, err == nil, "cannot open /dev/null: %v", err) {
		return
	}
	defer os.close(f)
	testing.expect_value(t, socket_inode(int(os.fd(f))), 0)
}
