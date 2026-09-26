package harness

import "core:c"
import "core:net"
import "core:sys/posix"

/*
The largest input `feed` takes, so the write below can never fill the socket
buffer and block with nobody reading the other end. The `-max_len` fuzz.yml
gives the HTTP targets, so an input can span several of their reads, and well
under what a Unix socket buffers.
*/
MAX_FEED :: 64 * 1024

/*
A connected socket whose peer has already sent `data` and finished sending.

For the readers that take a socket rather than a slice: what they read is the
input and then end-of-stream, so a reader waiting for bytes the input did not
carry gets the peer's close instead of a hang. The peer's receive side is left
open, so a reader that writes first - the HTTP client sends its request before
it reads the answer - does not meet a closed socket either. Both ends go to
`unfeed`.
*/
feed :: proc(data: []u8) -> (read_end: net.TCP_Socket, peer: net.TCP_Socket, ok: bool) {
	pair: [2]posix.FD
	if posix.socketpair(.UNIX, .STREAM, .IP, &pair) != .OK {
		return
	}
	// Non-blocking, so a socket buffer smaller than the input truncates it rather
	// than blocking a send nobody is reading, which libFuzzer would report as a
	// timeout in the parser.
	posix.fcntl(pair[1], .SETFL, c.int(posix.O_NONBLOCK))
	sent := 0
	for sent < min(len(data), MAX_FEED) {
		n := posix.send(pair[1], raw_data(data[sent:]), uint(min(len(data), MAX_FEED) - sent), {})
		if n <= 0 {
			break
		}
		sent += n
	}
	posix.shutdown(pair[1], .WR)
	return net.TCP_Socket(pair[0]), net.TCP_Socket(pair[1]), true
}

unfeed :: proc(read_end, peer: net.TCP_Socket) {
	posix.close(posix.FD(read_end))
	posix.close(posix.FD(peer))
}
