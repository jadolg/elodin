package harness

import "core:c"
import "core:fmt"
import "core:net"
import "core:strconv"
import "core:strings"
import "core:sys/posix"

/*
The largest input `feed` takes, so the write below can never fill the socket
buffer and block with nobody reading the other end. It equals the `-max_len`
in the HTTP targets' `.max_len` files, so an input can span several of their
reads, and is well under what a Unix socket buffers. `check_max_len` holds a
target that feeds a socket to it.
*/
MAX_FEED :: 64 * 1024

/*
Refuse a `-max_len` past `MAX_FEED`, for a target that hands its input to `feed`.

`feed` cuts anything longer, so libFuzzer would spend its mutations on bytes the
parser never sees and nothing would say so. Called from the target's
`LLVMFuzzerInitialize`, which libFuzzer hands its whole command line before it
runs anything, so a `.max_len` raised past this fails the run at start-up - and
`fuzz-regression` starts every target with its `.max_len`, so it fails the PR
that raised it.
*/
check_max_len :: proc(args: []cstring) {
	for arg in args {
		PREFIX :: "-max_len="
		if !strings.has_prefix(string(arg), PREFIX) {
			continue
		}
		value := string(arg)[len(PREFIX):]
		// Bare digits only, nine at most, as `scripts/fuzz-max-len.sh` writes them:
		// `parse_int` skips `_` and wraps on overflow where libFuzzer stops at the
		// first non-digit and truncates to an int, so anything else can read small
		// here and large there.
		n, ok := strconv.parse_int(value, 10)
		if !ok || len(value) > 9 || strings.trim_left(value, "0123456789") != "" || n > MAX_FEED {
			// Straight to fd 2: built without an entry point, a target never runs
			// the start-up code that would set up `os.stderr`.
			msg := fmt.tprintfln("-max_len=%s: a target that feeds a socket takes at most MAX_FEED (%d), and feed cuts anything longer", value, MAX_FEED)
			posix.write(posix.STDERR_FILENO, raw_data(msg), len(msg))
			posix.exit(1)
		}
	}
}

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
	want := min(len(data), MAX_FEED)
	sent := 0
	for sent < want {
		n := posix.send(pair[1], raw_data(data[sent:]), uint(want - sent), {})
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
