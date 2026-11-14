package server

import "core:mem"
import "core:net"
import "core:sys/linux"
import "core:sync"
import "core:sys/posix"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:loop"
import "elodin:tlsx"

/*
Answers written to one stream from several fibers at once arrive whole, each
behind its own length prefix, when every write stalls part-way: the peer
advertises a window of a few KB and the writer's send buffer is as small, so an
answer many times either has to wait for the peer to read, part-written, while
the other fibers want the socket.
*/

@(private = "file")
STALL_WRITERS :: 4
// Many times the stalled buffers, so every answer is written in several parts.
@(private = "file")
STALL_ANSWER :: 32 * 1024
@(private = "file")
STALL_TIMEOUT :: 5 * time.Second

@(private = "file")
Write_Job :: struct {
	session:  ^Stream_Session,
	response: []u8,
	// Whether the scratch has no room to frame the answer.
	dry:      bool,
}

@(private = "file")
write_job :: proc(data: rawptr) {
	job := cast(^Write_Job)data
	context.temp_allocator = mem.nil_allocator() if job.dry else context.temp_allocator
	stream_write_answer(job.session, job.response)
}

// Shrink a socket buffer to the kernel's floor, and say whether it took: read
// back, since one that did not leaves a test that stalls nothing.
@(private = "file")
shrink_buffer :: proc(socket: net.TCP_Socket, option: posix.Sock_Option) -> bool {
	want: i32 = 2048
	if posix.setsockopt(posix.FD(socket), i32(posix.SOL_SOCKET), option, &want, posix.socklen_t(size_of(want))) != .OK {
		return false
	}
	got: i32
	size := posix.socklen_t(size_of(got))
	if posix.getsockopt(posix.FD(socket), i32(posix.SOL_SOCKET), option, &got, &size) != .OK {
		return false
	}
	// Linux doubles what it is given and holds it at a floor of a few KB.
	return got <= 16 * 1024
}

// A loopback listener whose connections advertise a window of a few KB.
@(private = "file")
stall_listener :: proc(t: ^testing.T) -> (listener: net.TCP_Socket, bound: net.Endpoint, ok: bool) {
	fd, serr := linux.socket(.INET, .STREAM, {.CLOEXEC}, .TCP)
	if !testing.expectf(t, serr == .NONE, "socket: %v", serr) {
		return
	}
	listener = net.TCP_Socket(fd)
	// Set before `listen`, so the handshake advertises it.
	ok = testing.expect(t, shrink_buffer(listener, .RCVBUF), "cannot shrink the receive buffer")
	if ok {
		berr := net.bind(listener, net.Endpoint{address = net.IP4_Loopback, port = 0})
		ok = testing.expectf(t, berr == nil, "bind: %v", berr)
	}
	if ok {
		// So the accepting thread gives up on a dial that never came.
		oerr := net.set_option(listener, .Receive_Timeout, STALL_TIMEOUT)
		ok = testing.expectf(t, oerr == nil, "cannot bound the accept: %v", oerr)
	}
	if ok {
		lerr := linux.listen(fd, 1)
		ok = testing.expectf(t, lerr == .NONE, "listen: %v", lerr)
	}
	if ok {
		berr: net.Network_Error
		bound, berr = net.bound_endpoint(listener)
		ok = testing.expectf(t, berr == nil, "bound_endpoint: %v", berr)
	}
	if !ok {
		net.close(listener)
	}
	return
}

@(private = "file")
Stall_Accept :: struct {
	listener: net.TCP_Socket,
	ctx:      ^tlsx.Context,
	conn:     ^tlsx.Conn,
}

@(private = "file")
stall_accept :: proc(a: ^Stall_Accept) {
	socket, _, err := net.accept_tcp(a.listener)
	if err != nil {
		return
	}
	if net.set_option(socket, .Receive_Timeout, STALL_TIMEOUT) != nil {
		net.close(socket)
		return
	}
	conn, terr := tlsx.server_accept(a.ctx, socket)
	if terr != .None {
		net.close(socket)
		return
	}
	a.conn = conn
}

/*
A TLS session on loopback whose writes stall: `writer` with a send buffer of a
few KB, `reader` behind a window as small, both given `STALL_TIMEOUT` to wait.
The writer is the client end, which makes no difference to what is written.
*/
@(private = "file")
Stall_Pair :: struct {
	server_ctx: ^tlsx.Context,
	client_ctx: ^tlsx.Context,
	writer:     ^tlsx.Conn,
	reader:     ^tlsx.Conn,
}

@(private = "file")
stall_pair :: proc(t: ^testing.T, p: ^Stall_Pair) -> bool {
	cert, key, have := ensure_profile_certs()
	if !testing.expect(t, have, "no certificate available and openssl could not make one") {
		return false
	}
	listener, bound, listening := stall_listener(t)
	if !listening {
		return false
	}
	defer net.close(listener)
	serr, cerr: tlsx.Error
	p.server_ctx, serr = tlsx.server_context(cert, key)
	if !testing.expectf(t, serr == .None, "server_context: %v", serr) {
		return false
	}
	p.client_ctx, cerr = tlsx.client_context(false)
	if !testing.expectf(t, cerr == .None, "client_context: %v", cerr) {
		return false
	}

	accept := Stall_Accept{listener = listener, ctx = p.server_ctx}
	th := thread.create_and_start_with_poly_data(&accept, stall_accept)
	if !testing.expect(t, th != nil, "cannot start the accepting thread") {
		return false
	}
	socket, derr := net.dial_tcp_from_endpoint(bound)
	connected := testing.expectf(t, derr == nil, "dial: %v", derr)
	if connected {
		// Before the handshake, which carries it over as the write deadline.
		oerr := net.set_option(socket, .Send_Timeout, STALL_TIMEOUT)
		connected = testing.expectf(t, oerr == nil, "cannot bound the writes: %v", oerr)
		herr := tlsx.Error.None
		if connected {
			p.writer, herr = tlsx.client_connect(p.client_ctx, socket, "elodin.local")
			connected = testing.expectf(t, herr == .None, "client_connect: %v", herr)
		}
		if !connected {
			net.close(socket)
		}
	}
	thread.join(th)
	thread.destroy(th)
	p.reader = accept.conn
	return connected &&
		testing.expect(t, p.reader != nil, "the accepting end never completed its handshake") &&
		testing.expect(t, shrink_buffer(socket, .SNDBUF), "cannot shrink the send buffer")
}

@(private = "file")
stall_pair_destroy :: proc(p: ^Stall_Pair) {
	tlsx.close(p.writer)
	tlsx.close(p.reader)
	tlsx.context_destroy(p.server_ctx)
	tlsx.context_destroy(p.client_ctx)
}

@(private = "file")
answers_arrive_whole :: proc(t: ^testing.T, dry: bool) {
	pair: Stall_Pair
	defer stall_pair_destroy(&pair)
	if !stall_pair(t, &pair) {
		return
	}
	tl: Test_Loop
	if !testing.expect(t, start_test_loop(&tl), "no loop") {
		return
	}
	session := Stream_Session {
		conn = Conn{socket = pair.writer.socket, tls = pair.writer},
	}
	jobs: [STALL_WRITERS]Write_Job
	responses: [STALL_WRITERS][STALL_ANSWER]u8
	started := 0
	for &job, i in jobs {
		for &b in responses[i] {
			b = u8('a' + i)
		}
		job = Write_Job{&session, responses[i][:], dry}
		if _, ok := loop.spawn(tl.loops[0], write_job, &job); ok {
			started += 1
		}
	}
	defer stop_test_loop(&tl)
	if !testing.expectf(t, started == STALL_WRITERS, "%d of %d writers started", started, STALL_WRITERS) {
		return
	}

	seen: [STALL_WRITERS]bool
	body := make([]u8, STALL_ANSWER, context.temp_allocator)
	for n in 0 ..< STALL_WRITERS {
		prefix: [2]u8
		if !testing.expectf(t, tlsx.read_full(pair.reader, prefix[:]) == .None, "answer %d: no prefix", n) {
			return
		}
		length := int(prefix[0]) << 8 | int(prefix[1])
		if !testing.expectf(t, length == STALL_ANSWER, "answer %d: a prefix of %d, not %d", n, length, STALL_ANSWER) {
			return
		}
		if !testing.expectf(t, tlsx.read_full(pair.reader, body) == .None, "answer %d: the body did not arrive", n) {
			return
		}
		writer_index := int(body[0]) - 'a'
		if !testing.expectf(t, writer_index >= 0 && writer_index < STALL_WRITERS && !seen[writer_index], "answer %d: starts with %q", n, body[0]) {
			return
		}
		seen[writer_index] = true
		for b, at in body {
			if b != body[0] {
				testing.expectf(t, false, "answer %d: byte %d is %q in an answer of %q, so another answer was written into it", n, at, b, body[0])
				return
			}
		}
	}
	testing.expect(t, stream_answered(&session), "no answer was counted as written")
	testing.expect(t, !sync.atomic_load(&session.broken), "a write failed")
}

@(test)
test_stream_answers_written_at_once_arrive_whole :: proc(t: ^testing.T) {
	answers_arrive_whole(t, dry = false)
}

// The prefix and the body written apart, where the scratch has no room to frame
// the two together, are still one answer on the wire.
@(test)
test_stream_answers_with_no_room_to_frame_arrive_whole :: proc(t: ^testing.T) {
	answers_arrive_whole(t, dry = true)
}

/*
Once a write on the connection has failed nothing more is written to it, and an
answer written on a connection that has not is.
*/
@(test)
test_a_broken_stream_is_not_written_to :: proc(t: ^testing.T) {
	pair: Stall_Pair
	defer stall_pair_destroy(&pair)
	if !stall_pair(t, &pair) {
		return
	}
	session := Stream_Session {
		conn   = Conn{socket = pair.writer.socket, tls = pair.writer},
		broken = true,
	}
	skipped := [?]u8{'s', 's', 's', 's'}
	written := [?]u8{'w', 'w', 'w', 'w'}
	jobs := [2]Write_Job{{&session, skipped[:], false}, {&session, written[:], false}}
	for &job in jobs {
		tl: Test_Loop
		if !testing.expect(t, start_test_loop(&tl), "no loop") {
			return
		}
		_, started := loop.spawn(tl.loops[0], write_job, &job)
		stop_test_loop(&tl)
		if !testing.expect(t, started, "a writer did not start") {
			return
		}
		testing.expect(t, stream_answered(&session) != sync.atomic_load(&session.broken), "answered and broken agree")
		session.broken = false
	}
	got: [2 + len(written)]u8
	if !testing.expect(t, tlsx.read_full(pair.reader, got[:]) == .None, "the answer on the healthy connection did not arrive") {
		return
	}
	testing.expectf(t, got[2] == 'w', "the first answer to arrive starts with %q, the one written while broken", got[2])
}

/*
A write that fails ends the connection's reads too: the reader, parked waiting
for the client's next message, is woken at once rather than at the end of its
idle wait, so a connection nothing more can be written to does not keep its
place in `max_connections`.
*/
@(test)
test_a_failed_write_ends_the_reads :: proc(t: ^testing.T) {
	pair: Stall_Pair
	defer stall_pair_destroy(&pair)
	if !stall_pair(t, &pair) {
		return
	}
	// Long enough that a read waiting it out is told apart from one ended.
	tlsx.set_timeouts(pair.writer, STALL_TIMEOUT, 100 * time.Millisecond)
	session := Stream_Session {
		conn = Conn{socket = pair.writer.socket, tls = pair.writer},
	}
	// Never read, so the write stalls past its timeout.
	response: [STALL_ANSWER]u8
	job := Write_Job{&session, response[:], false}
	tl: Test_Loop
	if !testing.expect(t, start_test_loop(&tl), "no loop") {
		return
	}
	_, started := loop.spawn(tl.loops[0], write_job, &job)
	stop_test_loop(&tl)
	if !testing.expect(t, started, "the writer did not start") {
		return
	}
	// The premise: the write failed.
	if !testing.expect(t, sync.atomic_load(&session.broken), "the stalled write did not fail") {
		return
	}
	buf: [64]u8
	start := time.tick_now()
	_, err := tlsx.read(pair.writer, buf[:])
	testing.expectf(t, err != .None && err != .Timeout, "the read ended %v after %v, not at once", err, time.tick_since(start))
}
