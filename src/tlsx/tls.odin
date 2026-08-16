package tlsx

import "core:c"
import "core:fmt"
import "core:mem"
import "core:net"
import "core:strings"
import "core:sync"
import "core:sys/posix"
import "core:time"

Error :: enum u8 {
	None,
	Init_Failed,
	Context_Failed,
	Certificate_Failed,
	Handshake_Failed,
	Verify_Failed,
	Closed,
	Timeout,
	IO_Error,
	Alpn_Failed,
}

Context :: struct {
	ptr:       ^SSL_CTX,
	is_server: bool,
	// Whether the peer certificate is checked. Recorded because OpenSSL still
	// reports a verification result when verification is switched off, and
	// acting on it would reject every self-signed peer we were told to accept.
	verify:    bool,
	// Kept so the matching free uses the allocator the caller supplied.
	allocator: mem.Allocator,
	// ALPN protocol list, referenced by the selection callback for as long as
	// the context lives.
	alpn:      []u8,
}

/*
One TLS session.

A connection may be driven by two threads at once - HTTP/2 reads frames on the
connection's own thread while responses are written from handler-pool workers -
and OpenSSL does not allow that: one `SSL` object belongs to one thread at a
time. `mu` is what makes it so.

The lock is never held across a wait. The socket is put into non-blocking mode
once the handshake is done, so a call into OpenSSL either makes progress or
asks to be retried, and the waiting happens in `poll` with the lock released.
Holding it across a blocking read instead would park every writer behind a
reader sitting on a quiet connection, which on the DoH server is a ten-second
wait by default - trading a rare race for a constant stall.
*/
Conn :: struct {
	ssl:        ^SSL,
	socket:     net.TCP_Socket,
	allocator:  mem.Allocator,
	mu:         sync.Mutex,
	/*
	How long to wait for the socket, in nanoseconds; zero waits forever.

	Carried over from the SO_RCVTIMEO and SO_SNDTIMEO the caller set before the
	handshake, which stop applying once the socket goes non-blocking. Read and
	written atomically because `set_timeouts` may change them while the reader
	thread is using them.
	*/
	read_timeout_ns:  i64,
	write_timeout_ns: i64,
	/*
	How many threads are inside an OpenSSL call on this connection, and the
	highest that count ever reached.

	Only test builds maintain these - `ssl_enter` and `ssl_leave` compile to
	nothing otherwise - but the fields themselves are unconditional because
	`when` is not allowed in a struct body. Two integers per connection is not
	worth an awkward layout to avoid.

	They exist because the property this package owes OpenSSL, that one `SSL`
	is never driven by two threads at once, has no other observable symptom
	until the session quietly comes apart. `tlsx_test` asserts the peak never
	passes one.
	*/
	ssl_active: int,
	ssl_peak:   int,
}

// Bracket every call into OpenSSL on `conn`, so a test can see whether two
// threads were ever inside one at the same time. Compiled away outside tests.
@(private)
ssl_enter :: proc(conn: ^Conn) {
	when ODIN_TEST {
		active := sync.atomic_add(&conn.ssl_active, 1) + 1
		for {
			peak := sync.atomic_load(&conn.ssl_peak)
			if active <= peak {
				break
			}
			if _, swapped := sync.atomic_compare_exchange_strong(&conn.ssl_peak, peak, active); swapped {
				break
			}
		}
	}
}

@(private)
ssl_leave :: proc(conn: ^Conn) {
	when ODIN_TEST {
		sync.atomic_sub(&conn.ssl_active, 1)
	}
}

@(private)
init_once: sync.Once

@(private)
do_init :: proc() {
	OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nil)
}

// Safe to call from any thread and any number of times.
init :: proc() {
	sync.once_do(&init_once, do_init)
}

// The last OpenSSL error as text. Always call while the error is fresh; OpenSSL
// keeps errors on a per-thread queue.
last_error :: proc(allocator := context.allocator) -> string {
	code := ERR_get_error()
	if code == 0 {
		return strings.clone("no OpenSSL error recorded", allocator)
	}
	buf: [256]u8
	ERR_error_string_n(code, raw_data(buf[:]), len(buf))
	n := 0
	for n < len(buf) && buf[n] != 0 {
		n += 1
	}
	return strings.clone(string(buf[:n]), allocator)
}

/*
The errno behind the last handshake this thread gave up on, or `.NONE` when the
failure was OpenSSL's own.

A peer that resets or hangs up mid-handshake leaves the OpenSSL error queue
empty - nothing about the protocol went wrong - so `last_error` has nothing to
report and the operator is told only that the handshake failed. The errno is
the whole of the diagnosis in that case, and it is gone by the time the caller
logs, so it is recorded here as the handshake fails. Per thread, for the same
reason OpenSSL keeps its queue that way.
*/
@(private)
@(thread_local)
last_handshake_errno: posix.Errno

/*
Classify a handshake that did not complete.

`SSL_get_error` has to be read before anything else touches the session, and
errno before anything else makes a system call, so both are taken here, right
where the failure happened.

A blocking socket only ever asks to be retried because SO_RCVTIMEO or
SO_SNDTIMEO cut a wait short, which is a timeout rather than a protocol
failure, and a syscall-level error is the transport giving up rather than the
peer refusing us. Telling those apart is what lets a caller log the difference
between "the upstream is slow", "the upstream hung up on us", and "the
certificate did not check out".
*/
@(private)
handshake_error :: proc(ssl: ^SSL, ret: c.int) -> Error {
	saved := posix.errno()
	code := SSL_get_error(ssl, ret)
	last_handshake_errno = .NONE

	switch code {
	case SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE:
		return .Timeout
	case SSL_ERROR_ZERO_RETURN:
		return .Closed
	case SSL_ERROR_SYSCALL:
		// OpenSSL reports a blocking socket's expired timeout this way too on
		// some paths; it is still a timeout, not a broken connection.
		if saved == .EAGAIN || saved == .EWOULDBLOCK {
			return .Timeout
		}
		// errno zero here means the peer went away without a word: an EOF where
		// a handshake message was due.
		last_handshake_errno = saved
		return .Closed
	}
	return .Handshake_Failed
}

/*
Encode ALPN protocol names into OpenSSL's wire format: each name prefixed by its
one-byte length, all concatenated.
*/
@(private)
encode_alpn :: proc(protocols: []string, allocator := context.allocator) -> []u8 {
	total := 0
	for p in protocols {
		total += 1 + len(p)
	}
	if total == 0 {
		return nil
	}
	out := make([]u8, total, allocator)
	n := 0
	for p in protocols {
		out[n] = u8(len(p))
		n += 1
		copy(out[n:], transmute([]u8)p)
		n += len(p)
	}
	return out
}

/*
Create a client context.

`verify` turns on full chain and hostname verification against the system trust
store (or `ca_file` when given). Turning it off is only sensible when pinning to
an upstream by IP with a self-signed certificate.
*/
client_context :: proc(
	verify: bool,
	ca_file: string = "",
	alpn: []string = nil,
	allocator := context.allocator,
) -> (
	ctx: ^Context,
	err: Error,
) {
	init()
	ptr := SSL_CTX_new(TLS_client_method())
	if ptr == nil {
		return nil, .Context_Failed
	}
	if !ssl_ctx_set_min_proto_version(ptr, TLS1_2_VERSION) {
		SSL_CTX_free(ptr)
		return nil, .Context_Failed
	}

	if verify {
		ok: c.int
		if ca_file != "" {
			cpath := strings.clone_to_cstring(ca_file, context.temp_allocator)
			ok = SSL_CTX_load_verify_locations(ptr, cpath, nil)
		} else {
			ok = SSL_CTX_set_default_verify_paths(ptr)
		}
		if ok != 1 {
			SSL_CTX_free(ptr)
			return nil, .Certificate_Failed
		}
		SSL_CTX_set_verify(ptr, SSL_VERIFY_PEER, nil)
	} else {
		SSL_CTX_set_verify(ptr, SSL_VERIFY_NONE, nil)
	}

	if len(alpn) > 0 {
		wire := encode_alpn(alpn, context.temp_allocator)
		if SSL_CTX_set_alpn_protos(ptr, raw_data(wire), c.uint(len(wire))) != 0 {
			SSL_CTX_free(ptr)
			return nil, .Alpn_Failed
		}
	}

	ctx = new(Context, allocator)
	ctx.ptr = ptr
	ctx.allocator = allocator
	ctx.verify = verify
	return ctx, .None
}

/*
Pick a protocol, server preference first.

`arg` points at our length-prefixed preference list, most preferred first, with
a trailing zero byte marking the end. Choosing by *our* order rather than the
client's is what RFC 7301 recommends and is what lets a browser that offers
"h2, http/1.1" be answered with h2.
*/
@(private)
alpn_select :: proc "c" (
	ssl: ^SSL,
	out: ^[^]u8,
	outlen: ^u8,
	input: [^]u8,
	inlen: c.uint,
	arg: rawptr,
) -> c.int {
	wanted := ([^]u8)(arg)
	if wanted == nil {
		return SSL_TLSEXT_ERR_NOACK
	}

	w: u32 = 0
	for wanted[w] != 0 {
		want_len := u32(wanted[w])
		i: u32 = 0
		for i < u32(inlen) {
			plen := u32(input[i])
			if i + 1 + plen > u32(inlen) {
				break
			}
			if plen == want_len {
				same := true
				for k in 0 ..< plen {
					if input[i + 1 + k] != wanted[w + 1 + k] {
						same = false
						break
					}
				}
				if same {
					out^ = wanted[w + 1:]
					outlen^ = u8(want_len)
					return SSL_TLSEXT_ERR_OK
				}
			}
			i += 1 + plen
		}
		w += 1 + want_len
	}
	// Nothing in common. Failing here is better than answering HTTP/1.1 to a
	// client that will only ever send HTTP/2 frames.
	return SSL_TLSEXT_ERR_ALERT_FATAL
}

/*
Create a server context from a PEM certificate chain and private key.

`alpn_protocols` lists what the server will speak, most preferred first. A
client offering none of them gets a fatal alert rather than a mismatched
connection.
*/
server_context :: proc(
	cert_file, key_file: string,
	alpn_protocols: []string = nil,
	allocator := context.allocator,
) -> (
	ctx: ^Context,
	err: Error,
) {
	init()
	ptr := SSL_CTX_new(TLS_server_method())
	if ptr == nil {
		return nil, .Context_Failed
	}
	if !ssl_ctx_set_min_proto_version(ptr, TLS1_2_VERSION) {
		SSL_CTX_free(ptr)
		return nil, .Context_Failed
	}

	ccert := strings.clone_to_cstring(cert_file, context.temp_allocator)
	ckey := strings.clone_to_cstring(key_file, context.temp_allocator)
	if SSL_CTX_use_certificate_chain_file(ptr, ccert) != 1 {
		SSL_CTX_free(ptr)
		return nil, .Certificate_Failed
	}
	if SSL_CTX_use_PrivateKey_file(ptr, ckey, SSL_FILETYPE_PEM) != 1 {
		SSL_CTX_free(ptr)
		return nil, .Certificate_Failed
	}
	if SSL_CTX_check_private_key(ptr) != 1 {
		SSL_CTX_free(ptr)
		return nil, .Certificate_Failed
	}

	ctx = new(Context, allocator)
	ctx.ptr = ptr
	ctx.is_server = true
	ctx.allocator = allocator

	if len(alpn_protocols) > 0 {
		// The callback reads this on every handshake, so it has to outlive the
		// call; it is released with the context. The trailing zero terminates
		// the list.
		total := 1
		for p in alpn_protocols {
			total += 1 + len(p)
		}
		wire := make([]u8, total, allocator)
		n := 0
		for p in alpn_protocols {
			wire[n] = u8(len(p))
			copy(wire[n + 1:], transmute([]u8)p)
			n += 1 + len(p)
		}
		wire[n] = 0
		ctx.alpn = wire
		SSL_CTX_set_alpn_select_cb(ptr, alpn_select, raw_data(wire))
	}
	return ctx, .None
}

context_destroy :: proc(ctx: ^Context) {
	if ctx == nil {
		return
	}
	if ctx.ptr != nil {
		SSL_CTX_free(ctx.ptr)
	}
	if ctx.alpn != nil {
		delete(ctx.alpn, ctx.allocator)
	}
	free(ctx, ctx.allocator)
}

@(private)
socket_fd :: proc(s: net.TCP_Socket) -> c.int {
	return c.int(net.Socket(s))
}

/*
Wrap a connected socket in a TLS client session.

`hostname` is used both for SNI and, when the context verifies, for certificate
name checking. Pass "" only for an unverified context.
*/
client_connect :: proc(ctx: ^Context, socket: net.TCP_Socket, hostname: string, allocator := context.allocator) -> (conn: ^Conn, err: Error) {
	/*
	Verification without a name to verify against is not verification.

	`SSL_VERIFY_PEER` only asks that the chain end somewhere trusted; what ties
	the certificate to the peer we meant to reach is `SSL_set1_host` below, and
	that needs a name. Going ahead without one would accept any certificate any
	trusted CA ever issued, for any name at all - so this refuses instead,
	rather than quietly handing back a session the caller believes is checked.
	*/
	if ctx.verify && hostname == "" {
		return nil, .Verify_Failed
	}

	ssl := SSL_new(ctx.ptr)
	if ssl == nil {
		return nil, .Handshake_Failed
	}
	if SSL_set_fd(ssl, socket_fd(socket)) != 1 {
		SSL_free(ssl)
		return nil, .Handshake_Failed
	}
	if hostname != "" {
		/*
		A name with a NUL in it is not the name it looks like.

		`clone_to_cstring` ends the string at the first NUL, so what would be
		bound is a prefix of what was configured: "good.example\x00evil.test" is
		checked as "good.example" and the session comes back looking verified
		against a name nobody asked for. OpenSSL refuses embedded NULs itself -
		`X509_VERIFY_PARAM_set1_host` will not take one - but it only ever sees
		what survived the conversion, so the refusal belongs on this side of it.
		*/
		if strings.index_byte(hostname, 0) >= 0 {
			SSL_free(ssl)
			return nil, .Verify_Failed
		}
		chost := strings.clone_to_cstring(hostname, context.temp_allocator)

		// Fatal rather than best-effort: a server that picks its certificate by
		// SNI sends the wrong one when the extension is missing, and the name
		// check below then fails in a way that reads as the peer's fault.
		if !ssl_set_tlsext_host_name(ssl, chost) {
			SSL_free(ssl)
			return nil, .Handshake_Failed
		}

		/*
		Ties certificate verification to the name we asked for, and the result
		is checked because nothing downstream would notice if it had not taken.

		`SSL_VERIFY_PEER` on its own asks only that the chain end somewhere
		trusted, and `SSL_get_verify_result` returns X509_V_OK for a session with
		no name bound to it - so a discarded failure here is a handshake that
		accepts any certificate any trusted CA ever issued, for any name, while
		reporting itself as verified. That is the hole the empty-hostname refusal
		above exists to prevent, reached by another route.
		*/
		bound := SSL_set1_host(ssl, chost) == 1
		if ctx.verify && !bound {
			SSL_free(ssl)
			return nil, .Verify_Failed
		}
	}

	ERR_clear_error()
	if ret := SSL_connect(ssl); ret != 1 {
		err = handshake_error(ssl, ret)
		SSL_free(ssl)
		return nil, err
	}
	if ctx.verify && SSL_get_verify_result(ssl) != X509_V_OK {
		SSL_free(ssl)
		return nil, .Verify_Failed
	}

	conn = new(Conn, allocator)
	conn.ssl = ssl
	conn.socket = socket
	conn.allocator = allocator
	adopt_socket(conn)
	return conn, .None
}

server_accept :: proc(ctx: ^Context, socket: net.TCP_Socket, allocator := context.allocator) -> (conn: ^Conn, err: Error) {
	ssl := SSL_new(ctx.ptr)
	if ssl == nil {
		return nil, .Handshake_Failed
	}
	if SSL_set_fd(ssl, socket_fd(socket)) != 1 {
		SSL_free(ssl)
		return nil, .Handshake_Failed
	}
	ERR_clear_error()
	if ret := SSL_accept(ssl); ret != 1 {
		err = handshake_error(ssl, ret)
		SSL_free(ssl)
		return nil, err
	}
	conn = new(Conn, allocator)
	conn.ssl = ssl
	conn.socket = socket
	conn.allocator = allocator
	adopt_socket(conn)
	return conn, .None
}

/*
Take over the socket once the handshake is done.

Up to here only one thread has touched this connection, so the handshake ran on
a blocking socket bounded by whatever timeouts the caller set - which is exactly
what it wants. The data phase is different: it may have a reader and a writer at
the same time, and the lock keeping them out of each other's way must not span a
wait. So the timeouts are carried over as poll deadlines and the socket goes
non-blocking.
*/
@(private)
adopt_socket :: proc(conn: ^Conn) {
	conn.read_timeout_ns = i64(socket_timeout(conn.socket, .RCVTIMEO))
	conn.write_timeout_ns = i64(socket_timeout(conn.socket, .SNDTIMEO))
	_ = net.set_blocking(conn.socket, false)
}

// Zero when the caller set none, which means waits on this socket are unbounded.
@(private)
socket_timeout :: proc(socket: net.TCP_Socket, option: posix.Sock_Option) -> time.Duration {
	tv: posix.timeval
	length := posix.socklen_t(size_of(tv))
	if posix.getsockopt(posix.FD(socket_fd(socket)), posix.SOL_SOCKET, option, &tv, &length) != .OK {
		return 0
	}
	return time.Duration(tv.tv_sec) * time.Second + time.Duration(tv.tv_usec) * time.Microsecond
}

/*
Change how long this connection waits.

Callers that set socket options before handing the socket over need nothing
here; those were picked up at the handshake. This is for the ones that change
their mind afterwards, like the HTTP/2 upstream, which stretches its read
timeout into a polling interval once the connection turns long-lived.
*/
set_timeouts :: proc(conn: ^Conn, read, write: time.Duration) {
	sync.atomic_store(&conn.read_timeout_ns, i64(read))
	sync.atomic_store(&conn.write_timeout_ns, i64(write))
}

/*
Change how long a read waits and leave the write deadline where it is.

For a caller that shortens its reads for a moment without a view on what the
connection's writes should be waiting for - draining what a client had already
sent before closing on it, where the read wait is a bound on the drain and the
write wait is still the connection's. `set_timeouts` would need the writer's
figure passed back in to leave it alone, which is a value that caller has no
business knowing.
*/
set_read_timeout :: proc(conn: ^Conn, read: time.Duration) {
	sync.atomic_store(&conn.read_timeout_ns, i64(read))
}

@(private)
Op :: enum u8 {
	Read,
	Write,
}

/*
One transfer, with the waiting done outside the lock.

The lock covers only the call into OpenSSL, which cannot block now that the
socket is non-blocking: it either makes progress or asks to be retried once the
socket is ready. That wait then happens in `poll` with the lock released, so a
reader parked on an idle connection holds nothing a writer needs.
*/
@(private)
transfer :: proc(conn: ^Conn, op: Op, buf: []u8, timeout: time.Duration) -> (n: int, err: Error) {
	deadline := time.time_add(time.now(), timeout)
	for {
		sync.mutex_lock(&conn.mu)
		ERR_clear_error()
		ssl_enter(conn)
		ret: c.int
		switch op {
		case .Read:
			ret = SSL_read(conn.ssl, raw_data(buf), c.int(len(buf)))
		case .Write:
			ret = SSL_write(conn.ssl, raw_data(buf), c.int(len(buf)))
		}
		// Read under the lock that covered the call it describes: it reports on
		// the session's state, which another thread may move the moment the
		// lock goes.
		code := c.int(SSL_ERROR_NONE) if ret > 0 else SSL_get_error(conn.ssl, ret)
		ssl_leave(conn)
		sync.mutex_unlock(&conn.mu)

		if ret > 0 {
			return int(ret), .None
		}
		switch code {
		case SSL_ERROR_WANT_READ:
			if !wait_ready(conn, {.IN}, timeout, deadline) {
				return 0, .Timeout
			}
		case SSL_ERROR_WANT_WRITE:
			if !wait_ready(conn, {.OUT}, timeout, deadline) {
				return 0, .Timeout
			}
		case SSL_ERROR_ZERO_RETURN:
			return 0, .Closed
		case SSL_ERROR_SYSCALL:
			// A would-block arrives as WANT_READ or WANT_WRITE now, so this is
			// a real failure rather than the timeout it used to stand for.
			return 0, .Closed if ret == 0 else .IO_Error
		case:
			return 0, .IO_Error
		}
	}
}

// Wait for the socket, with the connection's lock released. A zero timeout
// waits indefinitely, which is what a blocking socket with no SO_RCVTIMEO did.
@(private)
wait_ready :: proc(conn: ^Conn, events: posix.Poll_Event, timeout: time.Duration, deadline: time.Time) -> bool {
	for {
		ms: c.int = -1
		if timeout > 0 {
			remaining := time.diff(time.now(), deadline)
			if remaining <= 0 {
				return false
			}
			ms = c.int(time.duration_milliseconds(remaining))
			if ms <= 0 {
				ms = 1
			}
		}
		fds := [1]posix.pollfd{{fd = posix.FD(socket_fd(conn.socket)), events = events}}
		ret := posix.poll(raw_data(fds[:]), 1, ms)
		if ret > 0 {
			return true
		}
		if ret == 0 {
			return false
		}
		if posix.errno() == .EINTR {
			continue
		}
		return false
	}
}

read :: proc(conn: ^Conn, buf: []u8) -> (n: int, err: Error) {
	if len(buf) == 0 {
		return 0, .None
	}
	return transfer(conn, .Read, buf, time.Duration(sync.atomic_load(&conn.read_timeout_ns)))
}

write :: proc(conn: ^Conn, buf: []u8) -> (n: int, err: Error) {
	timeout := time.Duration(sync.atomic_load(&conn.write_timeout_ns))
	written := 0
	for written < len(buf) {
		/*
		Partial writes are off by default, so a successful SSL_write took the
		whole slice it was given and this loop turns over once. It stays a loop
		because that mode is a per-context setting, and a future context that
		enabled it would otherwise silently drop the tail.
		*/
		sent, werr := transfer(conn, .Write, buf[written:], timeout)
		if werr != .None {
			return written, werr
		}
		written += sent
	}
	return written, .None
}

// Read exactly len(buf) bytes, or fail.
read_full :: proc(conn: ^Conn, buf: []u8) -> Error {
	got := 0
	for got < len(buf) {
		n, err := read(conn, buf[got:])
		if err != .None {
			return err
		}
		if n == 0 {
			return .Closed
		}
		got += n
	}
	return .None
}

close :: proc(conn: ^Conn) {
	if conn == nil {
		return
	}
	if conn.ssl != nil {
		// Callers are expected to have stopped using the connection by now, but
		// taking the lock costs nothing here and keeps the rule about this `SSL`
		// object true right to the end of its life.
		sync.mutex_lock(&conn.mu)
		SSL_shutdown(conn.ssl)
		SSL_free(conn.ssl)
		conn.ssl = nil
		sync.mutex_unlock(&conn.mu)
	}
	net.close(conn.socket)
	free(conn, conn.allocator)
}

// The protocol agreed during the handshake, or "" if none was negotiated.
alpn_protocol :: proc(conn: ^Conn) -> string {
	data: [^]u8
	length: c.uint
	SSL_get0_alpn_selected(conn.ssl, &data, &length)
	if length == 0 || data == nil {
		return ""
	}
	return string(data[:length])
}

describe_error :: proc(err: Error, allocator := context.allocator) -> string {
	#partial switch err {
	case .Handshake_Failed, .Certificate_Failed, .Context_Failed:
		detail := last_error(context.temp_allocator)
		return fmt.aprintf("%v: %s", err, detail, allocator = allocator)
	case .Closed:
		// Set only by a handshake that the transport killed; a connection closed
		// anywhere else leaves it clear and falls through to the bare name.
		if last_handshake_errno != .NONE {
			return fmt.aprintf("%v: %s", err, posix.strerror(last_handshake_errno), allocator = allocator)
		}
	}
	return fmt.aprintf("%v", err, allocator = allocator)
}
