package tlsx

import "core:mem"
import "core:net"
import "core:os"
import "core:strings"
import "core:sync"
import "core:sys/posix"
import "core:testing"
import "core:thread"
import "core:time"

/*
Tests run a real TLS session over loopback against a self-signed pair. Nothing
here mocks OpenSSL: the property under test is how this package drives it from
more than one thread at a time, and a mock would define that away.
*/

/*
Provide a certificate, the same way the integration suite does.

`certs/` is gitignored, so a developer usually has one and CI never does. When
it is missing, one is generated into the system temp directory and left there to
be reused by later runs, which keeps key generation off the clock for everything
but the first.
*/
@(private = "file")
CERT_DIR :: "/tmp/elodin-tlsx-test"

/*
How long a generated certificate lives.

Thirty rather than the two it was, now that an expired one is noticed rather than
handshaken with: the reuse is there to keep key generation off the clock, and a
lifetime measured in days spent it again every other day for no reason. Still
short enough that a forgotten key in the system temp directory is not a permanent
one.
*/
@(private = "file")
CERT_DAYS :: "30"

@(private = "file")
cert_once: sync.Once
@(private = "file")
cert_path: string
@(private = "file")
key_path: string
@(private = "file")
cert_ok: bool

/*
Whether a certificate already on disk can still be handshaken with.

The reuse above it is the point of the cache and was also a time bomb: the
generated certificate lives for `CERT_DAYS`, the files are reused whenever they
exist, and nothing looked at the date. So every machine that ran these tests more
than that long ago failed `test_verifying_context_refuses_a_name_it_cannot_bind`
on its *control* case - the name the certificate carries, refused - and went on
failing it, on every run, until somebody deleted the directory by hand. It is not
a flake and a re-run does not clear it; the one that found this had expired eight
minutes before the run that caught it.

`-checkend` asks the question directly, and asks it about an hour from now rather
than about this instant, so a certificate cannot expire between this check and
the handshakes that follow it.

A certificate is only rejected when openssl runs and says so. If it cannot be run
at all the certificate is kept: this suite needs openssl to *make* one, so a host
without it has nothing to gain from throwing away the one it has, and a
developer's own `certs/` pair should not be discarded over a missing tool.
*/
@(private = "file")
cert_still_valid :: proc(path: string) -> bool {
	// `-noout` suppresses the certificate and not the verdict: openssl writes
	// "Certificate will not expire" on the way to exit 0, and this runs on every
	// test binary. The exit code is the answer; the line is noise in a suite's
	// output. Discarded rather than captured - nothing here reads it - and a
	// /dev/null that will not open is not a reason to fail the check.
	devnull, nerr := os.open("/dev/null", {.Write})
	defer if nerr == nil {
		os.close(devnull)
	}
	desc := os.Process_Desc {
		command = []string{"openssl", "x509", "-in", path, "-noout", "-checkend", "3600"},
	}
	if nerr == nil {
		desc.stdout = devnull
		desc.stderr = devnull
	}
	process, perr := os.process_start(desc)
	if perr != nil {
		return true
	}
	state, werr := os.process_wait(process)
	if werr != nil {
		return true
	}
	return state.exit_code == 0
}

@(private = "file")
usable_pair :: proc(cert, key: string) -> bool {
	return os.exists(cert) && os.exists(key) && cert_still_valid(cert)
}

@(private = "file")
generate_certs :: proc() {
	if usable_pair("certs/cert.pem", "certs/key.pem") {
		cert_path, key_path, cert_ok = "certs/cert.pem", "certs/key.pem", true
		return
	}

	cert_path = CERT_DIR + "/cert.pem"
	key_path = CERT_DIR + "/key.pem"
	if usable_pair(cert_path, key_path) {
		cert_ok = true
		return
	}
	if !os.exists(CERT_DIR) {
		if err := os.make_directory(CERT_DIR); err != nil {
			return
		}
	}

	process, perr := os.process_start(
		os.Process_Desc {
			command = []string {
				"openssl",
				"req",
				"-x509",
				"-newkey",
				"ec",
				"-pkeyopt",
				"ec_paramgen_curve:prime256v1",
				"-nodes",
				"-keyout",
				key_path,
				"-out",
				cert_path,
				"-days",
				CERT_DAYS,
				"-subj",
				"/CN=elodin.local",
				"-addext",
				"subjectAltName=DNS:elodin.local,DNS:localhost,IP:127.0.0.1",
			},
		},
	)
	if perr != nil {
		return
	}
	state, werr := os.process_wait(process)
	if werr != nil || state.exit_code != 0 {
		return
	}
	cert_ok = true
}

@(private = "file")
ensure_certs :: proc() -> (cert, key: string, ok: bool) {
	sync.once_do(&cert_once, generate_certs)
	return cert_path, key_path, cert_ok
}

@(private = "file")
Accept_Ctx :: struct {
	listener: net.TCP_Socket,
	ctx:      ^Context,
	conn:     ^Conn,
	done:     bool,
}

@(private = "file")
accept_worker :: proc(a: ^Accept_Ctx) {
	defer sync.atomic_store(&a.done, true)
	sock, _, err := net.accept_tcp(a.listener)
	if err != nil {
		return
	}
	_ = net.set_option(sock, .Receive_Timeout, 10 * time.Second)
	_ = net.set_option(sock, .Send_Timeout, 10 * time.Second)
	conn, terr := server_accept(a.ctx, sock)
	if terr != .None {
		net.close(sock)
		return
	}
	a.conn = conn
}

@(private = "file")
Pair :: struct {
	server_ctx: ^Context,
	client_ctx: ^Context,
	server:     ^Conn,
	client:     ^Conn,
	listener:   net.TCP_Socket,
	accept:     ^thread.Thread,
	actx:       ^Accept_Ctx,
}

// A connected, handshaken TLS pair. The two handshakes have to run at the same
// time, so the accept side gets its own thread.
@(private = "file")
make_pair :: proc(t: ^testing.T) -> (p: Pair, ok: bool) {
	cert, key, have := ensure_certs()
	if !have {
		testing.expect(t, false, "no certificate available and openssl could not make one")
		return {}, false
	}
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.expectf(t, false, "cannot listen on loopback: %v", lerr)
		return {}, false
	}
	bound, berr := net.bound_endpoint(listener)
	if berr != nil {
		net.close(listener)
		testing.expectf(t, false, "cannot read the bound port: %v", berr)
		return {}, false
	}

	sctx, serr := server_context(cert, key)
	if serr != .None {
		net.close(listener)
		testing.expectf(t, false, "server_context: %v", serr)
		return {}, false
	}
	cctx, cerr := client_context(false)
	if cerr != .None {
		context_destroy(sctx)
		net.close(listener)
		testing.expectf(t, false, "client_context: %v", cerr)
		return {}, false
	}

	actx := new(Accept_Ctx)
	actx.listener = listener
	actx.ctx = sctx
	accept := thread.create_and_start_with_poly_data(actx, accept_worker)

	sock, derr := net.dial_tcp_from_endpoint(bound)
	if derr != nil {
		testing.expectf(t, false, "cannot dial: %v", derr)
		return {}, false
	}
	_ = net.set_option(sock, .Receive_Timeout, 10 * time.Second)
	_ = net.set_option(sock, .Send_Timeout, 10 * time.Second)

	client, clerr := client_connect(cctx, sock, "localhost")
	if clerr != .None {
		testing.expectf(t, false, "client_connect: %v", clerr)
		return {}, false
	}

	thread.join(accept)
	if actx.conn == nil {
		testing.expect(t, false, "the server never completed its handshake")
		return {}, false
	}

	return Pair {
			server_ctx = sctx,
			client_ctx = cctx,
			server = actx.conn,
			client = client,
			listener = listener,
			accept = accept,
			actx = actx,
		},
		true
}

@(private = "file")
destroy_pair :: proc(p: ^Pair) {
	if p.client != nil {
		close(p.client)
	}
	if p.server != nil {
		close(p.server)
	}
	net.close(p.listener)
	thread.destroy(p.accept)
	free(p.actx)
	context_destroy(p.server_ctx)
	context_destroy(p.client_ctx)
}

// ---------------------------------------------------------------------------
// Concurrent use of one connection
// ---------------------------------------------------------------------------

@(private = "file")
CHUNK :: 512
@(private = "file")
ROUNDS :: 400

@(private = "file")
Echo_Ctx :: struct {
	conn:    ^Conn,
	total:   int,
	stopped: bool,
}

// Reads and writes the same bytes straight back, so the client below has both
// directions of its connection busy at once.
@(private = "file")
echo_worker :: proc(e: ^Echo_Ctx) {
	defer sync.atomic_store(&e.stopped, true)
	buf: [CHUNK]u8
	sent := 0
	for sent < e.total {
		n, err := read(e.conn, buf[:])
		if err != .None || n <= 0 {
			return
		}
		if _, werr := write(e.conn, buf[:n]); werr != .None {
			return
		}
		sent += n
	}
}

@(private = "file")
Writer_Ctx :: struct {
	conn:   ^Conn,
	failed: bool,
	done:   bool,
}

@(private = "file")
writer_worker :: proc(w: ^Writer_Ctx) {
	defer sync.atomic_store(&w.done, true)
	payload: [CHUNK]u8
	for i in 0 ..< CHUNK {
		payload[i] = u8(i)
	}
	for _ in 0 ..< ROUNDS {
		if _, err := write(w.conn, payload[:]); err != .None {
			sync.atomic_store(&w.failed, true)
			return
		}
	}
}

@(test)
test_concurrent_read_and_write_on_one_connection :: proc(t: ^testing.T) {
	/*
	One thread writing while another reads, on a single `Conn`.

	This is what HTTP/2 does to every connection it owns: `h2.serve` reads
	frames on the connection's own thread while responses are written from
	handler-pool workers. OpenSSL does not allow one `SSL` object to be driven
	by two threads at once, so without serialisation inside this package the
	two corrupt each other's view of the session.

	The bytes are checked on the way back, so a session that comes apart shows
	up as a failed read or as data that does not match what was sent.
	*/
	p, ok := make_pair(t)
	if !ok {
		return
	}
	defer destroy_pair(&p)

	echo := Echo_Ctx {
		conn  = p.server,
		total = CHUNK * ROUNDS,
	}
	echo_thread := thread.create_and_start_with_poly_data(&echo, echo_worker)
	defer {
		thread.join(echo_thread)
		thread.destroy(echo_thread)
	}

	writer := Writer_Ctx {
		conn = p.client,
	}
	writer_thread := thread.create_and_start_with_poly_data(&writer, writer_worker)
	defer {
		thread.join(writer_thread)
		thread.destroy(writer_thread)
	}

	// Reading here, on this thread, while `writer_thread` writes to the same
	// connection.
	got := 0
	buf: [CHUNK]u8
	corrupt := false
	for got < CHUNK * ROUNDS {
		n, err := read(p.client, buf[:])
		if err != .None || n <= 0 {
			testing.expectf(t, false, "read failed after %d of %d bytes: %v", got, CHUNK * ROUNDS, err)
			break
		}
		for i in 0 ..< n {
			if buf[i] != u8((got + i) % CHUNK) {
				corrupt = true
				break
			}
		}
		if corrupt {
			break
		}
		got += n
	}

	testing.expect(t, !corrupt, "the echoed bytes did not match what was sent")
	testing.expect_value(t, got, CHUNK * ROUNDS)
	testing.expect(t, !sync.atomic_load(&writer.failed), "the writer thread hit an error")

	/*
	The real assertion. Corrupted bytes would be one symptom, but OpenSSL
	misused this way usually does something subtler and rarer than that, so the
	test watches the misuse itself rather than hoping for a visible outcome:
	two threads inside an OpenSSL call on one connection at the same time.
	*/
	peak := sync.atomic_load(&p.client.ssl_peak)
	testing.expectf(t, peak <= 1, "%d threads were inside an OpenSSL call on one connection at once", peak)
}

@(test)
test_idle_reader_does_not_block_a_writer :: proc(t: ^testing.T) {
	/*
	Guards against the obvious wrong fix for the above.

	A reader parked on a quiet connection is the normal state of an HTTP/2
	server: `h2.serve` sits in a read waiting for the peer's next request, for
	as long as the socket receive timeout allows - ten seconds, by default.
	Serialising reads against writes with a plain mutex would leave every
	response queued behind that wait.

	So the lock must not span the wait, only the calls into OpenSSL either side
	of it. A write issued while a read is parked has to go out immediately.
	*/
	p, ok := make_pair(t)
	if !ok {
		return
	}
	defer destroy_pair(&p)

	// The client reads from a server that says nothing, so this parks until the
	// receive timeout fires.
	idle := Idle_Ctx {
		conn = p.client,
	}
	idle_thread := thread.create_and_start_with_poly_data(&idle, idle_worker)
	defer {
		thread.join(idle_thread)
		thread.destroy(idle_thread)
	}

	// Long enough for the reader to be inside its wait.
	time.sleep(200 * time.Millisecond)

	payload := [8]u8{1, 2, 3, 4, 5, 6, 7, 8}
	started := time.now()
	_, werr := write(p.client, payload[:])
	elapsed := time.diff(started, time.now())

	testing.expect_value(t, werr, Error.None)
	testing.expectf(
		t,
		elapsed < 2 * time.Second,
		"the write waited %v behind a parked reader; it must not be serialised against one",
		elapsed,
	)

	// Let the server drain, so the reader above is released rather than sitting
	// out its full timeout.
	echoed: [8]u8
	read(p.server, echoed[:])
	write(p.server, echoed[:])
}

@(private = "file")
Idle_Ctx :: struct {
	conn: ^Conn,
	done: bool,
}

@(private = "file")
idle_worker :: proc(i: ^Idle_Ctx) {
	defer sync.atomic_store(&i.done, true)
	buf: [64]u8
	read(i.conn, buf[:])
}

/*
Dial the loopback server once and hand back what the handshake made of it.

The client context verifies against the server's own certificate, so the chain
always checks out and the only thing left to decide the outcome is whether the
name was checked.
*/
@(private = "file")
verified_handshake :: proc(t: ^testing.T, hostname: string) -> (err: Error, ran: bool) {
	cert, key, have := ensure_certs()
	if !have {
		testing.expect(t, false, "no certificate available and openssl could not make one")
		return .None, false
	}
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.expectf(t, false, "cannot listen on loopback: %v", lerr)
		return .None, false
	}
	defer net.close(listener)
	bound, berr := net.bound_endpoint(listener)
	if berr != nil {
		testing.expectf(t, false, "cannot read the bound port: %v", berr)
		return .None, false
	}

	sctx, serr := server_context(cert, key)
	if serr != .None {
		testing.expectf(t, false, "server_context: %v", serr)
		return .None, false
	}
	defer context_destroy(sctx)
	// The server's own certificate as the trust store: the chain is beyond
	// question, which leaves the name as the only thing under test.
	cctx, cerr := client_context(true, cert)
	if cerr != .None {
		testing.expectf(t, false, "client_context: %v", cerr)
		return .None, false
	}
	defer context_destroy(cctx)

	actx := new(Accept_Ctx)
	defer free(actx)
	actx.listener = listener
	actx.ctx = sctx
	accept := thread.create_and_start_with_poly_data(actx, accept_worker)
	defer {
		thread.join(accept)
		thread.destroy(accept)
		if actx.conn != nil {
			close(actx.conn)
		}
	}

	sock, derr := net.dial_tcp_from_endpoint(bound)
	if derr != nil {
		testing.expectf(t, false, "cannot dial: %v", derr)
		return .None, false
	}
	_ = net.set_option(sock, .Receive_Timeout, 10 * time.Second)
	_ = net.set_option(sock, .Send_Timeout, 10 * time.Second)

	conn, clerr := client_connect(cctx, sock, hostname)
	if clerr != .None {
		net.close(sock)
		return clerr, true
	}
	close(conn)
	return .None, true
}

@(private = "file")
Reset_Ctx :: struct {
	listener: net.TCP_Socket,
	done:     bool,
}

// Accept, wait for the handshake to actually start, then hang up hard:
// SO_LINGER with a zero timeout makes close() send a RST rather than a FIN,
// which is what a peer that drops handshakes mid-flight looks like on the
// wire.
@(private = "file")
reset_worker :: proc(r: ^Reset_Ctx) {
	defer sync.atomic_store(&r.done, true)
	sock, _, err := net.accept_tcp(r.listener)
	if err != nil {
		return
	}
	// Bounded so a client that never sends anything (a future change to this
	// test, say) fails this worker fast instead of hanging it - and the test's
	// own thread.join with it - forever.
	_ = net.set_option(sock, .Receive_Timeout, 10 * time.Second)
	// Block for at least one byte of ClientHello before resetting. Without
	// this, close() races the client's own connect(): under CI load the RST
	// can land while dial_tcp_from_endpoint is still reading connect()'s
	// SO_ERROR, so the client sees a reset dial rather than a reset
	// handshake (see fix(upstream) 795492b for the same race elsewhere).
	// Reading first guarantees the client's dial already succeeded and the
	// handshake is underway by the time the RST goes out.
	buf: [1]u8
	_, _ = net.recv_tcp(sock, buf[:])
	lg := posix.linger {
		l_onoff  = 1,
		l_linger = 0,
	}
	posix.setsockopt(posix.FD(sock), posix.SOL_SOCKET, .LINGER, &lg, posix.socklen_t(size_of(lg)))
	net.close(sock)
}

/*
A handshake killed by the transport must say so.

An upstream that resets the connection mid-handshake - Quad9 does it to a
noticeable share of connections from some networks - leaves OpenSSL's error
queue empty, because nothing about the protocol went wrong: the failure was the
socket's. Reporting that as `Handshake_Failed` with "no OpenSSL error recorded"
tells the operator nothing, and in particular does not tell them the problem is
not theirs. The errno is the whole of the diagnosis, so it has to be picked up
at the point of failure and carried out.
*/
@(test)
test_handshake_reset_by_peer_reports_the_transport_error :: proc(t: ^testing.T) {
	// The RST arrives while OpenSSL still has bytes to push, so the write that
	// follows it raises SIGPIPE. The server ignores it (see main.odin); the test
	// runner does not.
	posix.sigignore(.SIGPIPE)

	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.expectf(t, false, "cannot listen on loopback: %v", lerr)
		return
	}
	defer net.close(listener)
	bound, berr := net.bound_endpoint(listener)
	if berr != nil {
		testing.expectf(t, false, "cannot read the bound port: %v", berr)
		return
	}

	cctx, cerr := client_context(false)
	if cerr != .None {
		testing.expectf(t, false, "client_context: %v", cerr)
		return
	}
	defer context_destroy(cctx)

	rctx := new(Reset_Ctx)
	defer free(rctx)
	rctx.listener = listener
	reset := thread.create_and_start_with_poly_data(rctx, reset_worker)
	defer {
		thread.join(reset)
		thread.destroy(reset)
	}

	sock, derr := net.dial_tcp_from_endpoint(bound)
	if derr != nil {
		testing.expectf(t, false, "cannot dial: %v", derr)
		return
	}
	_ = net.set_option(sock, .Receive_Timeout, 10 * time.Second)
	_ = net.set_option(sock, .Send_Timeout, 10 * time.Second)

	conn, herr := client_connect(cctx, sock, "elodin.local")
	if herr == .None {
		close(conn)
		testing.expect(t, false, "the handshake succeeded against a peer that reset it")
		return
	}
	net.close(sock)

	testing.expect_value(t, herr, Error.Closed)

	detail := describe_error(herr, context.temp_allocator)
	testing.expectf(
		t,
		strings.contains(detail, "reset"),
		"the reported cause was %q, which does not name the transport error behind it",
		detail,
	)
}

/*
A verifying context must not accept a peer whose name it never checked.

`SSL_set1_host` is the only thing that ties a certificate to the name we meant
to reach; `SSL_VERIFY_PEER` on its own only asks that the chain end somewhere
trusted. Skipping the call for an empty hostname therefore accepts any
certificate from any trusted CA, which is the whole of a DoT upstream's
protection. The configuration reaches this: a `tls://` upstream given as an IP
literal leaves the hostname empty while `verify` defaults on.
*/
@(test)
test_verifying_context_refuses_a_nameless_peer :: proc(t: ^testing.T) {
	// Both ends of the session are shut down here, so the second close_notify
	// goes to a socket whose peer has already gone. The server ignores SIGPIPE
	// for the same reason (see main.odin); the test runner does not.
	posix.sigignore(.SIGPIPE)

	// A name the certificate does not carry is refused, which is what shows the
	// checking is on at all. OpenSSL fails the handshake itself over it, so the
	// error names that rather than the verification behind it.
	wrong, ran := verified_handshake(t, "wrong.example")
	if !ran {
		return
	}
	testing.expectf(t, wrong != .None, "a certificate for another name was accepted")

	// No name at all must not be the way around it.
	nameless, ran2 := verified_handshake(t, "")
	if !ran2 {
		return
	}
	testing.expect_value(t, nameless, Error.Verify_Failed)
}

/*
A name that cannot be bound as written must not be bound as something else.

`SSL_set1_host` is reached through `strings.clone_to_cstring`, which ends the
string at the first NUL byte. A configured name with one in it therefore
verifies against a prefix of itself: "localhost\0wrong.example" is checked as
"localhost", matches a certificate that carries that name, and the session comes
back looking verified against a name nobody asked for. OpenSSL refuses embedded
NULs itself - `X509_VERIFY_PARAM_set1_host` will not take one - but it only ever
sees what survived the conversion, so the refusal has to happen on this side of
it.

The other end of the same problem is `SSL_set1_host` failing outright, which is
not reproducible here: past the NUL case its only remaining failure is
allocation. The check on its return value is in the code regardless, because
what a missed failure produces is a chain-only handshake that
`SSL_get_verify_result` still calls X509_V_OK - a session the caller believes is
tied to a name and is not.
*/
@(test)
test_verifying_context_refuses_a_name_it_cannot_bind :: proc(t: ^testing.T) {
	posix.sigignore(.SIGPIPE)

	long := strings.repeat("a", 300, context.temp_allocator)
	defer free_all(context.temp_allocator)

	Case :: struct {
		hostname: string,
		accepted: bool,
		what:     string,
	}

	CASES := []Case {
		// The certificate carries DNS:localhost, so this is the control: the
		// refusals below are about the names, not about refusing everything.
		{"localhost", true, "a name the certificate carries"},
		// Truncates to a name the certificate does carry, which is what makes
		// this the dangerous one: the handshake succeeds and the name that was
		// checked is not the name that was configured.
		{"localhost\x00wrong.example", false, "a NUL with a matching prefix"},
		{"wrong.example\x00localhost", false, "a NUL with a matching suffix"},
		// Past what SNI can carry (255 bytes), so the extension cannot be set.
		{long, false, "a name too long to send"},
	}

	for c in CASES {
		err, ran := verified_handshake(t, c.hostname)
		if !ran {
			return
		}
		if c.accepted {
			testing.expectf(t, err == .None, "%s was refused: %v", c.what, err)
		} else {
			testing.expectf(t, err != .None, "%s was accepted", c.what)
		}
	}
}

// ---------------------------------------------------------------------------
// The ALPN list against a context that has been destroyed
// ---------------------------------------------------------------------------

@(private = "file")
Held_Block :: struct {
	ptr:  rawptr,
	size: int,
}

/*
An allocator that scribbles over what it is asked to free and keeps the block.

"Returned to the allocator" is not otherwise observable: freed bytes may still
read back correctly for as long as nothing else asks for that size, so a test
that only frees and looks proves nothing about a machine other than the one it
ran on. This makes the release itself the signal - the contents are destroyed at
the moment of the free, deterministically - while holding the block back so
nothing is written through a dangling pointer to memory the heap has reissued.

`release` hands everything over for real, because `odin test` fails a test that
still owes the allocator anything when it returns.
*/
@(private = "file")
Scribbler :: struct {
	under: mem.Allocator,
	held:  [dynamic]Held_Block,
}

@(private = "file")
scribbler_proc :: proc(
	allocator_data: rawptr,
	mode: mem.Allocator_Mode,
	size, alignment: int,
	old_memory: rawptr,
	old_size: int,
	loc := #caller_location,
) -> (
	[]byte,
	mem.Allocator_Error,
) {
	s := (^Scribbler)(allocator_data)
	// Only a sized free can be scribbled over; `free` on a bare pointer passes
	// no size, and those are handed straight through.
	if mode == .Free && old_memory != nil && old_size > 0 {
		mem.set(old_memory, 0xAA, old_size)
		append(&s.held, Held_Block{ptr = old_memory, size = old_size})
		return nil, .None
	}
	return s.under.procedure(s.under.data, mode, size, alignment, old_memory, old_size, loc)
}

@(private = "file")
scribbler_init :: proc(s: ^Scribbler) -> mem.Allocator {
	s.under = context.allocator
	s.held.allocator = s.under
	return mem.Allocator{procedure = scribbler_proc, data = s}
}

@(private = "file")
scribbler_release :: proc(s: ^Scribbler) {
	for b in s.held {
		_, _ = s.under.procedure(s.under.data, .Free, 0, 0, b.ptr, b.size)
	}
	delete(s.held)
}

@(private = "file")
Alpn_Client :: struct {
	endpoint:     net.Endpoint,
	ctx:          ^Context,
	conn:         ^Conn,
	err:          Error,
	// Copied rather than cloned: this runs on its own thread, and a string
	// allocated there and freed on the test's thread crosses allocators.
	protocol:     [64]u8,
	protocol_len: int,
}

@(private = "file")
alpn_client_worker :: proc(a: ^Alpn_Client) {
	sock, derr := net.dial_tcp_from_endpoint(a.endpoint)
	if derr != nil {
		a.err = .IO_Error
		return
	}
	_ = net.set_option(sock, .Receive_Timeout, 10 * time.Second)
	_ = net.set_option(sock, .Send_Timeout, 10 * time.Second)
	conn, cerr := client_connect(a.ctx, sock, "")
	if cerr != .None {
		net.close(sock)
		a.err = cerr
		return
	}
	a.conn = conn
	a.protocol_len = copy(a.protocol[:], alpn_protocol(conn))
	a.err = .None
}

/*
The ALPN list must outlive the `Context` that installed it.

`server_context` hands OpenSSL a raw pointer to the list, which `SSL_CTX` keeps
and the selection callback dereferences on every handshake. The `SSL_CTX` is
reference counted and an accepted connection holds one from `SSL_new` on, so it
survives a certificate reload freeing the `Context` that built it - but the list
had the `Context`'s lifetime instead, and `context_destroy` handed it back while
handshakes that would still read it were in flight.

That window is as wide as a peer cares to make it: `server.reload_tls` takes the
reference under its lock and leaves the handshake outside it on purpose, so a
client that connects and then stalls before its ClientHello decides when
`alpn_select` runs. What it read afterwards was memory the allocator had
reissued, and OpenSSL copies whatever the callback names into the ServerHello -
up to 255 bytes of it, back to an unauthenticated peer.

So this is the reload, in the order the server does it: take the session, free
the context, and only then shake hands. The client offers "http/1.1" first and
must still be answered "h2", which is the server's own list read in the server's
own order - nothing a scribbled-over buffer could produce.
*/
@(test)
test_alpn_outlives_the_context_that_installed_it :: proc(t: ^testing.T) {
	posix.sigignore(.SIGPIPE)

	cert, key, have := ensure_certs()
	if !have {
		testing.expect(t, false, "no certificate available and openssl could not make one")
		return
	}

	scribbler: Scribbler
	alloc := scribbler_init(&scribbler)
	defer scribbler_release(&scribbler)

	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.expectf(t, false, "cannot listen on loopback: %v", lerr)
		return
	}
	defer net.close(listener)
	bound, berr := net.bound_endpoint(listener)
	if berr != nil {
		testing.expectf(t, false, "cannot read the bound port: %v", berr)
		return
	}

	sctx, serr := server_context(cert, key, []string{"h2", "http/1.1"}, alloc)
	if serr != .None {
		testing.expectf(t, false, "server_context: %v", serr)
		return
	}
	// Offered in the opposite order to the server's preference, so the protocol
	// that comes back says whose list decided it.
	cctx, cerr := client_context(false, "", []string{"http/1.1", "h2"})
	if cerr != .None {
		context_destroy(sctx)
		testing.expectf(t, false, "client_context: %v", cerr)
		return
	}
	defer context_destroy(cctx)

	client := new(Alpn_Client)
	defer free(client)
	client.endpoint = bound
	client.ctx = cctx
	client.err = .Handshake_Failed
	worker := thread.create_and_start_with_poly_data(client, alpn_client_worker)
	defer {
		thread.join(worker)
		thread.destroy(worker)
		if client.conn != nil {
			close(client.conn)
		}
	}

	sock, _, aerr := net.accept_tcp(listener)
	if aerr != nil {
		context_destroy(sctx)
		testing.expectf(t, false, "cannot accept: %v", aerr)
		return
	}
	_ = net.set_option(sock, .Receive_Timeout, 10 * time.Second)
	_ = net.set_option(sock, .Send_Timeout, 10 * time.Second)

	// The half of accepting that reads the context, and the only half the
	// reload's lock covers.
	session, sserr := server_session(sctx, sock)
	if sserr != .None {
		context_destroy(sctx)
		net.close(sock)
		testing.expectf(t, false, "server_session: %v", sserr)
		return
	}

	// The reload: the listener's slot now holds a fresh context and this one is
	// released. The `SSL` above keeps the `SSL_CTX` alive; nothing on this side
	// keeps anything else alive.
	context_destroy(sctx)

	/*
	And the process goes on allocating between the release and the handshake
	that reads the list, the way a server still answering queries would.

	The scribbler is what makes the release observable for a list on the
	allocator the context was built with. This covers a list released anywhere
	else the heap can hand back: the sizes bracket the encoded list's and come
	from the allocator underneath the scribbler, so a block genuinely returned
	is one of the blocks reissued here, written over before the handshake reads
	it.
	*/
	churn: [64][]u8
	for i in 0 ..< len(churn) {
		churn[i] = make([]u8, 4 + i)
		mem.set(raw_data(churn[i]), 0xAA, len(churn[i]))
	}
	defer for c in churn {
		delete(c)
	}

	server_conn, herr := server_handshake(session)
	if herr != .None {
		net.close(sock)
		testing.expectf(t, false, "the handshake failed after the context was released: %v", herr)
		return
	}
	defer close(server_conn)

	testing.expect_value(t, alpn_protocol(server_conn), "h2")

	thread.join(worker)
	testing.expect_value(t, client.err, Error.None)
	testing.expect_value(t, string(client.protocol[:client.protocol_len]), "h2")
}
