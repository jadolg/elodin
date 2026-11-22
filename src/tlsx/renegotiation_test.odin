package tlsx

import "core:c"
import "core:net"
import "core:testing"
import "core:thread"
import "core:time"

foreign import reneg_ssl "system:ssl"

@(default_calling_convention = "c")
foreign reneg_ssl {
	SSL_renegotiate :: proc(ssl: ^SSL) -> c.int ---
	SSL_CTX_clear_options :: proc(ctx: ^SSL_CTX, op: u64) -> u64 ---
}

@(private = "file")
SSL_CTRL_GET_TOTAL_RENEGOTIATIONS :: 12

@(private = "file")
total_renegotiations :: proc(ssl: ^SSL) -> int {
	return int(SSL_ctrl(ssl, SSL_CTRL_GET_TOTAL_RENEGOTIATIONS, 0, nil))
}

@(test)
test_every_context_refuses_renegotiation :: proc(t: ^testing.T) {
	cert, key, have := ensure_certs()
	if !testing.expect(t, have, "no certificate available and openssl could not make one") {
		return
	}
	server, serr := server_context(cert, key)
	if testing.expectf(t, serr == .None, "server_context: %v", serr) {
		testing.expect(t, SSL_CTX_get_options(server.ptr) & SSL_OP_NO_RENEGOTIATION != 0, "the server context renegotiates")
		context_destroy(server)
	}
	for verify in ([]bool{false, true}) {
		client, cerr := client_context(verify)
		if testing.expectf(t, cerr == .None, "client_context(%v): %v", verify, cerr) {
			testing.expectf(t, SSL_CTX_get_options(client.ptr) & SSL_OP_NO_RENEGOTIATION != 0, "the client context (verify %v) renegotiates", verify)
			context_destroy(client)
		}
	}
}

@(private = "file")
Reneg_Server :: struct {
	listener: net.TCP_Socket,
	ctx:      ^Context,
	conn:     ^Conn,
	// Whether `SSL_renegotiate` took: the HelloRequest went out.
	asked:    bool,
	// What the server read back after asking to renegotiate.
	got:      [4]u8,
	got_n:    int,
	read_err: Error,
}

// Accepts one client, asks it to renegotiate, writes "ping" and reads its
// answer, which is what drives a renegotiation the client agreed to.
@(private = "file")
reneg_server_worker :: proc(s: ^Reneg_Server) {
	sock, _, err := net.accept_tcp(s.listener)
	if err != nil {
		return
	}
	_ = net.set_option(sock, .Receive_Timeout, 5 * time.Second) // lint:allow a missing bound only lets a broken run wait for the test's own timeout
	conn, aerr := server_accept(s.ctx, sock)
	if aerr != .None {
		net.close(sock)
		return
	}
	s.conn = conn
	s.asked = SSL_renegotiate(conn.ssl) == 1
	if _, werr := write(conn, transmute([]u8)string("ping")); werr != .None {
		s.read_err = werr
		return
	}
	s.got_n, s.read_err = read(conn, s.got[:])
}

/*
RFC 9113 9.2.1: "A deployment of HTTP/2 over TLS 1.2 MUST disable
renegotiation." A TLS 1.2 server's HelloRequest is not followed: the client
reads on, the data after it arrives, and no renegotiation happens. An OpenSSL
server that insists on it then ends the session, which is the server's choice.
*/
@(test)
test_the_client_does_not_renegotiate_at_the_servers_request :: proc(t: ^testing.T) {
	cert, key, have := ensure_certs()
	if !testing.expect(t, have, "no certificate available and openssl could not make one") {
		return
	}
	listener, bound, listening := listen_loopback(t)
	if !listening {
		return
	}
	defer net.close(listener)
	sctx, serr := server_context(cert, key)
	if !testing.expectf(t, serr == .None, "server_context: %v", serr) {
		return
	}
	defer context_destroy(sctx)
	// A server that renegotiates, as an upstream may.
	SSL_CTX_clear_options(sctx.ptr, SSL_OP_NO_RENEGOTIATION)
	cctx, cerr := client_context(false)
	if !testing.expectf(t, cerr == .None, "client_context: %v", cerr) {
		return
	}
	defer context_destroy(cctx)
	// Renegotiation is a TLS 1.2 matter; 1.3 has none.
	if !testing.expect(t, ssl_ctx_set_max_proto_version(cctx.ptr, TLS1_2_VERSION), "cannot cap the client at TLS 1.2") {
		return
	}

	s := Reneg_Server {
		listener = listener,
		ctx      = sctx,
	}
	worker := thread.create_and_start_with_poly_data(&s, reneg_server_worker)
	if !testing.expect(t, worker != nil, "cannot start the server") {
		return
	}
	// Run in reverse: the worker is joined before its connection is closed,
	// on every path out.
	defer if s.conn != nil {
		close(s.conn)
	}
	defer thread.destroy(worker)

	sock, derr := net.dial_tcp_from_endpoint(bound)
	if !testing.expectf(t, derr == nil, "cannot dial: %v", derr) {
		net.shutdown(listener, .Both)
		thread.join(worker)
		return
	}
	testing.expect(t, net.set_option(sock, .Receive_Timeout, 5 * time.Second) == nil, "cannot bound the client")
	client, clerr := client_connect(cctx, sock, "localhost")
	if !testing.expectf(t, clerr == .None, "client_connect: %v", clerr) {
		net.close(sock)
		net.shutdown(listener, .Both)
		thread.join(worker)
		return
	}
	defer close(client)

	got: [4]u8
	n, rerr := read(client, got[:])
	testing.expectf(t, rerr == .None && string(got[:n]) == "ping", "the data after the HelloRequest: %q (%v)", string(got[:n]), rerr)
	// The answer the server reads, which is where a renegotiation the client
	// took up would complete.
	_, werr := write(client, transmute([]u8)string("pong"))
	testing.expectf(t, werr == .None, "cannot answer: %v", werr)
	thread.join(worker)
	// The premise: the server did ask.
	testing.expect(t, s.asked, "the server sent no HelloRequest")
	testing.expect_value(t, total_renegotiations(client.ssl), 0)
	// And the OpenSSL server, refused, ended the session rather than read on.
	testing.expectf(t, s.read_err != .None, "the server read %q after the refusal", string(s.got[:s.got_n]))
}
