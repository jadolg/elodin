package tlsx

import "core:c"
import "core:fmt"
import "core:mem"
import "core:net"
import "core:strings"
import "core:sync"

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

Conn :: struct {
	ssl:       ^SSL,
	socket:    net.TCP_Socket,
	allocator: mem.Allocator,
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
	ssl := SSL_new(ctx.ptr)
	if ssl == nil {
		return nil, .Handshake_Failed
	}
	if SSL_set_fd(ssl, socket_fd(socket)) != 1 {
		SSL_free(ssl)
		return nil, .Handshake_Failed
	}
	if hostname != "" {
		chost := strings.clone_to_cstring(hostname, context.temp_allocator)
		ssl_set_tlsext_host_name(ssl, chost)
		// Ties certificate verification to the name we asked for.
		SSL_set1_host(ssl, chost)
	}

	ERR_clear_error()
	if SSL_connect(ssl) != 1 {
		SSL_free(ssl)
		return nil, .Handshake_Failed
	}
	if ctx.verify && SSL_get_verify_result(ssl) != X509_V_OK {
		SSL_free(ssl)
		return nil, .Verify_Failed
	}

	conn = new(Conn, allocator)
	conn.ssl = ssl
	conn.socket = socket
	conn.allocator = allocator
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
	if SSL_accept(ssl) != 1 {
		SSL_free(ssl)
		return nil, .Handshake_Failed
	}
	conn = new(Conn, allocator)
	conn.ssl = ssl
	conn.socket = socket
	conn.allocator = allocator
	return conn, .None
}

read :: proc(conn: ^Conn, buf: []u8) -> (n: int, err: Error) {
	if len(buf) == 0 {
		return 0, .None
	}
	ERR_clear_error()
	ret := SSL_read(conn.ssl, raw_data(buf), c.int(len(buf)))
	if ret > 0 {
		return int(ret), .None
	}
	return 0, classify(conn, ret)
}

write :: proc(conn: ^Conn, buf: []u8) -> (n: int, err: Error) {
	written := 0
	for written < len(buf) {
		ERR_clear_error()
		ret := SSL_write(conn.ssl, raw_data(buf[written:]), c.int(len(buf) - written))
		if ret <= 0 {
			return written, classify(conn, ret)
		}
		written += int(ret)
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

@(private)
classify :: proc(conn: ^Conn, ret: c.int) -> Error {
	switch SSL_get_error(conn.ssl, ret) {
	case SSL_ERROR_ZERO_RETURN:
		return .Closed
	case SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE:
		// Sockets are blocking with SO_RCVTIMEO/SO_SNDTIMEO set, so this only
		// happens when that timeout fires.
		return .Timeout
	case SSL_ERROR_SYSCALL:
		return .Timeout if ret < 0 else .Closed
	}
	return .IO_Error
}

close :: proc(conn: ^Conn) {
	if conn == nil {
		return
	}
	if conn.ssl != nil {
		SSL_shutdown(conn.ssl)
		SSL_free(conn.ssl)
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
	}
	return fmt.aprintf("%v", err, allocator = allocator)
}
