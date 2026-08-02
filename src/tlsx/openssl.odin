package tlsx

import "core:c"

// Minimal OpenSSL 3.x bindings: only what a DoT/DoH endpoint and client need.
// Verified against the headers shipped with OpenSSL 3.x.

foreign import libssl "system:ssl"
foreign import libcrypto "system:crypto"

SSL_CTX :: struct {}
SSL :: struct {}
SSL_METHOD :: struct {}

OPENSSL_INIT_LOAD_SSL_STRINGS :: 0x0020_0000
OPENSSL_INIT_LOAD_CRYPTO_STRINGS :: 0x0000_0002

SSL_FILETYPE_PEM :: 1

SSL_VERIFY_NONE :: 0x00
SSL_VERIFY_PEER :: 0x01

SSL_ERROR_NONE :: 0
SSL_ERROR_SSL :: 1
SSL_ERROR_WANT_READ :: 2
SSL_ERROR_WANT_WRITE :: 3
SSL_ERROR_SYSCALL :: 5
SSL_ERROR_ZERO_RETURN :: 6

SSL_CTRL_SET_TLSEXT_HOSTNAME :: 55
SSL_CTRL_SET_MIN_PROTO_VERSION :: 123
SSL_CTRL_SET_MAX_PROTO_VERSION :: 124

TLSEXT_NAMETYPE_host_name :: 0

TLS1_2_VERSION :: 0x0303
TLS1_3_VERSION :: 0x0304

X509_V_OK :: 0

SSL_TLSEXT_ERR_OK :: 0
SSL_TLSEXT_ERR_ALERT_FATAL :: 2
SSL_TLSEXT_ERR_NOACK :: 3

ALPN_Select_Cb :: #type proc "c" (
	ssl: ^SSL,
	out: ^[^]u8,
	outlen: ^u8,
	input: [^]u8,
	inlen: c.uint,
	arg: rawptr,
) -> c.int

@(default_calling_convention = "c")
foreign libssl {
	OPENSSL_init_ssl :: proc(opts: u64, settings: rawptr) -> c.int ---

	TLS_client_method :: proc() -> ^SSL_METHOD ---
	TLS_server_method :: proc() -> ^SSL_METHOD ---

	SSL_CTX_new :: proc(method: ^SSL_METHOD) -> ^SSL_CTX ---
	SSL_CTX_free :: proc(ctx: ^SSL_CTX) ---
	SSL_CTX_ctrl :: proc(ctx: ^SSL_CTX, cmd: c.int, larg: c.long, parg: rawptr) -> c.long ---
	SSL_CTX_set_verify :: proc(ctx: ^SSL_CTX, mode: c.int, callback: rawptr) ---
	SSL_CTX_set_default_verify_paths :: proc(ctx: ^SSL_CTX) -> c.int ---
	SSL_CTX_load_verify_locations :: proc(ctx: ^SSL_CTX, ca_file: cstring, ca_path: cstring) -> c.int ---
	SSL_CTX_use_certificate_chain_file :: proc(ctx: ^SSL_CTX, file: cstring) -> c.int ---
	SSL_CTX_use_PrivateKey_file :: proc(ctx: ^SSL_CTX, file: cstring, type: c.int) -> c.int ---
	SSL_CTX_check_private_key :: proc(ctx: ^SSL_CTX) -> c.int ---
	SSL_CTX_set_alpn_protos :: proc(ctx: ^SSL_CTX, protos: [^]u8, len: c.uint) -> c.int ---
	SSL_CTX_set_alpn_select_cb :: proc(ctx: ^SSL_CTX, cb: ALPN_Select_Cb, arg: rawptr) ---

	SSL_new :: proc(ctx: ^SSL_CTX) -> ^SSL ---
	SSL_free :: proc(ssl: ^SSL) ---
	SSL_set_fd :: proc(ssl: ^SSL, fd: c.int) -> c.int ---
	SSL_ctrl :: proc(ssl: ^SSL, cmd: c.int, larg: c.long, parg: rawptr) -> c.long ---
	SSL_set1_host :: proc(ssl: ^SSL, host: cstring) -> c.int ---
	SSL_connect :: proc(ssl: ^SSL) -> c.int ---
	SSL_accept :: proc(ssl: ^SSL) -> c.int ---
	SSL_read :: proc(ssl: ^SSL, buf: rawptr, num: c.int) -> c.int ---
	SSL_write :: proc(ssl: ^SSL, buf: rawptr, num: c.int) -> c.int ---
	SSL_shutdown :: proc(ssl: ^SSL) -> c.int ---
	SSL_get_error :: proc(ssl: ^SSL, ret: c.int) -> c.int ---
	SSL_get_verify_result :: proc(ssl: ^SSL) -> c.long ---
	SSL_get0_alpn_selected :: proc(ssl: ^SSL, data: ^[^]u8, len: ^c.uint) ---
}

@(default_calling_convention = "c")
foreign libcrypto {
	ERR_get_error :: proc() -> c.ulong ---
	ERR_clear_error :: proc() ---
	ERR_error_string_n :: proc(e: c.ulong, buf: [^]u8, len: c.size_t) ---
}

// Macro equivalents that OpenSSL only exposes through SSL_CTX_ctrl / SSL_ctrl.

ssl_ctx_set_min_proto_version :: proc(ctx: ^SSL_CTX, version: c.long) -> bool {
	return SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, version, nil) == 1
}

ssl_ctx_set_max_proto_version :: proc(ctx: ^SSL_CTX, version: c.long) -> bool {
	return SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, version, nil) == 1
}

ssl_set_tlsext_host_name :: proc(ssl: ^SSL, name: cstring) -> bool {
	return SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, rawptr(name)) == 1
}
