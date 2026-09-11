package tlsx

import "core:c"
import "core:sys/posix"

// Minimal OpenSSL 3.x bindings: only what a DoT/DoH endpoint and client need.
// Verified against the headers shipped with OpenSSL 3.x.

foreign import libssl "system:ssl"
foreign import libcrypto "system:crypto"

SSL_CTX :: struct {}
SSL :: struct {}
SSL_METHOD :: struct {}

// Only what signing an Apple configuration profile needs: the certificate and
// key a server context already holds, and the CMS structure they are wrapped in.
X509 :: struct {}
EVP_PKEY :: struct {}
BIO :: struct {}
BIO_METHOD :: struct {}
CMS_ContentInfo :: struct {}
ASN1_TIME :: struct {}
// STACK_OF(X509). OpenSSL's stacks are one implementation behind per-type
// macros, so there is a single opaque type here rather than one per element.
OPENSSL_STACK :: struct {}

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
SSL_CTRL_GET_CHAIN_CERTS :: 115
SSL_CTRL_SET_MIN_PROTO_VERSION :: 123
SSL_CTRL_SET_MAX_PROTO_VERSION :: 124

// What `BIO_get_mem_data` is a macro for.
BIO_CTRL_INFO :: 3

/*
The CMS_sign flags a configuration profile is signed under.

`CMS_BINARY` keeps the payload byte for byte: without it the input is treated as
text and its line endings are canonicalised, which would sign something other
than the profile served. `CMS_NOSMIMECAP` drops the S/MIME capabilities
attribute, which advertises the ciphers this end can decrypt with and is
meaningless in a structure nobody replies to.

Notably absent is `CMS_DETACHED`: the profile travels inside the structure, which
is what makes the signed file a replacement for the unsigned one rather than a
signature alongside it.
*/
CMS_BINARY :: 0x80
CMS_NOSMIMECAP :: 0x200

TLSEXT_NAMETYPE_host_name :: 0

TLS1_2_VERSION :: 0x0303
TLS1_3_VERSION :: 0x0304

X509_V_OK :: 0

SSL_TLSEXT_ERR_OK :: 0
SSL_TLSEXT_ERR_ALERT_FATAL :: 2
SSL_TLSEXT_ERR_NOACK :: 3

// The ex_data class an SSL_CTX belongs to. OpenSSL only exposes
// SSL_CTX_get_ex_new_index as a macro over CRYPTO_get_ex_new_index with this.
CRYPTO_EX_INDEX_SSL_CTX :: 1

/*
Releases one piece of ex_data when the object carrying it is finally freed - for
an SSL_CTX, when the last reference to it goes.

Called once per registered index for every object of the class, so `ptr` is nil
for an object that never had anything stored at that index.
*/
CRYPTO_EX_Free :: #type proc "c" (
	parent: rawptr,
	ptr: rawptr,
	ad: rawptr,
	idx: c.int,
	argl: c.long,
	argp: rawptr,
)

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
	SSL_CTX_set_ex_data :: proc(ctx: ^SSL_CTX, idx: c.int, data: rawptr) -> c.int ---

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

	// The material a context was loaded with, borrowed back out of it. `get0`
	// means no reference is taken; see `signer_of`.
	SSL_CTX_get0_certificate :: proc(ctx: ^SSL_CTX) -> ^X509 ---
	SSL_CTX_get0_privatekey :: proc(ctx: ^SSL_CTX) -> ^EVP_PKEY ---
}

@(default_calling_convention = "c")
foreign libcrypto {
	CRYPTO_get_ex_new_index :: proc(class_index: c.int, argl: c.long, argp: rawptr, new_func: rawptr, dup_func: rawptr, free_func: CRYPTO_EX_Free) -> c.int ---

	ERR_get_error :: proc() -> c.ulong ---
	ERR_clear_error :: proc() ---
	ERR_error_string_n :: proc(e: c.ulong, buf: [^]u8, len: c.size_t) ---

	X509_free :: proc(x: ^X509) ---
	X509_up_ref :: proc(x: ^X509) -> c.int ---
	X509_chain_up_ref :: proc(chain: ^OPENSSL_STACK) -> ^OPENSSL_STACK ---
	X509_get0_notBefore :: proc(x: ^X509) -> ^ASN1_TIME ---
	X509_get0_notAfter :: proc(x: ^X509) -> ^ASN1_TIME ---
	// Negative when the certificate time is before `t`, positive when after, and
	// zero when the time could not be read at all.
	X509_cmp_time :: proc(s: ^ASN1_TIME, t: ^posix.time_t) -> c.int ---
	// OpenSSL's own name matching: subject alternative names, the wildcard rules
	// and the common-name fallback, rather than a second opinion about RFC 6125.
	X509_check_host :: proc(x: ^X509, chk: [^]u8, chklen: c.size_t, flags: c.uint, peername: ^cstring) -> c.int ---
	X509_check_ip_asc :: proc(x: ^X509, ipasc: cstring, flags: c.uint) -> c.int ---

	EVP_PKEY_free :: proc(pkey: ^EVP_PKEY) ---
	EVP_PKEY_up_ref :: proc(pkey: ^EVP_PKEY) -> c.int ---

	OPENSSL_sk_pop_free :: proc(st: ^OPENSSL_STACK, free_func: rawptr) ---

	BIO_new :: proc(type: ^BIO_METHOD) -> ^BIO ---
	BIO_new_mem_buf :: proc(buf: rawptr, len: c.int) -> ^BIO ---
	BIO_s_mem :: proc() -> ^BIO_METHOD ---
	BIO_ctrl :: proc(bp: ^BIO, cmd: c.int, larg: c.long, parg: rawptr) -> c.long ---
	BIO_free :: proc(a: ^BIO) -> c.int ---

	CMS_sign :: proc(signcert: ^X509, pkey: ^EVP_PKEY, certs: ^OPENSSL_STACK, data: ^BIO, flags: c.uint) -> ^CMS_ContentInfo ---
	CMS_ContentInfo_free :: proc(cms: ^CMS_ContentInfo) ---
	i2d_CMS_bio :: proc(bp: ^BIO, cms: ^CMS_ContentInfo) -> c.int ---
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

// The intermediates loaded alongside the leaf, or nil when the file held only a
// leaf. Borrowed from the context, like the leaf and the key beside it.
ssl_ctx_get0_chain_certs :: proc(ctx: ^SSL_CTX) -> ^OPENSSL_STACK {
	chain: ^OPENSSL_STACK
	if SSL_CTX_ctrl(ctx, SSL_CTRL_GET_CHAIN_CERTS, 0, &chain) != 1 {
		return nil
	}
	return chain
}

// What `BIO_get_mem_data` is a macro for: the bytes a memory BIO has collected,
// which stay owned by the BIO.
bio_mem_data :: proc(b: ^BIO) -> []u8 {
	buf: [^]u8
	n := BIO_ctrl(b, BIO_CTRL_INFO, 0, &buf)
	if n <= 0 || buf == nil {
		return nil
	}
	return buf[:n]
}
