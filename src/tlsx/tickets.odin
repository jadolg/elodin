package tlsx

import "core:c"
import "core:c/libc"
import "core:sync"
import "core:time"

/*
How long a session-ticket key seals new tickets. It then opens the tickets it
sealed for one interval more, and is erased.

RFC 9325 §3.4: "Ticket-encryption keys MUST be changed regularly ... so as not
to negate the benefits of forward secrecy", and "session ticket validity MUST be
limited to a reasonable duration (e.g., half as long as ticket-encryption key
validity)". A key lives two intervals and a ticket one (`server_context` sets the
session timeout to it), so every ticket is still opened for the whole lifetime it
was issued with, and nothing that opens a ticket stays in memory past two
intervals. Two hours is the session timeout OpenSSL already used, so clients
resume exactly as long as they did before rotation.

What a stolen key exposes differs by version. A TLS 1.2 ticket carries the master
secret, so its key decrypts the recorded session that issued it and every one
resumed from it. TLS 1.3 resumption here always runs a fresh (EC)DHE exchange
(OpenSSL refuses `psk_ke` without `SSL_OP_ALLOW_NO_DHE_KEX`, and accepts no early
data), so a stolen key opens tickets but not the traffic after them.
*/
TICKET_KEY_INTERVAL :: 2 * time.Hour

@(private)
Ticket_Key :: struct {
	name: [TLSEXT_KEYNAME_LENGTH]u8,
	aes:  [32]u8,
	hmac: [32]u8,
	born: time.Tick,
	live: bool,
}

/*
A server context's ticket keys: the one sealing new tickets, and the one it
replaced, which only opens.

Owned by the `SSL_CTX` through ex_data, for the reason `alpn_ex_index` gives: a
handshake still running after a reload displaced the context opens and seals
tickets through it. A reload builds a new context and so new keys, which is why
every ticket outstanding stops resuming when a certificate is renewed.

`mu` because the callback runs on every loop thread's handshakes and the
maintenance thread rotates the keys under them.
*/
@(private)
Ticket_Keys :: struct {
	mu:       sync.Mutex,
	current:  Ticket_Key,
	previous: Ticket_Key,
}

@(private)
tickets_ex_index: c.int = -1

@(private)
tickets_ex_free :: proc "c" (parent: rawptr, ptr: rawptr, ad: rawptr, idx: c.int, argl: c.long, argp: rawptr) {
	if ptr != nil {
		OPENSSL_cleanse(ptr, size_of(Ticket_Keys))
	}
	libc.free(ptr)
}

@(private)
erase_ticket_key :: proc "contextless" (key: ^Ticket_Key) {
	OPENSSL_cleanse(key, size_of(Ticket_Key))
}

// A failed draw leaves the key erased and not live: no ticket is sealed until a
// later draw succeeds, rather than one sealed under a key that is not random.
@(private)
draw_ticket_key :: proc "contextless" (key: ^Ticket_Key, now: time.Tick) {
	erase_ticket_key(key)
	if RAND_priv_bytes(raw_data(key.name[:]), size_of(key.name)) != 1 ||
	   RAND_priv_bytes(raw_data(key.aes[:]), size_of(key.aes)) != 1 ||
	   RAND_priv_bytes(raw_data(key.hmac[:]), size_of(key.hmac)) != 1 {
		erase_ticket_key(key)
		return
	}
	key.born = now
	key.live = true
}

/*
Retire the sealing key once it is an interval old, erase any key two intervals
old, and draw a sealing key when there is none. Under `k.mu`.

Run by the callback on every ticket as well as by the maintenance tick, so a
handshake never uses a key past its time however late the tick runs, and an idle
listener still erases its keys on schedule.
*/
@(private)
advance_ticket_keys :: proc "contextless" (k: ^Ticket_Keys, now: time.Tick) {
	if k.current.live && time.tick_diff(k.current.born, now) >= TICKET_KEY_INTERVAL {
		erase_ticket_key(&k.previous)
		k.previous = k.current
		erase_ticket_key(&k.current)
	}
	if k.previous.live && time.tick_diff(k.previous.born, now) >= 2 * TICKET_KEY_INTERVAL {
		erase_ticket_key(&k.previous)
	}
	if !k.current.live {
		draw_ticket_key(&k.current, now)
	}
}

/*
Give `ptr` its ticket keys and the callback that uses them, and make a ticket
last one `TICKET_KEY_INTERVAL`.

Without a callback OpenSSL seals every ticket under one key drawn when the
context is created and never changed, for as long as the process runs.
*/
@(private)
install_ticket_keys :: proc(ptr: ^SSL_CTX) -> bool {
	if tickets_ex_index < 0 {
		return false
	}
	k := (^Ticket_Keys)(libc.calloc(1, size_of(Ticket_Keys)))
	if k == nil {
		return false
	}
	draw_ticket_key(&k.current, time.tick_now())
	if !k.current.live {
		libc.free(k)
		return false
	}
	if SSL_CTX_set_ex_data(ptr, tickets_ex_index, k) != 1 {
		tickets_ex_free(nil, k, nil, 0, 0, nil)
		return false
	}
	SSL_CTX_set_timeout(ptr, c.long(TICKET_KEY_INTERVAL / time.Second))
	return SSL_CTX_set_tlsext_ticket_key_evp_cb(ptr, ticket_key_cb) == 1
}

@(private)
ticket_keys_of :: proc "contextless" (ptr: ^SSL_CTX) -> ^Ticket_Keys {
	if ptr == nil || tickets_ex_index < 0 {
		return nil
	}
	return (^Ticket_Keys)(SSL_CTX_get_ex_data(ptr, tickets_ex_index))
}

/*
Rotate and erase a server context's ticket keys on schedule, as of `now`
(`time.tick_now()` outside tests).

For the maintenance tick, so a listener nobody connects to still erases its
keys; the callback does the same on every ticket. Nothing on a client context.
*/
rotate_ticket_keys :: proc(ctx: ^Context, now: time.Tick) {
	if ctx == nil {
		return
	}
	k := ticket_keys_of(ctx.ptr)
	if k == nil {
		return
	}
	sync.mutex_lock(&k.mu)
	advance_ticket_keys(k, now)
	sync.mutex_unlock(&k.mu)
}

/*
Seal or open one ticket.

The key is copied out under the lock and erased from the stack after use, so the
lock is held for a copy and never across OpenSSL. A ticket under the retired key
is opened and answered with 2, which has OpenSSL issue a fresh one under the
current key, so a client resuming at least once an interval keeps resuming. Any
failure answers 0: no ticket sealed, or a full handshake for the one offered.
*/
@(private)
ticket_key_cb :: proc "c" (
	ssl: ^SSL,
	key_name: [^]u8,
	iv: [^]u8,
	cctx: ^EVP_CIPHER_CTX,
	hctx: ^EVP_MAC_CTX,
	enc: c.int,
) -> c.int {
	k := ticket_keys_of(SSL_get_SSL_CTX(ssl))
	if k == nil {
		return 0
	}
	digest: cstring = "SHA256"
	key: Ticket_Key
	defer erase_ticket_key(&key)
	renew := false
	sync.mutex_lock(&k.mu)
	advance_ticket_keys(k, time.tick_now())
	if enc == 1 {
		key = k.current
	} else {
		name := key_name[:TLSEXT_KEYNAME_LENGTH]
		switch {
		case k.current.live && libc.memcmp(raw_data(name), &k.current.name, TLSEXT_KEYNAME_LENGTH) == 0:
			key = k.current
		case k.previous.live && libc.memcmp(raw_data(name), &k.previous.name, TLSEXT_KEYNAME_LENGTH) == 0:
			key = k.previous
			renew = true
		}
	}
	sync.mutex_unlock(&k.mu)
	if !key.live {
		return 0
	}

	params := [3]OSSL_PARAM {
		{
			key = "key",
			data_type = OSSL_PARAM_OCTET_STRING,
			data = raw_data(key.hmac[:]),
			data_size = size_of(key.hmac),
			return_size = OSSL_PARAM_UNMODIFIED,
		},
		{
			key = "digest",
			data_type = OSSL_PARAM_UTF8_STRING,
			data = rawptr(digest),
			data_size = len("SHA256"),
			return_size = OSSL_PARAM_UNMODIFIED,
		},
		{},
	}
	if EVP_MAC_CTX_set_params(hctx, raw_data(params[:])) != 1 {
		return 0
	}
	if enc == 1 {
		if RAND_bytes(iv, AES_256_CBC_IV_LENGTH) != 1 {
			return 0
		}
		libc.memcpy(key_name, &key.name, TLSEXT_KEYNAME_LENGTH)
		if EVP_EncryptInit_ex(cctx, EVP_aes_256_cbc(), nil, raw_data(key.aes[:]), iv) != 1 {
			return 0
		}
		return 1
	}
	if EVP_DecryptInit_ex(cctx, EVP_aes_256_cbc(), nil, raw_data(key.aes[:]), iv) != 1 {
		return 0
	}
	return 2 if renew else 1
}

// The name of the key sealing `ctx`'s tickets now, which a ticket carries in
// its first 16 bytes; false on a client context. For tests outside this
// package, which cannot see the keys themselves.
ticket_key_name :: proc(ctx: ^Context) -> (name: [TLSEXT_KEYNAME_LENGTH]u8, ok: bool) {
	k := ticket_keys_of(ctx.ptr) if ctx != nil else nil
	if k == nil {
		return
	}
	sync.mutex_lock(&k.mu)
	defer sync.mutex_unlock(&k.mu)
	return k.current.name, k.current.live
}
