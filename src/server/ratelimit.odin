package server

import "core:crypto"
import "core:crypto/siphash"
import "core:mem"
import "core:net"
import "core:sync"
import "core:time"
import "elodin:logx"

/*
Response rate limiting for the UDP listener.

A datagram carries no proof of where it came from, so an answer sent over UDP
goes wherever the source address said - which is how a resolver becomes an
amplifier. A ~40 byte query with an OPT record advertising 4096 buys the sender
two orders of magnitude of traffic aimed at whoever they named, and DNSSEC and
ANY answers are the usual way to get the most of it.

What bounds that is a limit on how much this server will send *to one place*.
The attacker's own rate is not the thing to measure: they are not the ones
receiving it, and with spoofed sources there is nothing of theirs to measure
anyway. The victim is, and every response in a reflection attack is addressed to
the victim - so a budget kept per destination prefix caps what any one target
can be made to receive, whoever asked for it.

By prefix rather than by address: /24 for IPv4 and /64 for IPv6, since an
attacker spoofing addresses picks them freely within the range they are aiming
at, and a per-address budget would just be spread across it.

Over-limit queries are not all dropped. Every `slip`th one is answered with a
header and a question and the TC bit set, which is 30-odd bytes rather than
4096 - too small to be worth reflecting - and which tells a real client to ask
again over TCP, where the handshake proves the address. A client stuck behind a
busy NAT therefore still resolves, at the cost of a round trip, while a spoofed
source gets a truncated answer it cannot follow up.

This is what BIND's `rate-limit` and Knot's RRL do, and the shape is theirs.
*/

/*
The table is fixed at construction and never grows.

A cache of buckets that allocated per source would be a memory bound written in
terms of how many distinct addresses an attacker cares to name, which is not a
bound. Sixteen thousand buckets is 512 KB and more prefixes than a resolver
serves; what collides shares a budget, which is a limit that is too strict on
rare occasions rather than a limit that fails.
*/
@(private)
RRL_BUCKETS :: 16384

/*
Seconds of unused budget a prefix may bank.

A client that has been quiet may answer a burst at once - a browser opening a
page asks for a dozen names in as many milliseconds - so the bucket holds more
than one second's worth. Two seconds is enough for any burst a real client
produces and still bounds what one moment of an attack delivers.
*/
@(private)
RRL_BURST_SECONDS :: 2

@(private)
Rate_Bucket :: struct {
	// The hashed prefix this bucket is accounting for; 0 when unused.
	key:     u64,
	tokens:  f64,
	last_ns: i64,
	// Over-limit queries since the last one that was answered, for `slip`.
	over:    u32,
}

Rate_Limiter :: struct {
	buckets:   []Rate_Bucket,
	// Tokens per second, and the most that may be banked.
	rate:      f64,
	capacity:  f64,
	slip:      int,
	/*
	Keyed with process entropy, so which prefixes share a bucket is not
	something an attacker can work out and use.

	Without it the mapping is a published function of the address: an attacker
	who wanted a particular victim's answers dropped could send from whatever
	prefix collides with theirs and spend the shared budget on purpose. With it
	the table's layout is unknown outside this process.
	*/
	hash_key:  [16]u8,
	allocator: mem.Allocator,
	// Counted here rather than in Stats because these are properties of the
	// limiter, and read by tests.
	limited:   u64,
	slipped:   u64,
}

make_rate_limiter :: proc(
	responses_per_second: int,
	slip: int,
	allocator := context.allocator,
) -> ^Rate_Limiter {
	r := new(Rate_Limiter, allocator)
	r.allocator = allocator
	r.buckets = make([]Rate_Bucket, RRL_BUCKETS, allocator)
	r.rate = f64(max(responses_per_second, 1))
	r.capacity = r.rate * RRL_BURST_SECONDS
	r.slip = max(slip, 0)
	crypto.rand_bytes(r.hash_key[:])
	return r
}

destroy_rate_limiter :: proc(r: ^Rate_Limiter) {
	if r == nil {
		return
	}
	delete(r.buckets, r.allocator)
	free(r, r.allocator)
}

Rate_Verdict :: enum u8 {
	// Under the budget: answer it as usual.
	Allow,
	// Over the budget, and this is the one in `slip` that gets told so.
	Truncate,
	// Over the budget: send nothing at all.
	Drop,
}

/*
Charge one response to `client`'s prefix and say what to do with it.

Called from the UDP read loop and from nowhere else. That loop is one thread,
which is why nothing here is locked; a second reader would need this table to be
locked or split per thread.

`now` is passed in rather than read here so a test can run a bucket through an
hour in a few microseconds.
*/
rate_check :: proc(r: ^Rate_Limiter, client: net.Endpoint, now: time.Tick) -> Rate_Verdict {
	if r == nil {
		return .Allow
	}

	key := prefix_key(r, client.address)
	b := &r.buckets[key % RRL_BUCKETS]

	// Monotonic: a wall clock stepped backwards by an NTP correction would hand
	// out a bucket's worth of budget, and stepped forwards, none.
	now_ns := now._nsec
	if b.key != key {
		/*
		Somebody else's bucket, or one never used.

		Taken over only once it has refilled: a bucket still spending is one a
		live prefix is being accounted by, and handing it to a newcomer would
		let a flood from one prefix clear the accounting of another. Otherwise
		the two share what is left, which is the conservative reading of a
		collision.
		*/
		refilled := b.key == 0 || b.tokens + elapsed_tokens(r, b.last_ns, now_ns) >= r.capacity
		if refilled {
			b.key = key
			b.tokens = r.capacity
			b.last_ns = now_ns
			b.over = 0
		}
	}

	b.tokens = min(r.capacity, b.tokens + elapsed_tokens(r, b.last_ns, now_ns))
	b.last_ns = now_ns

	if b.tokens >= 1 {
		b.tokens -= 1
		b.over = 0
		return .Allow
	}

	sync.atomic_add(&r.limited, 1)
	b.over += 1
	if r.slip > 0 && int(b.over) % r.slip == 0 {
		sync.atomic_add(&r.slipped, 1)
		return .Truncate
	}
	return .Drop
}

@(private)
elapsed_tokens :: proc(r: ^Rate_Limiter, last_ns, now_ns: i64) -> f64 {
	if last_ns == 0 || now_ns <= last_ns {
		return 0
	}
	return f64(now_ns - last_ns) / f64(time.Second) * r.rate
}

/*
The prefix an answer would be delivered to, hashed.

/24 and /64 are the units an attacker picks addresses within, so they are the
units the budget is kept in. The hash is keyed (see `hash_key`), and never
returns 0, which marks a bucket as unused.
*/
@(private)
prefix_key :: proc(r: ^Rate_Limiter, address: net.Address) -> u64 {
	buf: [16]u8
	n := 0
	switch a in address {
	case net.IP4_Address:
		buf[0], buf[1], buf[2] = a[0], a[1], a[2]
		n = 3
	case net.IP6_Address:
		for i in 0 ..< 4 {
			buf[i * 2] = u8(u16(a[i]) >> 8)
			buf[i * 2 + 1] = u8(u16(a[i]))
		}
		n = 8
	}
	if n == 0 {
		return 1
	}
	h := siphash.sum_bytes_2_4(buf[:n], r.hash_key[:])
	return h if h != 0 else 1
}

start_rate_limiter :: proc(s: ^Server) -> bool {
	cfg := s.cfg.server.rate_limit
	if !cfg.enabled {
		return true
	}
	s.limiter = make_rate_limiter(cfg.responses_per_second, cfg.slip)
	if cfg.slip > 0 {
		logx.infof(
			"rate limit: %d responses/s per client prefix (/24, /64); 1 in %d over that answered truncated",
			cfg.responses_per_second,
			cfg.slip,
		)
	} else {
		logx.infof(
			"rate limit: %d responses/s per client prefix (/24, /64); anything over that dropped",
			cfg.responses_per_second,
		)
	}
	return true
}

stop_rate_limiter :: proc(s: ^Server) {
	destroy_rate_limiter(s.limiter)
	s.limiter = nil
}

// Read for the periodic stats line and by tests.
rate_limit_stats :: proc(r: ^Rate_Limiter) -> (limited, slipped: u64) {
	if r == nil {
		return 0, 0
	}
	return sync.atomic_load(&r.limited), sync.atomic_load(&r.slipped)
}
