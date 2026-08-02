package cache

import "core:mem"
import "core:strings"
import "core:sync"
import "core:time"
import "elodin:dns"

/*
An LRU answer cache.

Entries hold the upstream response exactly as it arrived on the wire, together
with the byte offsets of every TTL field. Serving a hit is a copy plus a handful
of u32 writes, which keeps the original name compression intact and avoids a
decode/encode round trip on the hot path.
*/

Entry :: struct {
	key:         string,
	wire:        []u8,
	ttl_offsets: []int,
	ttls:        []u32,
	inserted:    time.Time,
	expires:     time.Time,
	prev, next:  ^Entry,
}

Stats :: struct {
	hits:      u64,
	misses:    u64,
	stale:     u64,
	inserts:   u64,
	evictions: u64,
}

Cache :: struct {
	mu:           sync.Mutex,
	entries:      map[string]^Entry,
	head, tail:   ^Entry,
	max_entries:  int,
	min_ttl:      u32,
	max_ttl:      u32,
	negative_ttl: u32,
	serve_stale:  bool,
	allocator:    mem.Allocator,
	stats:        Stats,
}

// TTL handed out with a stale answer so the client comes back soon.
STALE_TTL :: 30

Options :: struct {
	max_entries:  int,
	min_ttl:      u32,
	max_ttl:      u32,
	negative_ttl: u32,
	serve_stale:  bool,
}

make_cache :: proc(opts: Options, allocator := context.allocator) -> ^Cache {
	c := new(Cache, allocator)
	c.allocator = allocator
	c.max_entries = max(opts.max_entries, 1)
	c.min_ttl = opts.min_ttl
	c.max_ttl = opts.max_ttl if opts.max_ttl > 0 else 86400
	c.negative_ttl = opts.negative_ttl
	c.serve_stale = opts.serve_stale
	c.entries = make(map[string]^Entry, max(opts.max_entries, 16), allocator)
	return c
}

destroy :: proc(c: ^Cache) {
	if c == nil {
		return
	}
	for _, e in c.entries {
		free_entry(c, e)
	}
	delete(c.entries)
	free(c, c.allocator)
}

// Longest key we build on the stack: a presentation name plus type/class/flags.
KEY_MAX :: 1024 + 8

/*
Build a lookup key for a question.

`dnssec_ok` is part of the key because a resolver may return a different answer
set depending on the DO bit, and serving one to the other would be wrong.

`checking_disabled` is part of it for a sharper reason: a client that sets CD
gets whatever the upstream said, validated or not, and that answer must never
come back out of the cache for a client that asked us to check.
*/
make_key :: proc(
	buf: []u8,
	name: string,
	type: dns.Type,
	class: dns.Class,
	dnssec_ok: bool,
	checking_disabled := false,
) -> string {
	n := 0
	limit := len(buf) - 8
	for i in 0 ..< len(name) {
		if n >= limit {
			break
		}
		c := name[i]
		buf[n] = c + 32 if c >= 'A' && c <= 'Z' else c
		n += 1
	}
	buf[n] = u8(u16(type) >> 8)
	buf[n + 1] = u8(u16(type))
	buf[n + 2] = u8(u16(class) >> 8)
	buf[n + 3] = u8(u16(class))
	buf[n + 4] = 1 if dnssec_ok else 0
	buf[n + 5] = 1 if checking_disabled else 0
	return string(buf[:n + 6])
}

/*
Look a response up.

On a hit the returned bytes are a fresh copy owned by `allocator`, with TTLs
already counted down and the transaction ID left at whatever the cached message
had; callers set the ID and re-case the question themselves.
*/
get :: proc(
	c: ^Cache,
	key: string,
	allocator := context.allocator,
) -> (
	wire: []u8,
	stale: bool,
	ok: bool,
) {
	if c == nil {
		return nil, false, false
	}
	sync.mutex_lock(&c.mu)
	defer sync.mutex_unlock(&c.mu)

	e, found := c.entries[key]
	if !found {
		c.stats.misses += 1
		return nil, false, false
	}

	now := time.now()
	expired := time.diff(e.expires, now) > 0
	if expired && !c.serve_stale {
		unlink(c, e)
		delete_key(&c.entries, key)
		free_entry(c, e)
		c.stats.misses += 1
		return nil, false, false
	}

	elapsed := u32(max(0, time.duration_seconds(time.diff(e.inserted, now))))
	out := make([]u8, len(e.wire), allocator)
	copy(out, e.wire)

	if expired {
		// A stale answer goes out with a short fixed TTL rather than a
		// counted-down one, which would already have reached zero.
		for off in e.ttl_offsets {
			out[off] = 0
			out[off + 1] = 0
			out[off + 2] = u8(STALE_TTL >> 8)
			out[off + 3] = u8(STALE_TTL)
		}
		c.stats.stale += 1
		stale = true
	} else {
		dns.patch_ttls(out, e.ttl_offsets, e.ttls, elapsed, c.min_ttl)
	}

	move_to_front(c, e)
	c.stats.hits += 1
	return out, stale, true
}

/*
Store a response.

Returns false when the message should not be cached at all: truncated answers,
transient failures, and anything whose effective TTL works out as zero.
*/
put :: proc(c: ^Cache, key: string, wire: []u8, msg: dns.Message) -> bool {
	if c == nil || len(wire) < dns.HEADER_SIZE {
		return false
	}
	if msg.flags.tc {
		return false
	}

	rcode := dns.rcode_of(msg)
	#partial switch rcode {
	case .No_Error, .NX_Domain:
	case:
		return false
	}

	offsets, scan_ok := dns.scan_ttl_offsets(wire, c.allocator)
	if !scan_ok {
		return false
	}
	ttls := dns.read_ttls(wire, offsets, c.allocator)

	effective: u32
	if rcode == .NX_Domain || len(msg.answer) == 0 {
		effective = dns.negative_ttl(msg, c.negative_ttl)
		if c.negative_ttl > 0 {
			effective = min(effective, c.negative_ttl)
		}
	} else {
		v, has := dns.min_ttl(ttls)
		effective = v if has else 0
	}
	effective = clamp(effective, c.min_ttl, c.max_ttl)
	if effective == 0 {
		delete(offsets, c.allocator)
		delete(ttls, c.allocator)
		return false
	}

	now := time.now()
	e := new(Entry, c.allocator)
	e.key = strings.clone(key, c.allocator)
	e.wire = make([]u8, len(wire), c.allocator)
	copy(e.wire, wire)
	e.ttl_offsets = offsets
	e.ttls = ttls
	e.inserted = now
	e.expires = time.time_add(now, time.Duration(effective) * time.Second)

	sync.mutex_lock(&c.mu)
	defer sync.mutex_unlock(&c.mu)

	if old, exists := c.entries[key]; exists {
		unlink(c, old)
		delete_key(&c.entries, key)
		free_entry(c, old)
	}
	c.entries[e.key] = e
	push_front(c, e)
	c.stats.inserts += 1

	for len(c.entries) > c.max_entries && c.tail != nil {
		victim := c.tail
		unlink(c, victim)
		delete_key(&c.entries, victim.key)
		free_entry(c, victim)
		c.stats.evictions += 1
	}
	return true
}

// Drop everything, e.g. after a configuration reload.
clear_all :: proc(c: ^Cache) {
	if c == nil {
		return
	}
	sync.mutex_lock(&c.mu)
	defer sync.mutex_unlock(&c.mu)
	for _, e in c.entries {
		free_entry(c, e)
	}
	clear(&c.entries)
	c.head, c.tail = nil, nil
}

// Remove every entry whose TTL has run out. Called periodically so a cache that
// stops being queried does not hold memory indefinitely.
sweep :: proc(c: ^Cache) -> (removed: int) {
	if c == nil {
		return 0
	}
	sync.mutex_lock(&c.mu)
	defer sync.mutex_unlock(&c.mu)

	now := time.now()
	e := c.tail
	for e != nil {
		prev := e.prev
		if time.diff(e.expires, now) > 0 {
			unlink(c, e)
			delete_key(&c.entries, e.key)
			free_entry(c, e)
			removed += 1
		}
		e = prev
	}
	return
}

len_entries :: proc(c: ^Cache) -> int {
	if c == nil {
		return 0
	}
	sync.mutex_lock(&c.mu)
	defer sync.mutex_unlock(&c.mu)
	return len(c.entries)
}

stats :: proc(c: ^Cache) -> Stats {
	if c == nil {
		return {}
	}
	sync.mutex_lock(&c.mu)
	defer sync.mutex_unlock(&c.mu)
	return c.stats
}

@(private)
free_entry :: proc(c: ^Cache, e: ^Entry) {
	delete(e.wire, c.allocator)
	delete(e.ttl_offsets, c.allocator)
	delete(e.ttls, c.allocator)
	delete(e.key, c.allocator)
	free(e, c.allocator)
}

@(private)
push_front :: proc(c: ^Cache, e: ^Entry) {
	e.prev = nil
	e.next = c.head
	if c.head != nil {
		c.head.prev = e
	}
	c.head = e
	if c.tail == nil {
		c.tail = e
	}
}

@(private)
unlink :: proc(c: ^Cache, e: ^Entry) {
	if e.prev != nil {
		e.prev.next = e.next
	} else if c.head == e {
		c.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else if c.tail == e {
		c.tail = e.prev
	}
	e.prev, e.next = nil, nil
}

@(private)
move_to_front :: proc(c: ^Cache, e: ^Entry) {
	if c.head == e {
		return
	}
	unlink(c, e)
	push_front(c, e)
}
