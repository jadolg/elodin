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
	max_bytes:    int,
	// What the entries currently hold, by `entry_bytes`.
	bytes:        int,
	min_ttl:      u32,
	max_ttl:      u32,
	negative_ttl: u32,
	serve_stale:  bool,
	allocator:    mem.Allocator,
	stats:        Stats,
}

// TTL handed out with a stale answer so the client comes back soon.
STALE_TTL :: 30

/*
What the cache may hold when the operator has not said.

A count on its own is not a bound on memory. An entry holds the response as it
arrived - up to 64 KiB, since a query over TCP, DoT or DoH is answered with the
whole message rather than a 512-byte UDP one - plus an offset and a TTL for
every record in it, which for a response packed with minimal records comes to
about twice the wire size again. Ten thousand of those is on the order of 640 MB
for a setting that reads like a modest cache, and an attacker serving maximal
answers from a zone it controls needs only distinct names to walk elodin there.
The end of that is the resolver being killed for the memory it took, which on a
box where elodin is the system resolver takes name resolution with it.

64 MiB is far above what a working set of ordinary answers needs - the default
ten thousand entries measure about 4.6 MB in practice - and far below what the
count alone would allow.
*/
DEFAULT_MAX_BYTES :: 64 * 1024 * 1024

Options :: struct {
	max_entries:  int,
	max_bytes:    int,
	min_ttl:      u32,
	max_ttl:      u32,
	negative_ttl: u32,
	serve_stale:  bool,
}

make_cache :: proc(opts: Options, allocator := context.allocator) -> ^Cache {
	c := new(Cache, allocator)
	c.allocator = allocator
	c.max_entries = max(opts.max_entries, 1)
	c.max_bytes = opts.max_bytes if opts.max_bytes > 0 else DEFAULT_MAX_BYTES
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
		remove_entry(c, e)
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

	/*
	An entry that could not fit on its own is not cached at all.

	Storing it would mean evicting everything else to make room it still does not
	have, so the cache would empty itself for one answer and then drop that too.
	Nothing an operator can set makes this reachable with real answers: the
	smallest budget worth configuring is orders of magnitude past the 64 KiB a
	response can be.
	*/
	size := sizeof_entry(key, wire, offsets, ttls)
	if size > c.max_bytes {
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
		remove_entry(c, old)
	}
	c.entries[e.key] = e
	push_front(c, e)
	c.bytes += size
	c.stats.inserts += 1

	// Both bounds, because the count alone is not one: see DEFAULT_MAX_BYTES. The
	// entry just inserted is at the head and was refused above if it could not
	// fit by itself, so this cannot come round to evicting it.
	for (len(c.entries) > c.max_entries || c.bytes > c.max_bytes) && c.tail != nil {
		remove_entry(c, c.tail)
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
	c.bytes = 0
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
			remove_entry(c, e)
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

// What the entries hold, counted the way the bound counts it.
bytes_used :: proc(c: ^Cache) -> int {
	if c == nil {
		return 0
	}
	sync.mutex_lock(&c.mu)
	defer sync.mutex_unlock(&c.mu)
	return c.bytes
}

stats :: proc(c: ^Cache) -> Stats {
	if c == nil {
		return {}
	}
	sync.mutex_lock(&c.mu)
	defer sync.mutex_unlock(&c.mu)
	return c.stats
}

/*
What one entry costs the process, near enough to bound it by.

The response as it arrived, an offset and a TTL for every record in it, the key,
and the entry itself. What is left out is the map's own slot, which is a pointer
and a hash in a table that grows in steps rather than per entry - a few tens of
bytes against a mean entry of several hundred, and not something an attacker can
inflate on its own.
*/
@(private)
sizeof_entry :: proc(key: string, wire: []u8, offsets: []int, ttls: []u32) -> int {
	return size_of(Entry) + len(key) + len(wire) + len(offsets) * size_of(int) + len(ttls) * size_of(u32)
}

@(private)
entry_bytes :: proc(e: ^Entry) -> int {
	return sizeof_entry(e.key, e.wire, e.ttl_offsets, e.ttls)
}

/*
Take an entry out of the cache entirely: the list, the map, the byte total, the
memory.

Every removal goes through here. Doing it by hand at each of the four call sites
is how a byte total drifts from what is actually held, and a bound computed from
a drifting total is not a bound.

The caller holds the lock.
*/
@(private)
remove_entry :: proc(c: ^Cache, e: ^Entry) {
	unlink(c, e)
	// Before `free_entry`, which frees the string the map is keyed on.
	delete_key(&c.entries, e.key)
	c.bytes -= entry_bytes(e)
	free_entry(c, e)
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
