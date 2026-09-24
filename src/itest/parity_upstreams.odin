package itest

import "core:slice"
import "core:strings"
import "core:time"

/*
The upstreams a mock-mode scenario runs against: one mock per entry in the
scenario's `kinds`, every one answering from the same synthetic zone.

The same zone is what lets several of them stand in for one. The mock's answer is
a function of the question and nothing else about the exchange - not which mock,
not which transport - so whichever of them a strategy picks, raced or rotated or
routed, the reply it sent is this query's reference.
*/
Parity_Upstreams :: struct {
	// Parallel: entry `i` is a plain mock or, for an HTTPS upstream, a DoH one.
	mocks: [dynamic]^Mock,
	doh:   [dynamic]^Doh2_Mock,
	ports: [dynamic]int,
}

parity_upstreams_start :: proc(r: ^Runner, s: Parity_Scenario) -> (ups: Parity_Upstreams, ok: bool) {
	ups.mocks = make([dynamic]^Mock, 0, len(s.kinds))
	ups.doh = make([dynamic]^Doh2_Mock, 0, len(s.kinds))
	ups.ports = make([dynamic]int, 0, len(s.kinds))
	for kind in s.kinds {
		port := next_port(r)
		append(&ups.ports, port)
		if kind == .HTTPS {
			d := doh2_mock_make(port, "/dns-query", nil)
			d.parity = true
			append(&ups.mocks, nil)
			append(&ups.doh, d)
			if !doh2_mock_start(d, r.cert_file, r.key_file) {
				fail(r, "the parity doh mock did not start on port %d", port)
				return ups, false
			}
			continue
		}
		m := mock_make("parity", port)
		mock_parity_all(m)
		append(&ups.mocks, m)
		append(&ups.doh, nil)
		started := kind == .TLS ? mock_start(m, r.cert_file, r.key_file) : mock_start(m)
		if !started {
			fail(r, "the parity mock did not start on port %d", port)
			return ups, false
		}
	}
	return ups, true
}

parity_upstreams_stop :: proc(ups: ^Parity_Upstreams) {
	for m in ups.mocks {
		if m != nil {
			mock_stop(m)
		}
	}
	for d in ups.doh {
		if d != nil {
			doh2_mock_stop(d)
		}
	}
	delete(ups.mocks)
	delete(ups.doh)
	delete(ups.ports)
}

parity_upstreams_reset :: proc(ups: ^Parity_Upstreams) {
	for m, i in ups.mocks {
		if m != nil {
			mock_reset_replies(m)
		} else {
			doh2_mock_reset_replies(ups.doh[i])
		}
	}
}

/*
The reply this query was answered from, and which upstream sent it.

`asked` is false when no upstream answered this question since the last reset,
which is the server having answered from its own mouth.

A reply is only taken for this query if it answers this query's question. The
race strategy is why: the slower upstream's reply to the previous query can land
after the reset, and read without the check it would be the reference for a
question it never answered. Where several upstreams answered - the race again -
any whole reply will do, because the zone is the same zone; one cut short for a
datagram is only taken if there is nothing better, which there always is once
the retry over TCP has come back.
*/
parity_upstreams_reference :: proc(
	ups: ^Parity_Upstreams,
	q: Parity_Query,
) -> (
	reference: []u8,
	from: int,
	asked: bool,
) {
	from = -1
	for m, i in ups.mocks {
		reply: []u8
		count: int
		if m != nil {
			reply, count = mock_last_reply(m)
		} else {
			reply, count = doh2_mock_last_reply(ups.doh[i])
		}
		if count == 0 || reply == nil || !parity_answers_question(reply, q) {
			continue
		}
		whole := len(reply) > 2 && reply[2] & 0x02 == 0
		if reference == nil || whole {
			reference, from = reply, i
		}
		asked = true
		if whole {
			break
		}
	}
	return
}

// Whether `reply` is an answer to `q`'s question, name compared without case.
parity_answers_question :: proc(reply: []u8, q: Parity_Query) -> bool {
	m := pw_parse(reply, context.temp_allocator)
	if !m.ok || len(m.question) != 1 {
		return false
	}
	got := m.question[0]
	return got.type == q.qtype && got.class == q.qclass && pw_names_equal_fold(got.name, q.name)
}

/*
A cached answer's reference: the reply the upstream gave the last time this
question was put to it, and when.

A cached answer is served without asking anybody, so there is no reply of this
query's own to hold it against. The mock's answer is a function of the question,
though, so the reply it gave the query that filled the entry is the reply the
entry was made from - and the entry's age is how far its ttls may have counted
down since.
*/
Parity_Cached :: struct {
	reply: []u8,
	at:    time.Time,
}

/*
Keyed the way the server's cache is (`cache.make_key`): the question folded to
lower case, its type and class, and the DO and CD bits.

The mock's answer does not depend on either bit, so a coarser key would find
the right records - and the wrong moment. The server holds one entry per
DO/CD pair, filled at different times, and an entry's age is what a cached ttl
is judged by; keyed without them, the reference's time is whichever pair was
forwarded last, and an older entry's countdown reads as a ttl that fell further
than it had any right to.
*/
parity_cache_key :: proc(q: Parity_Query, allocator := context.temp_allocator) -> string {
	n := len(q.name)
	key := make([]u8, n + 6, allocator)
	copy(key, q.name)
	pw_lower_name(key[:n])
	key[n] = u8(q.qtype >> 8)
	key[n + 1] = u8(q.qtype)
	key[n + 2] = u8(q.qclass >> 8)
	key[n + 3] = u8(q.qclass)
	key[n + 4] = u8(q.do_bit)
	key[n + 5] = u8(q.cd)
	return string(key)
}

parity_cache_store :: proc(store: ^map[string]Parity_Cached, q: Parity_Query, reply: []u8) {
	key := parity_cache_key(q)
	if old, found := store[key]; found {
		delete(old.reply)
		store[key] = Parity_Cached{reply = slice.clone(reply), at = time.now()}
		return
	}
	store[strings.clone(key)] = Parity_Cached{reply = slice.clone(reply), at = time.now()}
}

parity_cache_destroy :: proc(store: ^map[string]Parity_Cached) {
	for key, v in store {
		delete(key)
		delete(v.reply)
	}
	delete(store^)
}
