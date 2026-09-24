package itest

import "core:fmt"

/*
The one divergence parity is defined to allow, checked for being exactly that.

A blocked name is answered by this server and not by its upstream, so there is
nothing to hold it to parity against - but that is not the same as there being
nothing to check. A block that also asked the upstream has leaked the name it
was meant to keep, a block that answered something other than the configured
response has told the client something nobody decided, and a name the rules do
not cover being answered as blocked is the worst divergence of all, because it
looks deliberate. So every answer in a blocking scenario is one of two things:
the block response, for exactly the names the rules cover, or parity with the
upstream, for everything else.

The rules here are read independently of the filter engine rather than asked of
it. A judge that consulted the implementation could not catch it being wrong.
*/

// Whether `name` (wire form) is `zone` or below it, compared without case on
// label boundaries - the way a `||zone^` rule reads.
parity_name_under :: proc(name: []u8, zone: string) -> bool {
	want := pm_name(zone, context.temp_allocator)
	pos := 0
	for pos < len(name) {
		if len(name) - pos == len(want) && pw_names_equal_fold(name[pos:], want) {
			return true
		}
		n := int(name[pos])
		if n == 0 || n & 0xc0 != 0 {
			return false
		}
		pos += 1 + n
	}
	return false
}

// Whether the blocking scenario's rules cover `name`: under a blocked zone and
// not under the allowed one inside it.
parity_blocked_name :: proc(name: []u8) -> bool {
	if parity_name_under(name, PARITY_ALLOWED) {
		return false
	}
	for zone in PARITY_BLOCKED {
		if parity_name_under(name, zone) {
			return true
		}
	}
	return false
}

/*
Whether the upstream's answer leads into a blocked name.

Any CNAME in the answer section whose target the rules cover. The mock's chains
start at the question and are one link long (`pm_cname_chain`), so "any CNAME"
and "the chain from the question" are the same set here, and the looser reading
is the one that cannot miss a link.
*/
parity_cloaked :: proc(reference: []u8) -> bool {
	m := pw_parse(reference, context.temp_allocator)
	if !m.ok {
		return false
	}
	for rec in m.answer {
		if rec.type == 5 && parity_blocked_name(rec.rdata) {
			return true
		}
	}
	return false
}

/*
An answer the rules said to block, held to the configured block response.

`blocking.response: nxdomain`: NXDOMAIN, nothing in the answer section, and the
question echoed as it was asked like any other answer. Blocked by name, the
upstream must not have been asked at all - asking it is the leak a block list is
there to prevent. Blocked by a CNAME target the upstream had to be asked, since
the CNAME is in its answer; what must not happen there is the answer reaching
the client.
*/
parity_check_blocked :: proc(
	r: ^Runner,
	q: Parity_Query,
	answer: []u8,
	asked: bool,
	by_cname: bool,
	stats: ^Parity_Stats,
) {
	stats.blocked += 1
	m := pw_parse(answer, context.temp_allocator)
	why := by_cname ? "its cname target is blocked" : "its name is blocked"

	problem := ""
	switch {
	case !m.ok:
		problem = fmt.tprintf("the answer does not parse: %s", m.err)
	case m.id != q.id:
		problem = fmt.tprintf("the answer came back with id %d, not %d", m.id, q.id)
	case len(m.question) != 1 || string(m.question[0].name) != string(q.name):
		problem = "the question is not echoed byte for byte"
	case !by_cname && asked:
		problem = "the upstream was asked about a name the rules block"
	case m.rcode != 3:
		problem = fmt.tprintf("rcode %s, not the configured nxdomain", pc_rcode_text(m.rcode, context.temp_allocator))
	case len(m.answer) != 0:
		problem = fmt.tprintf("a block response carrying %d answer records", len(m.answer))
	case m.opt.present != q.edns:
		problem = q.edns ? "no opt record for a client that sent one" : "an opt record for a client that sent none"
	}
	if problem == "" {
		return
	}
	stats.failures += 1
	fail(r, "%s (%s): %s\n    query:  %s\n    elodin: %s", q.desc, why, problem, parity_hex(q.wire), parity_hex(answer))
}
