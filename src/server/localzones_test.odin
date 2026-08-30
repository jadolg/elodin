package server

import "core:testing"

/*
The gate that keeps locally-served names off the public chain of trust.

`is_locally_served` is the whole of the decision - once it answers, `validating`
follows - so the cases that matter are the boundaries: the reported name, the
siblings of the range it lives in, the label-break trap, and a public name that
must stay validated.
*/

@(test)
test_reported_private_ptr_is_locally_served :: proc(t: ^testing.T) {
	// 20.2.168.192.in-addr.arpa is the reverse name for 192.168.2.20.
	testing.expect(
		t,
		is_locally_served("20.2.168.192.in-addr.arpa."),
		"a PTR for an RFC 1918 address must skip validation",
	)
}

@(test)
test_locally_served_covers_each_family :: proc(t: ^testing.T) {
	cases := [?]string {
		"5.10.in-addr.arpa.", // 10/8
		"1.16.172.in-addr.arpa.", // low end of 172.16/12
		"1.31.172.in-addr.arpa.", // high end of 172.16/12
		"254.169.in-addr.arpa.", // link-local, exact zone
		"9.127.in-addr.arpa.", // loopback
		"1.0.0.0.d.f.ip6.arpa.", // IPv6 ULA
		"a.b.9.e.f.ip6.arpa.", // IPv6 link-local
	}
	for name in cases {
		testing.expectf(t, is_locally_served(name), "%s should be locally served", name)
	}
}

@(test)
test_case_folding_matches :: proc(t: ^testing.T) {
	testing.expect(
		t,
		is_locally_served("A.B.9.E.F.IP6.ARPA."),
		"the match must be case-insensitive",
	)
}

@(test)
test_public_names_stay_validated :: proc(t: ^testing.T) {
	// 172.17 is genuinely inside 172.16/12, so it stays served; 172.15 and
	// 172.32 sit just outside the private block and must remain validated.
	testing.expect(t, is_locally_served("1.17.172.in-addr.arpa."), "172.17 is inside 172.16/12")
	testing.expect(t, !is_locally_served("www.example.com."), "a public name must be validated")
	testing.expect(t, !is_locally_served("8.8.8.8.in-addr.arpa."), "a public reverse name must be validated")
	testing.expect(t, !is_locally_served("1.32.172.in-addr.arpa."), "172.32 is outside the private block")
	testing.expect(t, !is_locally_served("1.15.172.in-addr.arpa."), "172.15 is outside the private block")
}

@(test)
test_local_anchor_defers_the_bypass :: proc(t: ^testing.T) {
	// An operator who anchors 10.in-addr.arpa is asking for it to be validated,
	// so a name inside it is "covered" and the bypass stands down; a name in a
	// different locally-served zone is not covered and still bypasses.
	s := Server {
		anchor_zones = []string{"10.in-addr.arpa."},
	}
	testing.expect(
		t,
		covered_by_local_anchor(&s, "5.10.in-addr.arpa."),
		"a name under an anchored zone must be covered",
	)
	testing.expect(
		t,
		!covered_by_local_anchor(&s, "20.2.168.192.in-addr.arpa."),
		"a name outside every anchored zone must not be covered",
	)
	// The label-break rule holds here too.
	testing.expect(
		t,
		!covered_by_local_anchor(&s, "evil10.in-addr.arpa."),
		"a string suffix of an anchored zone is not covered",
	)
}

@(test)
test_no_anchors_means_no_coverage :: proc(t: ^testing.T) {
	// The default: root-only anchors leave anchor_zones empty, so nothing is
	// covered and every locally-served name takes the bypass.
	s := Server{}
	testing.expect(
		t,
		!covered_by_local_anchor(&s, "5.10.in-addr.arpa."),
		"with no configured anchors nothing is covered",
	)
}

@(test)
test_label_boundary_is_respected :: proc(t: ^testing.T) {
	// A bare string suffix that does not fall on a label break is a different
	// name, not a subtree, and must not be swept in.
	testing.expect(
		t,
		!is_locally_served("evil168.192.in-addr.arpa."),
		"a name that only shares a string suffix is not inside the zone",
	)
}

@(test)
test_home_arpa_is_locally_served :: proc(t: ^testing.T) {
	// RFC 8375's forward zone. `arpa` delegates it insecure, so a resolver that
	// reaches `arpa` for the proof settles it there - but the router that
	// answers the zone answers the `DS` query out of it too, so the proof never
	// arrives and the broken chain is a SERVFAIL for the printer. Not walking
	// it at all is the way past that.
	testing.expect(
		t,
		is_locally_served("printer.home.arpa."),
		"a name in the home network's own zone must skip validation",
	)
	testing.expect(t, is_locally_served("home.arpa."), "the zone's apex is inside it")
	testing.expect(t, is_locally_served("HOME.ARPA."), "the match must be case-insensitive")
	// The label-break rule, and the parent that is genuinely public.
	testing.expect(
		t,
		!is_locally_served("nothome.arpa."),
		"a name that only shares a string suffix is not inside the zone",
	)
	testing.expect(t, !is_locally_served("arpa."), "the signed parent stays validated")
	testing.expect(
		t,
		!is_locally_served("2.0.192.in-addr.arpa."),
		"a public reverse name under arpa stays validated",
	)
}

@(test)
test_home_arpa_anchor_defers_the_bypass :: proc(t: ^testing.T) {
	// An operator who signs their own home zone and anchors it locally - what
	// RFC 8375 section 5 leaves them - is asking for it to be validated, and
	// the bypass has to stand down exactly as it does on the reverse side.
	s := Server {
		anchor_zones = []string{"home.arpa."},
	}
	testing.expect(
		t,
		covered_by_local_anchor(&s, "printer.home.arpa."),
		"an anchor over the home zone puts a name inside it back under validation",
	)
	testing.expect(t, covered_by_local_anchor(&s, "home.arpa."), "the anchored apex is covered")
	testing.expect(
		t,
		!covered_by_local_anchor(&s, "nothome.arpa."),
		"a string suffix of the anchored zone is not covered",
	)
}
