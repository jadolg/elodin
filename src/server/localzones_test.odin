package server

import "core:testing"

/*
The gate that keeps RFC 6303 locally-served names off the public chain of trust.

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
test_label_boundary_is_respected :: proc(t: ^testing.T) {
	// A bare string suffix that does not fall on a label break is a different
	// name, not a subtree, and must not be swept in.
	testing.expect(
		t,
		!is_locally_served("evil168.192.in-addr.arpa."),
		"a name that only shares a string suffix is not inside the zone",
	)
}
