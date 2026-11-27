package upstream

import "core:testing"

/*
RFC 8484 section 5.1: a DoH client "MUST account for the Age response header
field's value [RFC7234] when calculating the DNS TTL of a response".
*/

// The final response's `Age`, the first of them; not an interim response's, and
// not one that does not parse.
@(test)
test_age_is_read_from_the_final_response :: proc(t: ^testing.T) {
	Row :: struct {
		reply: string,
		want:  u32,
	}
	rows := []Row {
		{reply = "HTTP/1.1 200 OK\r\nAge: 250\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", want = 250},
		{reply = "HTTP/1.1 200 OK\r\nage: 250\r\nAge: 10\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", want = 250},
		{reply = "HTTP/1.1 200 OK\r\nAge: soon\r\nAge: 10\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", want = 0},
		{reply = "HTTP/1.1 103 Early Hints\r\nAge: 250\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", want = 0},
		{reply = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", want = 0},
	}
	for row in rows {
		if resp, ok := response_head(t, row.reply); ok {
			testing.expectf(t, resp.age == row.want, "%q: Age read as %d, want %d", row.reply, resp.age, row.want)
		}
	}
}
