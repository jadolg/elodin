/*
Fixtures the unit tests of more than one package share. A package's tests cannot
reach another package's `_test.odin` files, so a helper two packages' tests need
lives here, and only test files import it.
*/
package testkit

import "core:sys/linux"
import "elodin:dns"

/*
A window-0 type bit map (RFC 4034 section 4.1.2) holding `types`, every one
below 256; nil for none, since a window with no type set is never written.
*/
type_bitmap :: proc(types: ..dns.Type) -> []u8 {
	if len(types) == 0 {
		return nil
	}
	high := 0
	for type in types {
		assert(int(type) < 256, "type_bitmap writes window 0 only")
		high = max(high, int(type))
	}
	length := high / 8 + 1
	out := make([]u8, 2 + length, context.temp_allocator)
	out[1] = u8(length)
	for type in types {
		out[2 + int(type) / 8] |= 0x80 >> u8(int(type) % 8)
	}
	return out
}

// Bytes `fd` sent that its peer has not acknowledged: `SIOCOUTQ`. -1 when the
// kernel will not say.
unacked_bytes :: proc(fd: linux.Fd) -> int {
	SIOCOUTQ :: 0x5411
	n: i32
	if i32(linux.ioctl(fd, SIOCOUTQ, uintptr(&n))) < 0 {
		return -1
	}
	return int(n)
}
