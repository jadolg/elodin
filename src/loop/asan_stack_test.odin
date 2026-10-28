package loop

import "core:testing"

when ASAN {
	@(private = "file", default_calling_convention = "c")
	foreign _ {
		__asan_poison_memory_region :: proc(addr: rawptr, size: uint) ---
		__asan_address_is_poisoned :: proc(addr: rawptr) -> i32 ---
	}
}

/*
An unmapped stack leaves no poison behind for whatever is mapped there next.

A fiber's frames poison the stack's shadow as they are entered, and the one a
fiber leaves on its stack for good - `fiber_entry`, which never returns -
leaves that poison in place. The stack goes with a raw `munmap`, which
AddressSanitizer never sees, and the next stack of the same size is mapped at
the same addresses: its frames' locals then sit on stale redzones, and the first
write to one is reported as an overflow that is not there (soak, PR #549).
Asked of the address itself after the unmap, so it does not depend on where the
kernel puts the next mapping. Only an AddressSanitizer build has shadow memory
to ask.
*/
@(test)
test_an_unmapped_stack_leaves_no_poison :: proc(t: ^testing.T) {
	when ASAN {
		s, mapped := stack_map()
		if !testing.expect(t, mapped, "no stack") {
			return
		}
		// Where a frame near the top of the stack would put a redzone.
		spot := rawptr(stack_top(s) - 512)
		__asan_poison_memory_region(spot, 32)
		testing.expect(t, __asan_address_is_poisoned(spot) != 0, "the premise: the spot is poisoned while mapped")
		stack_unmap(s)
		testing.expect(t, __asan_address_is_poisoned(spot) == 0, "the unmapped stack's shadow still says poisoned")
	}
}
