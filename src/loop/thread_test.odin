package loop

import "base:runtime"
import "core:sys/posix"
import "core:testing"
import "core:thread"

@(private = "file")
Mask_Probe :: struct {
	blocked: [3]bool,
}

@(test)
test_a_spawned_thread_holds_the_signals_main_acts_on :: proc(t: ^testing.T) {
	// See `spawn_thread`: a thread that took one in a timed read would fail the read.
	before: Mask_Probe
	read_mask(&before)
	probe: Mask_Probe
	th := spawn_thread(&probe, read_mask)
	if !testing.expect(t, th != nil, "no thread") {
		return
	}
	thread.join(th)
	thread.destroy(th)
	testing.expect_value(t, probe.blocked, [3]bool{true, true, true})

	// And the caller's own mask is put back as it was.
	after: Mask_Probe
	read_mask(&after)
	testing.expect_value(t, after.blocked, before.blocked)
}

@(private = "file")
read_mask :: proc(p: ^Mask_Probe) {
	cur: posix.sigset_t
	posix.pthread_sigmask(.BLOCK, nil, &cur)
	for sig, i in ([]posix.Signal{.SIGTERM, .SIGINT, .SIGHUP}) {
		p.blocked[i] = posix.sigismember(&cur, sig) == 1
	}
}

/*
`mapped_allocator` hands out zeroed memory aligned as asked, and refuses an
alignment past a page rather than return a pointer that is not aligned to it.
*/
@(test)
test_mapped_allocator_aligns_and_zeroes :: proc(t: ^testing.T) {
	for align in ([]int{16, 64, MAPPING_ALIGN_MAX}) {
		b, err := runtime.mem_alloc(10_000, align, mapped_allocator)
		if !testing.expectf(t, err == nil && len(b) == 10_000, "align %d: %v", align, err) {
			return
		}
		testing.expectf(t, uintptr(raw_data(b)) % uintptr(align) == 0, "align %d: %p", align, raw_data(b))
		zero := true
		for c in b {
			zero &&= c == 0
		}
		testing.expectf(t, zero, "align %d: not zeroed", align)
		b[len(b) - 1] = 1
		testing.expect_value(t, runtime.mem_free(raw_data(b), mapped_allocator), nil)
	}
	_, err := runtime.mem_alloc(64, 2 * MAPPING_ALIGN_MAX, mapped_allocator)
	testing.expect_value(t, err, runtime.Allocator_Error.Invalid_Argument)
}
