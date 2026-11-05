#+build linux
package loop

import "core:slice"
import "core:testing"
import "core:thread"

@(private = "file")
Pin_Probe :: struct {
	allowed:        []int,
	// What the thread's affinity was after each pin, and whether the pin said it held.
	after:          [dynamic][]int,
	held:           [dynamic]bool,
	refused:        bool,
	// A CPU inside the mask but past any this machine has: the kernel's refusal.
	refused_kernel: bool,
	after_no:       []int,
}

/*
A thread pinned to each CPU the process may use is then allowed that CPU alone,
and a CPU past the mask is refused with the thread left as it was.

On a thread of its own: the test runner's threads run other tests after this one,
and a pin would hold them to one CPU for the rest of the run.
*/
@(test)
test_a_pinned_thread_runs_on_its_cpu_alone :: proc(t: ^testing.T) {
	p := Pin_Probe {
		allowed = allowed_cpus(context.temp_allocator),
		after   = make([dynamic][]int, context.temp_allocator),
		held    = make([dynamic]bool, context.temp_allocator),
	}
	testing.expect(t, len(p.allowed) > 0, "the process's affinity could not be read")
	th := thread.create_and_start_with_poly_data(&p, proc(p: ^Pin_Probe) {
		p.refused = !pin_current_thread(CPU_MASK_WORDS * 64)
		p.refused_kernel = !pin_current_thread(CPU_MASK_WORDS * 64 - 1)
		p.after_no = allowed_cpus(context.temp_allocator)
		for cpu in p.allowed {
			append(&p.held, pin_current_thread(cpu))
			append(&p.after, allowed_cpus(context.temp_allocator))
		}
	}, context)
	thread.join(th)
	thread.destroy(th)

	testing.expect(t, p.refused, "a CPU past the mask was not refused")
	testing.expect(t, p.refused_kernel, "a CPU past the machine's was not refused")
	testing.expect(t, slice.equal(p.after_no, p.allowed), "a refused pin changed the thread's affinity")
	for cpu, i in p.allowed {
		testing.expectf(t, p.held[i], "pinning to CPU %d failed", cpu)
		testing.expectf(t, slice.equal(p.after[i], []int{cpu}), "pinned to CPU %d, the thread may run on %v", cpu, p.after[i])
	}
}
