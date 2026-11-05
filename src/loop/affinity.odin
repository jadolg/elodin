package loop

import "core:sys/linux"

// Room for 8192 CPUs, past any machine this runs on; the kernel refuses a mask
// shorter than the CPUs it was built for.
@(private)
CPU_MASK_WORDS :: 128

/*
The CPUs the calling thread may run on, in order: its affinity, which `taskset`, a
cpuset cgroup or systemd's `CPUAffinity=` narrow. On a thread nothing has pinned,
the main thread at startup, that is the process's. Empty when it cannot be read.
*/
allowed_cpus :: proc(allocator := context.allocator) -> []int {
	mask: [CPU_MASK_WORDS]u64
	if _, err := linux.sched_getaffinity(0, size_of(mask), &mask); err != .NONE {
		return nil
	}
	cpus := make([dynamic]int, allocator)
	for word, w in mask {
		for b in 0 ..< 64 {
			if word & (1 << uint(b)) != 0 {
				append(&cpus, w * 64 + b)
			}
		}
	}
	return cpus[:]
}

/*
Hold the calling thread to `cpu` alone; false, and the thread left as it was,
when the kernel refuses.

For an event loop (`server.pin_loops`, #610). A loop that waits in `epoll_wait`
gives up its CPU, and when it wakes the scheduler may queue it on the CPU another
loop is running on: it then waits out that loop's slice, about 3 ms, with every
connection it serves waiting behind it. A loop held to a CPU of its own never
queues behind another.
*/
pin_current_thread :: proc(cpu: int) -> bool {
	if cpu < 0 || cpu >= CPU_MASK_WORDS * 64 {
		return false
	}
	mask: [CPU_MASK_WORDS]u64
	mask[cpu / 64] = 1 << uint(cpu % 64)
	_, err := linux.sched_setaffinity(0, size_of(mask), &mask)
	return err == .NONE
}
