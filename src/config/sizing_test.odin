package config

import "core:testing"

@(private = "file")
GIB :: i64(1024 * 1024 * 1024)
@(private = "file")
MIB :: i64(1024 * 1024)

/*
The shape the derivation is meant to have: a household box lands on the floor
rather than on the old 128, a large resolver keeps what it used to get, and
nothing in between overshoots the ceiling.
*/
@(test)
test_derive_workers_scales_with_cpus :: proc(t: ^testing.T) {
	// A two-core home router: 16 workers, about 800 cache misses a second,
	// where the old default gave it 128 and the memory to go with them.
	testing.expect_value(t, derive_workers(Machine{cpus = 2, memory = 8 * GIB}), MIN_DERIVED_WORKERS)
	// The floor holds until four per CPU passes it.
	testing.expect_value(t, derive_workers(Machine{cpus = 4, memory = 8 * GIB}), 16)
	testing.expect_value(t, derive_workers(Machine{cpus = 8, memory = 16 * GIB}), 32)
	// 32 CPUs is where the old default becomes the derived one.
	testing.expect_value(t, derive_workers(Machine{cpus = 32, memory = 64 * GIB}), MAX_DERIVED_WORKERS)
	// And past it the ceiling holds: more workers would be memory spent on
	// throughput no upstream is going to deliver.
	testing.expect_value(t, derive_workers(Machine{cpus = 128, memory = 256 * GIB}), MAX_DERIVED_WORKERS)
}

/*
A term the machine did not report is left out rather than guessed.

An unreadable `/proc` on a large host should not size it like a Raspberry Pi,
so with nothing known at all the answer is the number elodin has always
shipped.
*/
@(test)
test_derive_workers_ignores_what_it_cannot_measure :: proc(t: ^testing.T) {
	testing.expect_value(t, derive_workers(Machine{}), MAX_DERIVED_WORKERS)
	testing.expect_value(t, derive_workers(Machine{cpus = 4}), 16)
	testing.expect_value(t, derive_workers(Machine{memory = 64 * GIB}), MAX_DERIVED_WORKERS)
}

/*
Memory binds where it should and nowhere else.

The interesting case is a small container on a large host: plenty of CPUs in
the mask, a few hundred megabytes to live in, and a thread floor that would
otherwise be a visible fraction of the whole allowance.
*/
@(test)
test_derive_workers_is_capped_by_memory :: proc(t: ^testing.T) {
	// 256 MiB / 32 = 8 MiB of thread budget, or 16 threads at 512 KiB each,
	// which buys 10 handlers and the 5 racers that come with them.
	testing.expect_value(t, derive_workers(Machine{cpus = 16, memory = 256 * MIB}), 10)
	// Small enough that the budget buys nothing: the floor answers instead,
	// because a resolver that has stopped answering has saved nobody memory.
	testing.expect_value(t, derive_workers(Machine{cpus = 16, memory = 16 * MIB}), MIN_MEMORY_WORKERS)
	// Roomy enough that the CPU term is what decides, which is the case on
	// anything an operator would call a server.
	testing.expect_value(t, derive_workers(Machine{cpus = 4, memory = 4 * GIB}), 16)
}

@(test)
test_derive_upstream_workers_is_half :: proc(t: ^testing.T) {
	testing.expect_value(t, derive_upstream_workers(128), 64)
	testing.expect_value(t, derive_upstream_workers(16), 8)
	// Never zero: a race with no racers is a strategy that cannot run.
	testing.expect_value(t, derive_upstream_workers(1), 1)
}

/*
`cpu.max` is the one the CPU mask cannot see: `docker run --cpus 0.5` and
systemd's `CPUQuota=` throttle rather than narrow the mask.
*/
@(test)
test_parse_cpu_max :: proc(t: ^testing.T) {
	quota, ok := parse_cpu_max("50000 100000\n")
	testing.expect(t, ok, "half a CPU should parse")
	// Rounded up: half a CPU still runs a worker's worth of work.
	testing.expect_value(t, quota, 1)

	quota, ok = parse_cpu_max("250000 100000\n")
	testing.expect(t, ok, "two and a half CPUs should parse")
	testing.expect_value(t, quota, 3)

	// "max" is the unlimited case, and leaves the answer to the CPU mask.
	_, ok = parse_cpu_max("max 100000\n")
	testing.expect(t, !ok, "an unlimited quota should not cap anything")

	_, ok = parse_cpu_max("")
	testing.expect(t, !ok, "an empty cpu.max should be ignored")
	_, ok = parse_cpu_max("100000")
	testing.expect(t, !ok, "a quota with no period should be ignored")
	_, ok = parse_cpu_max("plenty 100000")
	testing.expect(t, !ok, "a quota that is not a number should be ignored")
	_, ok = parse_cpu_max("100000 0")
	testing.expect(t, !ok, "a zero period should be ignored rather than divided by")
}

@(test)
test_parse_memory_max :: proc(t: ^testing.T) {
	bytes, ok := parse_memory_max("134217728\n")
	testing.expect(t, ok, "a container limit should parse")
	testing.expect_value(t, bytes, 128 * MIB)

	_, ok = parse_memory_max("max\n")
	testing.expect(t, !ok, "cgroup v2's unlimited should be ignored")

	// cgroup v1 says unlimited with a page-aligned max int64 rather than a
	// word, and eight petabytes of RAM is not a machine anyone is running.
	_, ok = parse_memory_max("9223372036854771712\n")
	testing.expect(t, !ok, "cgroup v1's unlimited sentinel should be ignored")

	_, ok = parse_memory_max("")
	testing.expect(t, !ok, "an empty limit should be ignored")
	_, ok = parse_memory_max("lots")
	testing.expect(t, !ok, "a limit that is not a number should be ignored")
}

/*
The machine this test is running on, whatever it is, has to produce a usable
pair. The exact numbers are not the assertion - they are the machine's - but
the bounds are.
*/
@(test)
test_probe_machine_produces_a_usable_pool :: proc(t: ^testing.T) {
	m := probe_machine()
	testing.expect(t, m.cpus >= 0, "a negative CPU count would size nothing sensibly")
	testing.expect(t, m.memory >= 0, "a negative memory figure would size nothing sensibly")

	workers := derive_workers(m)
	testing.expect(t, workers >= MIN_MEMORY_WORKERS, "the derivation should never leave a pool too narrow to answer")
	testing.expect(t, workers <= MAX_DERIVED_WORKERS, "the derivation should never exceed the ceiling")
	testing.expect(t, derive_upstream_workers(workers) >= 1, "there should always be a racer")
}

/*
An unset worker count is the derived one, and it is recorded as derived: an
operator reading the log needs to know the number came from the machine rather
than from a file they have not found yet.
*/
@(test)
test_unset_workers_are_derived_at_load :: proc(t: ^testing.T) {
	cfg, err := load_string("upstream:\n  servers: [1.1.1.1]\n", context.temp_allocator)
	testing.expect(t, err == nil, "expected a clean load")
	testing.expect(t, cfg.server.sizing.derived_workers, "workers should be marked as derived")
	testing.expect(t, cfg.server.sizing.derived_upstream_workers, "upstream_workers should be marked as derived")
	testing.expect_value(t, cfg.server.workers, derive_workers(cfg.server.sizing.machine))
	testing.expect_value(t, cfg.server.upstream_workers, derive_upstream_workers(cfg.server.workers))
	// The queue bound follows the derived count rather than the old default.
	testing.expect_value(t, cfg.server.max_pending, cfg.server.workers * 8)
	free_all(context.temp_allocator)
}

/*
A number in the file wins, and half of it is still a sensible racer count - so
the two can be set independently without the file having to name both.
*/
@(test)
test_configured_workers_win :: proc(t: ^testing.T) {
	src := "upstream:\n  servers: [1.1.1.1]\nserver:\n  workers: 40\n"
	cfg, err := load_string(src, context.temp_allocator)
	testing.expect(t, err == nil, "expected a clean load")
	testing.expect_value(t, cfg.server.workers, 40)
	testing.expect(t, !cfg.server.sizing.derived_workers, "a configured count is not a derived one")
	testing.expect_value(t, cfg.server.upstream_workers, 20)
	testing.expect(t, cfg.server.sizing.derived_upstream_workers, "the unset half should be derived from the set one")

	both := "upstream:\n  servers: [1.1.1.1]\nserver:\n  workers: 40\n  upstream_workers: 40\n"
	pair, perr := load_string(both, context.temp_allocator)
	testing.expect(t, perr == nil, "expected a clean load")
	testing.expect_value(t, pair.server.workers, 40)
	testing.expect_value(t, pair.server.upstream_workers, 40)
	testing.expect(t, !pair.server.sizing.derived_upstream_workers, "nothing should have been derived")
	free_all(context.temp_allocator)
}

// Zero means "work it out"; below zero means nothing at all.
@(test)
test_negative_worker_counts_are_refused :: proc(t: ^testing.T) {
	src := "upstream:\n  servers: [1.1.1.1]\nserver:\n  workers: -1\n  upstream_workers: -4\n"
	_, err := load_string(src, context.temp_allocator)
	e, has := err.?
	testing.expect(t, has, "a negative worker count should be refused")
	testing.expect_value(t, len(e.messages), 2)
	free_all(context.temp_allocator)
}
