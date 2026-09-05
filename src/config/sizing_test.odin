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
The path a limit is read from, which is the one thing here that cannot be
checked by running it: the file that exists is the file this process's own
cgroup owns, and a test cannot put itself in one.

The v2 lines are the two shapes that matter - a container with its own cgroup
namespace, and a systemd unit - and the v1 lines are why the mounted hierarchy
cannot be read directly.
*/
@(test)
test_cgroup_file_finds_this_processes_own_cgroup :: proc(t: ^testing.T) {
	buf: [512]u8

	// A container with its own cgroup namespace: the leaf is the root it sees,
	// and joining "/" would ask for "/sys/fs/cgroup//memory.max".
	path, ok := cgroup_file(buf[:], "0::/\n", V2_MOUNT, "", "memory.max")
	testing.expect(t, ok, "the unified hierarchy should be found")
	testing.expect_value(t, path, "/sys/fs/cgroup/memory.max")

	// Under the systemd unit, where the limit `MemoryMax=` sets lives.
	path, ok = cgroup_file(buf[:], "0::/system.slice/elodin.service\n", V2_MOUNT, "", "memory.max")
	testing.expect(t, ok, "a unit's cgroup should be found")
	testing.expect_value(t, path, "/sys/fs/cgroup/system.slice/elodin.service/memory.max")

	// A hybrid host lists a line per v1 controller and prints the unified one
	// last, so the unified line has to be picked out rather than assumed first.
	hybrid := "8:memory:/user.slice\n4:cpu,cpuacct:/user.slice\n0::/user.slice/app.scope\n"
	path, ok = cgroup_file(buf[:], hybrid, V2_MOUNT, "", "cpu.max")
	testing.expect(t, ok, "the unified line should be found among v1 ones")
	testing.expect_value(t, path, "/sys/fs/cgroup/user.slice/app.scope/cpu.max")

	// v1, where the controller names the hierarchy - and "cpu" is one field of
	// a list rather than the whole of it.
	path, ok = cgroup_file(buf[:], hybrid, V1_CPU_MOUNT, "cpu", "cpu.cfs_quota_us")
	testing.expect(t, ok, "a v1 hierarchy should be found by one of its controllers")
	testing.expect_value(t, path, "/sys/fs/cgroup/cpu/user.slice/cpu.cfs_quota_us")

	path, ok = cgroup_file(buf[:], hybrid, V1_MEMORY_MOUNT, "memory", "memory.limit_in_bytes")
	testing.expect(t, ok, "the v1 memory hierarchy should be found")
	testing.expect_value(t, path, "/sys/fs/cgroup/memory/user.slice/memory.limit_in_bytes")

	// A unit name may contain a colon, and the path is what follows the second
	// one rather than what precedes the last.
	path, ok = cgroup_file(buf[:], "0::/system.slice/dev-disk-by\\x2duuid:0.device\n", V2_MOUNT, "", "cpu.max")
	testing.expect(t, ok, "a colon in the path should not be read as a separator")
	testing.expect_value(t, path, "/sys/fs/cgroup/system.slice/dev-disk-by\\x2duuid:0.device/cpu.max")
}

// Nothing to join a mount point to is no limit, not a path near one.
@(test)
test_cgroup_file_refuses_what_it_cannot_place :: proc(t: ^testing.T) {
	buf: [512]u8

	// A pure v1 host has no unified line at all.
	_, ok := cgroup_file(buf[:], "8:memory:/user.slice\n4:cpu:/user.slice\n", V2_MOUNT, "", "cpu.max")
	testing.expect(t, !ok, "a host with no unified hierarchy should report none")

	// And a v2 host has no v1 controllers, so the fallback must not invent one.
	_, ok = cgroup_file(buf[:], "0::/user.slice\n", V1_CPU_MOUNT, "cpu", "cpu.cfs_quota_us")
	testing.expect(t, !ok, "the unified line should not answer for a v1 controller")

	// "cpuset" is not "cpu", however much of the name it shares.
	_, ok = cgroup_file(buf[:], "4:cpuset,cpuacct:/user.slice\n", V1_CPU_MOUNT, "cpu", "cpu.cfs_quota_us")
	testing.expect(t, !ok, "a controller should match a whole field")

	_, ok = cgroup_file(buf[:], "", V2_MOUNT, "", "cpu.max")
	testing.expect(t, !ok, "an empty /proc/self/cgroup should report nothing")
	_, ok = cgroup_file(buf[:], "0::relative\n", V2_MOUNT, "", "cpu.max")
	testing.expect(t, !ok, "a path that is not absolute cannot be joined to a mount")
	_, ok = cgroup_file(buf[:], "garbage\n", V2_MOUNT, "", "cpu.max")
	testing.expect(t, !ok, "a line that is not an entry should be skipped")
}

/*
A truncated pseudo-file is refused rather than parsed.

"1073" of "10737418240" is a limit off by seven orders of magnitude and parses
as cleanly as the whole of it, so a buffer that filled has to be read as a file
this did not understand.
*/
@(test)
test_read_small_file_refuses_a_truncated_read :: proc(t: ^testing.T) {
	// /proc/self/cmdline is longer than one byte and, unlike /sys, is here on
	// every machine the tests run on.
	tiny: [1]u8
	_, ok := read_small_file("/proc/self/cmdline", tiny[:])
	testing.expect(t, !ok, "a value that did not fit should be refused")

	roomy: [4096]u8
	_, ok = read_small_file("/proc/self/cmdline", roomy[:])
	testing.expect(t, ok, "a value that fits should be read")

	_, ok = read_small_file("/proc/elodin-does-not-exist", roomy[:])
	testing.expect(t, !ok, "a missing file is not a limit")
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
	// The machine here is measured for the UDP reader count, which is derived
	// and says so; what it must not be is reported as though the worker counts
	// had come from it, which `derived_workers` above is what decides.
	testing.expect(t, cfg.server.sizing.derived_udp_readers, "the reader count was left underived")

	// With nothing left to derive, nothing is measured at all: half of 40 is
	// the file's doing, not the hardware's, and a machine nobody consulted must
	// not appear in the line that explains where the numbers came from.
	quiet, qerr := load_string(
		"upstream:\n  servers: [1.1.1.1]\nserver:\n  workers: 40\n  upstream_workers: 20\nlisteners:\n  udp: { enabled: false }\n",
		context.temp_allocator,
	)
	testing.expect(t, qerr == nil, "expected a clean load")
	testing.expect_value(t, quiet.server.sizing.machine, Machine{})

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

/*
A route's pool counts too, which is the whole reason this is a procedure.

`main` builds one group per `upstream.zones` entry, so a configuration with
routes holds several pools rather than one; counting only the top-level servers
would under-report the descriptors a routed configuration wants by exactly the
part that grows with the routing.
*/
@(test)
test_pooled_upstream_connections_counts_every_route :: proc(t: ^testing.T) {
	plain := Upstream_Config {
		max_idle = 8,
		servers  = []Upstream_Spec{{name = "a"}, {name = "b"}},
	}
	testing.expect_value(t, pooled_upstream_connections(plain), 16)

	routed := plain
	routed.zones = []Zone_Route {
		{
			domains = []string{"corp.example."},
			upstream = Upstream_Config{max_idle = 4, servers = []Upstream_Spec{{name = "dc1"}}},
		},
		{
			domains = []string{"home.arpa."},
			upstream = Upstream_Config{max_idle = 2, servers = []Upstream_Spec{{name = "r1"}, {name = "r2"}}},
		},
	}
	testing.expect_value(t, pooled_upstream_connections(routed), 16 + 4 + 4)
}
