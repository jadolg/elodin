package config

import "core:strings"
import "core:testing"

@(private = "file")
GIB :: i64(1024 * 1024 * 1024)
@(private = "file")
MIB :: i64(1024 * 1024)

/*
What may be in flight is sized by memory alone: a query waiting on an upstream
costs no CPU, so two cores carry as many as thirty-two - what binds is what each
can come to hold (`QUERY_MEMORY_BYTES`), against an eighth of memory.
*/
@(test)
test_derive_max_pending_is_sized_by_memory :: proc(t: ^testing.T) {
	// A 1 GiB VPS: 128 MiB over 320 KiB.
	testing.expect_value(t, derive_max_pending(Machine{cpus = 2, memory = GIB}), 409)
	testing.expect_value(t, derive_max_pending(Machine{cpus = 64, memory = GIB}), 409)
	// A small container on a large host.
	testing.expect_value(t, derive_max_pending(Machine{cpus = 16, memory = 256 * MIB}), 102)
	// Small enough that the share buys almost nothing: the floor answers
	// instead, since a resolver that has stopped answering saved nobody memory.
	testing.expect_value(t, derive_max_pending(Machine{cpus = 1, memory = 16 * MIB}), MIN_DERIVED_PENDING)
	// And the ceiling, which is descriptors as much as memory.
	testing.expect_value(t, derive_max_pending(Machine{cpus = 4, memory = 64 * GIB}), MAX_DERIVED_PENDING)
}

/*
A term the machine did not report is left out rather than guessed: an unreadable
`/proc` on a large host should not size it like a Raspberry Pi, so with no memory
figure the answer is the bound the worker pools shipped with.
*/
@(test)
test_derive_max_pending_ignores_what_it_cannot_measure :: proc(t: ^testing.T) {
	testing.expect_value(t, derive_max_pending(Machine{}), DEFAULT_MAX_PENDING)
	testing.expect_value(t, derive_max_pending(Machine{cpus = 4}), DEFAULT_MAX_PENDING)
}

/*
The heavy decode slots take a thirty-second of memory at the whole decode budget
each, which is the share the worker threads were held to: never fewer than two,
never more than the 128 workers there ever were, and 16 where memory is unknown.
*/
@(test)
test_derive_heavy_decodes_is_sized_by_memory :: proc(t: ^testing.T) {
	testing.expect_value(t, derive_heavy_decodes(Machine{memory = GIB}), 4)
	testing.expect_value(t, derive_heavy_decodes(Machine{memory = 8 * GIB}), 32)
	testing.expect_value(t, derive_heavy_decodes(Machine{memory = 256 * MIB}), MIN_DERIVED_HEAVY_DECODES)
	testing.expect_value(t, derive_heavy_decodes(Machine{memory = 1024 * GIB}), MAX_DERIVED_HEAVY_DECODES)
	testing.expect_value(t, derive_heavy_decodes(Machine{cpus = 4}), DEFAULT_HEAVY_DECODES)
}

@(test)
test_derive_chain_walks_reserves_a_quarter :: proc(t: ^testing.T) {
	// Everything but a reserved quarter, which is the whole of the shape: the
	// bound exists to keep queries turning over, not to cap what the resolver
	// validates.
	testing.expect_value(t, derive_chain_walks(128), 96)
	testing.expect_value(t, derive_chain_walks(16), 12)
	// The floor on the reservation binds on a small bound, where a quarter would
	// be one query or none and the resolver would stop answering while it
	// walked.
	testing.expect_value(t, derive_chain_walks(8), 6)
	testing.expect_value(t, derive_chain_walks(4), 2)
	// And a bound too small to reserve from still walks: the bound is on walks
	// at once, so zero would be a resolver that validates nothing.
	testing.expect_value(t, derive_chain_walks(2), 1)
	testing.expect_value(t, derive_chain_walks(1), 1)
}

@(test)
test_chain_walks_are_derived_at_load :: proc(t: ^testing.T) {
	cfg, err := load_string("upstream:\n  servers: [1.1.1.1]\nserver:\n  max_pending: 16\n", context.temp_allocator)
	testing.expect(t, err == nil, "expected a clean load")
	// From the bound on queries in flight, derived at load rather than at
	// start-up, so `--check` and the run that follows it name the same number.
	testing.expect_value(t, cfg.dnssec.max_chain_walks, derive_chain_walks(16))
	// And the connections' own, from theirs.
	testing.expect_value(t, cfg.dnssec.max_connection_walks, derive_chain_walks(cfg.server.max_connections))
	testing.expect(t, cfg.server.sizing.derived_connection_walks, "a derived connection bound was not marked so")
	testing.expect(t, cfg.server.sizing.derived_chain_walks, "a derived bound was not marked so")

	// A number in the file wins, as everywhere else in this file.
	set, serr := load_string(
		"upstream:\n  servers: [1.1.1.1]\nserver:\n  max_pending: 16\ndnssec:\n  max_chain_walks: 3\n",
		context.temp_allocator,
	)
	testing.expect(t, serr == nil, "expected a clean load")
	testing.expect_value(t, set.dnssec.max_chain_walks, 3)
	free_all(context.temp_allocator)
}

@(test)
test_a_negative_chain_walk_bound_is_refused :: proc(t: ^testing.T) {
	// Not read as one more way of asking for the default: the bound is a
	// denial-of-service guard, so a number that cannot be one is a mistake to
	// report rather than to paper over.
	_, err := load_string(
		"upstream:\n  servers: [1.1.1.1]\ndnssec:\n  max_chain_walks: -1\n",
		context.temp_allocator,
	)
	testing.expect(t, err != nil, "a negative chain-walk bound should be refused")
	free_all(context.temp_allocator)
}

/*
The keys #547 retired are accepted for one release, each recorded so it can be
named - a file that was correct before the upgrade still starts - and read as the
integers they always were, so a typo in one is still caught.
*/
@(test)
test_retired_keys_are_accepted_and_recorded :: proc(t: ^testing.T) {
	cfg, err := load_string(
		"upstream:\n  servers: [1.1.1.1]\nserver:\n  workers: 8\n  upstream_workers: 1\n  running_workers: 4\ndnssec:\n  max_connection_walks: 24\n",
		context.temp_allocator,
	)
	testing.expect(t, err == nil, "a file naming the retired keys was refused")
	testing.expect_value(t, cfg.retired, Retired_Keys{.Workers, .Upstream_Workers, .Running_Workers})
	// Not retired: the connections keep a walk bound of their own.
	testing.expect_value(t, cfg.dnssec.max_connection_walks, 24)

	plain, perr := load_string("upstream:\n  servers: [1.1.1.1]\n", context.temp_allocator)
	testing.expect(t, perr == nil, "expected a clean load")
	testing.expect_value(t, plain.retired, Retired_Keys{})

	_, terr := load_string("upstream:\n  servers: [1.1.1.1]\nserver:\n  workers: lots\n", context.temp_allocator)
	testing.expect(t, terr != nil, "a retired key that is not an integer was accepted")

	// Each warning names its own key and the release that refuses it.
	for key in Retired_Key {
		line := retired_warning(key)
		testing.expectf(t, strings.contains(line, RETIRED_KEYS_REFUSED_IN), "%v: %q names no release", key, line)
	}
	testing.expect(t, strings.contains(retired_warning(.Workers), "server.workers"))
	free_all(context.temp_allocator)
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
The machine this test is running on, whatever it is, has to produce usable
sizes. The exact numbers are not the assertion - they are the machine's - but
the bounds are.
*/
@(test)
test_probe_machine_produces_usable_sizes :: proc(t: ^testing.T) {
	m := probe_machine()
	testing.expect(t, m.cpus >= 0, "a negative CPU count would size nothing sensibly")
	testing.expect(t, m.memory >= 0, "a negative memory figure would size nothing sensibly")
	pending := derive_max_pending(m)
	testing.expect(t, pending >= MIN_DERIVED_PENDING && pending <= MAX_DERIVED_PENDING, "max_pending out of its bounds")
	heavy := derive_heavy_decodes(m)
	testing.expect(t, heavy >= MIN_DERIVED_HEAVY_DECODES && heavy <= MAX_DERIVED_HEAVY_DECODES, "heavy decodes out of their bounds")
}

/*
Unset sizes are the derived ones, and recorded as derived: an operator reading
the log needs to know a number came from the machine rather than from a file they
have not found yet. The loop count is derived with UDP off as well, since every
listener runs on the loops.
*/
@(test)
test_unset_sizes_are_derived_at_load :: proc(t: ^testing.T) {
	cfg, err := load_string(
		"upstream:\n  servers: [1.1.1.1]\nlisteners:\n  udp: { enabled: false }\n",
		context.temp_allocator,
	)
	testing.expect(t, err == nil, "expected a clean load")
	testing.expect(t, cfg.server.sizing.derived_max_pending, "max_pending should be marked as derived")
	testing.expect_value(t, cfg.server.max_pending, derive_max_pending(cfg.server.sizing.machine))
	testing.expect_value(t, cfg.server.heavy_decodes, derive_heavy_decodes(cfg.server.sizing.machine))
	testing.expect(t, cfg.server.sizing.derived_udp_readers, "the loop count should be marked as derived")
	testing.expect_value(t, cfg.listeners.udp.readers, derive_udp_readers(cfg.server.sizing.machine))
	free_all(context.temp_allocator)
}

// A number in the file wins, and what is derived from it follows it.
@(test)
test_configured_max_pending_wins :: proc(t: ^testing.T) {
	cfg, err := load_string("upstream:\n  servers: [1.1.1.1]\nserver:\n  max_pending: 40\n", context.temp_allocator)
	testing.expect(t, err == nil, "expected a clean load")
	testing.expect_value(t, cfg.server.max_pending, 40)
	testing.expect(t, !cfg.server.sizing.derived_max_pending, "a configured bound is not a derived one")
	testing.expect_value(t, cfg.dnssec.max_chain_walks, derive_chain_walks(40))

	_, nerr := load_string("upstream:\n  servers: [1.1.1.1]\nserver:\n  max_pending: -1\n", context.temp_allocator)
	testing.expect(t, nerr != nil, "a negative max_pending should be refused")
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

/*
Issue #336: the zone-key cache had a bound the configuration could not reach.

`dnssec.Options.max_cached_zones` existed and nothing passed it, so the only
number in use was the built-in one - on a box whose memory the operator knows
and this server does not.
*/
@(test)
test_the_zone_cache_bound_is_configurable :: proc(t: ^testing.T) {
	cfg, err := load_string("upstream:\n  servers: [1.1.1.1]\n", context.temp_allocator)
	testing.expect(t, err == nil, "expected a clean load")
	// Zero here rather than a number of its own: the validator holds the
	// default, so the two cannot drift apart.
	testing.expect_value(t, cfg.dnssec.max_cached_zones, 0)

	set, serr := load_string(
		"upstream:\n  servers: [1.1.1.1]\ndnssec:\n  max_cached_zones: 512\n",
		context.temp_allocator,
	)
	testing.expect(t, serr == nil, "expected a clean load")
	testing.expect_value(t, set.dnssec.max_cached_zones, 512)

	// Negative is not a cache without a bound, it is a number nobody meant.
	_, nerr := load_string(
		"upstream:\n  servers: [1.1.1.1]\ndnssec:\n  max_cached_zones: -1\n",
		context.temp_allocator,
	)
	testing.expect(t, nerr != nil, "a negative zone-cache bound should be refused")
	free_all(context.temp_allocator)
}

/*
A full connection table is said when it would take more than a quarter of the
memory (#526): the default 512 at the boundary of 256 MB, a raised table on a
machine that cannot hold it, and nothing where the memory is not known.
*/
@(test)
test_connection_memory_warning_at_a_quarter_of_memory :: proc(t: ^testing.T) {
	_, say := connection_memory_warning(512, Machine{memory = 256 * MIB})
	testing.expect(t, !say, "512 connections at a quarter of 256 MB")
	text: string
	text, say = connection_memory_warning(512, Machine{memory = 256 * MIB - 1})
	testing.expect(t, say, "512 connections past a quarter of 256 MB")
	testing.expect_value(t, text, "server.max_connections is 512: with every connection open that is about 64.0 MiB, more than a quarter of the 256.0 MiB this process may use")
	text, say = connection_memory_warning(4096, Machine{memory = 1 * GIB})
	testing.expect(t, say, "4096 connections on 1 GiB")
	testing.expect_value(t, text, "server.max_connections is 4096: with every connection open that is about 512.0 MiB, more than a quarter of the 1.0 GiB this process may use")
	_, say = connection_memory_warning(512, Machine{memory = 1 * GIB})
	testing.expect(t, !say, "the default on 1 GiB")
	_, say = connection_memory_warning(1 << 20, Machine{})
	testing.expect(t, !say, "memory not measured")
	text, say = connection_memory_warning(1 << 62, Machine{memory = 1 * GIB})
	testing.expect(t, say, "a table whose cost does not fit in an i64")
	testing.expect_value(t, text, "server.max_connections is 4611686018427387904: with every connection open that is about 8.0 EiB, more than a quarter of the 1.0 GiB this process may use")
}
