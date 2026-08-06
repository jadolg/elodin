package config

import "core:fmt"
import "core:io"
import "core:os"
import "core:strconv"
import "core:strings"
import si "core:sys/info"

/*
Worker counts derived from the machine elodin is starting on.

`server.workers` and `server.upstream_workers` used to ship as 128 and 64, which
is a resolver sized for five thousand cache misses a second on every box that
installs it. The cost of being wrong is not symmetric: too few workers is
throughput an operator can see and raise, while too many is memory that never
comes back. A worker holds a scratch arena from its first query onward - 256 KiB
here, since the build defines `DEFAULT_TEMP_ALLOCATOR_BACKING_SIZE` - and Odin's
`arena_free_all` keeps and zeroes the first block rather than returning it, so
the pages stay resident for the life of the process. 192 threads is some 50 MB
that a household resolver answering a few queries a second has no use for.

So the numbers are worked out at startup from what the machine actually has,
and only when the file leaves them unset. An operator who names a number gets
that number; nothing here overrides a configured value or second-guesses it.
*/

/*
Handlers per usable CPU.

Workers are sized by expected load rather than by parallelism - a worker spends
its time parked on an upstream round trip, not on a core - so the CPU count is
being read as "how big is this machine" rather than as a limit on useful
threads. Four per CPU with the bounds below puts a two-core home box on 16
workers, or about 800 cache misses per second, and a 32-core resolver on the
128 that used to be everybody's default.
*/
WORKERS_PER_CPU :: 4

/*
The narrowest and widest derived pools.

The floor is not about throughput but about latency under a burst: every query
shares this pool, so a handful of workers all parked on a slow upstream is a
cache hit that takes 60 µs to produce arriving hundreds of milliseconds late.
The ceiling is where the old default sat, and past it the memory is real while
the throughput is theoretical.
*/
MIN_DERIVED_WORKERS :: 16
MAX_DERIVED_WORKERS :: 128

/*
Memory charged to each thread when checking the derivation against RAM.

Measured resident cost is ~0.26 MB per worker (README, "Resource use"), nearly
all of it the scratch arena; this rounds up to cover the stack pages a query
touches and the allocator's own per-thread retention.
*/
WORKER_MEMORY_BYTES :: 512 * 1024

/*
The share of memory the thread floor is allowed to take.

A thirty-second of RAM is generous for something that is neither the cache nor
the blocklists - the two things an operator sizes elodin's memory for - and it
only ever binds on machines small enough that the CPU term alone would still
have overcommitted them. On anything from about 3 GB up it is inert.
*/
WORKER_MEMORY_SHARE :: 32

/*
Where the derivation stops when memory is what binds.

Below this the pool is too narrow to keep answering while a single upstream is
slow, and a resolver that stops answering has not saved anybody any memory.
*/
MIN_MEMORY_WORKERS :: 4

/*
What the machine has, as far as this process can see it.

Zero means "could not tell", and the derivation then leaves that term out
rather than guessing: an unreadable `/proc` is not a reason to size a resolver
for a Raspberry Pi.
*/
Machine :: struct {
	// CPUs this process may run on, not CPUs the box has.
	cpus:   int,
	// Bytes it may use, likewise: a cgroup limit counts for more than the
	// host's RAM when there is one.
	memory: i64,
}

/*
Whether the worker counts came from the machine or from the file.

Kept so that startup and `--check` can say where the numbers came from. A
derived number that nobody can see is one an operator cannot argue with.
*/
Sizing :: struct {
	machine:                  Machine,
	derived_workers:          bool,
	derived_upstream_workers: bool,
}

// Handlers for a machine, ignoring any term the machine did not report.
derive_workers :: proc(m: Machine) -> int {
	workers := MAX_DERIVED_WORKERS
	if m.cpus > 0 {
		workers = clamp(m.cpus * WORKERS_PER_CPU, MIN_DERIVED_WORKERS, MAX_DERIVED_WORKERS)
	}
	if m.memory > 0 {
		threads := (m.memory / WORKER_MEMORY_SHARE) / WORKER_MEMORY_BYTES
		// The handlers bring `workers / 2` racers with them, so a budget of
		// threads buys two thirds of itself in handlers.
		affordable := int(min(threads * 2 / 3, i64(MAX_DERIVED_WORKERS)))
		workers = min(workers, max(affordable, MIN_MEMORY_WORKERS))
	}
	return workers
}

/*
Racers to go with a given handler count.

Half, which is the ratio the old pair of defaults had. They are a separate pool
because a race job is submitted by a handler and waited on by it, so the two
sharing one pool could deadlock; the count only has to be enough that a burst of
races does not queue behind itself.
*/
derive_upstream_workers :: proc(workers: int) -> int {
	return max(workers / 2, 1)
}

// What this process can see of the machine, at the moment it asks.
probe_machine :: proc() -> (m: Machine) {
	/*
	Read once and pass it down: both limits live in the hierarchies this file
	names, and a process that moved cgroups between the two reads would be
	sized against two different machines.

	4 KiB because procfs hands out a page at a time and a hybrid host lists one
	line per v1 controller plus the unified one - which procfs prints last, so a
	buffer that cuts the file short is a buffer that loses the line cgroup v2
	detection depends on.
	*/
	cgroup_buf: [4096]u8
	cgroups, has_cgroups := read_small_file("/proc/self/cgroup", cgroup_buf[:])

	// Affinity rather than the CPU count: a process pinned to two cores of a
	// sixty-four core box is running on a two-core machine.
	m.cpus = os.get_processor_core_count()
	if has_cgroups {
		if quota, ok := cgroup_cpus(cgroups); ok && (m.cpus == 0 || quota < m.cpus) {
			m.cpus = quota
		}
	}
	if total, _, _, _, ok := si.ram_stats(); ok {
		m.memory = total
	}
	if has_cgroups {
		if limit, ok := cgroup_memory(cgroups); ok && (m.memory == 0 || limit < m.memory) {
			m.memory = limit
		}
	}
	return
}

// Where the cgroup hierarchies are mounted, which is the same everywhere a
// distribution has not gone out of its way. Under v1 each controller has a
// hierarchy of its own; under v2 there is one for all of them.
@(private)
V2_MOUNT :: "/sys/fs/cgroup"
@(private)
V1_CPU_MOUNT :: "/sys/fs/cgroup/cpu"
@(private)
V1_MEMORY_MOUNT :: "/sys/fs/cgroup/memory"

/*
The CPU allowance of the cgroup this process is in, in whole CPUs.

Worth reading because affinity does not see it: `docker run --cpus 0.5` and
systemd's `CPUQuota=` both leave every CPU in the mask and throttle instead, so
without this a container limited to half a core would size itself for the host.
Rounded up - half a CPU is still a machine that can run one worker's worth of
work - and read from the process's own cgroup path rather than the hierarchy
root, for the reason `cgroup_file` gives.
*/
@(private)
cgroup_cpus :: proc(cgroups: string) -> (cpus: int, ok: bool) {
	value_buf: [256]u8
	path_buf: [512]u8
	// cgroup v2: "$MAX $PERIOD", where $MAX is "max" when there is no limit.
	if path, found := cgroup_file(path_buf[:], cgroups, V2_MOUNT, "", "cpu.max"); found {
		if text, read_ok := read_small_file(path, value_buf[:]); read_ok {
			return parse_cpu_max(text)
		}
	}
	// cgroup v1 keeps the two halves in separate files, under the hierarchy
	// mounted for the `cpu` controller, and a quota of -1 is the unlimited case.
	quota_path_buf: [512]u8
	period_path_buf: [512]u8
	quota_path := cgroup_file(quota_path_buf[:], cgroups, V1_CPU_MOUNT, "cpu", "cpu.cfs_quota_us") or_return
	period_path := cgroup_file(period_path_buf[:], cgroups, V1_CPU_MOUNT, "cpu", "cpu.cfs_period_us") or_return
	quota_buf: [64]u8
	period_buf: [64]u8
	quota_text := read_small_file(quota_path, quota_buf[:]) or_return
	period_text := read_small_file(period_path, period_buf[:]) or_return
	quota := strconv.parse_i64(strings.trim_space(quota_text)) or_return
	period := strconv.parse_i64(strings.trim_space(period_text)) or_return
	return cpus_from_quota(quota, period)
}

/*
Where a cgroup interface file for *this* process lives.

The controller files are not on the root cgroup, so `/sys/fs/cgroup/memory.max`
exists only when something has put this process somewhere - which is exactly
when it has a limit. `/proc/self/cgroup` names that somewhere, so one path
covers a container, a systemd unit and a hand-made cgroup alike, and it is why
`MemoryMax=` in the unit and `docker run -m` end up meaning the same thing here.
Reading the mounted hierarchy directly would not: under cgroup v1 a container
gets its own cgroup remapped to the mount root, but a plain systemd host does
not, so `/sys/fs/cgroup/memory/memory.limit_in_bytes` there is the root group's
- unlimited, whatever the unit says.

Only this process's own cgroup, not the ancestors it inherits limits from. Every
case above puts the limit on the leaf, and reading the whole chain to catch a
hand-built hierarchy is more machinery than a default is worth: what it would
miss is a limit an operator can still name a worker count under.
*/
@(private)
cgroup_file :: proc(buf: []u8, cgroups, mount, controller, leaf: string) -> (path: string, ok: bool) {
	rel := cgroup_rel_path(cgroups, controller) or_return
	// The root cgroup is "/", and joining that would ask for
	// "/sys/fs/cgroup//memory.max".
	if rel == "/" {
		rel = ""
	}
	return fmt.bprintf(buf, "%s%s/%s", mount, rel, leaf), true
}

/*
This process's path within one cgroup hierarchy, from the text of
`/proc/self/cgroup`.

Every line is "$ID:$CONTROLLERS:$PATH". The unified hierarchy that cgroup v2
uses is the line with no controllers at all - "0::/" inside a container with its
own cgroup namespace, "0::/system.slice/elodin.service" under the systemd unit -
so an empty `controller` asks for that one. A v1 hierarchy is named by any of the
controllers mounted together on it, which is why "cpu" has to match one field of
"cpu,cpuacct" rather than the whole of it.

The path may itself contain a colon, since a systemd unit name may, so only the
first two are separators.
*/
@(private)
cgroup_rel_path :: proc(cgroups: string, controller: string) -> (rel: string, ok: bool) {
	text := cgroups
	for line in strings.split_lines_iterator(&text) {
		entry := strings.trim_space(line)
		id_end := strings.index_byte(entry, ':')
		if id_end < 0 {
			continue
		}
		rest := entry[id_end + 1:]
		names_end := strings.index_byte(rest, ':')
		if names_end < 0 {
			continue
		}
		if !cgroup_hierarchy_has(rest[:names_end], controller) {
			continue
		}
		path := rest[names_end + 1:]
		// Anything that is not an absolute path is not a cgroup this can join
		// to a mount point.
		if !strings.has_prefix(path, "/") {
			continue
		}
		return path, true
	}
	return "", false
}

// Whether a hierarchy's comma-separated controller list is the one asked for.
// An empty `controller` means the v2 unified hierarchy, which carries no names.
@(private)
cgroup_hierarchy_has :: proc(names: string, controller: string) -> bool {
	if controller == "" {
		return names == ""
	}
	rest := names
	for name in strings.split_iterator(&rest, ",") {
		if name == controller {
			return true
		}
	}
	return false
}

// "max 100000" leaves the CPU count to affinity; "50000 100000" is half a CPU.
@(private)
parse_cpu_max :: proc(text: string) -> (cpus: int, ok: bool) {
	rest := text
	quota_field := strings.fields_iterator(&rest) or_return
	if quota_field == "max" {
		return 0, false
	}
	period_field := strings.fields_iterator(&rest) or_return
	quota := strconv.parse_i64(quota_field) or_return
	period := strconv.parse_i64(period_field) or_return
	return cpus_from_quota(quota, period)
}

@(private)
cpus_from_quota :: proc(quota, period: i64) -> (cpus: int, ok: bool) {
	if quota <= 0 || period <= 0 {
		return 0, false
	}
	// Rounded up: a fraction of a CPU is still a CPU's worth of machine as far
	// as the smallest pool worth running is concerned.
	return int((quota + period - 1) / period), true
}

/*
The memory allowance of the cgroup this process is in.

Same reasoning as the CPU quota, and it matters more: `/proc/meminfo` inside a
container reports the host's RAM, so a 128 MB container would otherwise size
itself against tens of gigabytes it cannot touch. `MemoryMax=` in the systemd
unit lands here too, which makes it a way to say how large elodin should
consider itself without naming a worker count.
*/
@(private)
cgroup_memory :: proc(cgroups: string) -> (bytes: i64, ok: bool) {
	buf: [64]u8
	path_buf: [512]u8
	if path, found := cgroup_file(path_buf[:], cgroups, V2_MOUNT, "", "memory.max"); found {
		if text, read_ok := read_small_file(path, buf[:]); read_ok {
			return parse_memory_max(text)
		}
	}
	v1_path := cgroup_file(path_buf[:], cgroups, V1_MEMORY_MOUNT, "memory", "memory.limit_in_bytes") or_return
	text := read_small_file(v1_path, buf[:]) or_return
	return parse_memory_max(text)
}

/*
"max" under cgroup v2, and under v1 a number near the top of the int64 range
that means the same thing. Anything above what a machine could hold is read as
no limit rather than as an enormous one.
*/
@(private)
parse_memory_max :: proc(text: string) -> (bytes: i64, ok: bool) {
	trimmed := strings.trim_space(text)
	if trimmed == "" || trimmed == "max" {
		return 0, false
	}
	value := strconv.parse_i64(trimmed) or_return
	// 2^53 bytes is eight petabytes; the v1 sentinel is a page-aligned max
	// int64 and lands well above it.
	if value <= 0 || value > 1 << 53 {
		return 0, false
	}
	return value, true
}

/*
Read a small pseudo-file into a caller-supplied buffer.

`/sys` and `/proc` files report a size of zero, so the usual read-the-whole-file
path allocates nothing and reads nothing. Everything read here is a line or two,
so a stack buffer covers it and the config loader stays free of allocations it
would have to own.

Read to the end rather than trusting one `read`, and refuse a buffer that filled
completely: half of "10737418240" is "1073", which parses as cleanly as the whole
of it and would be a limit off by seven orders of magnitude. Nothing read here is
long enough for that to bind, so a truncation means something is not the file
this expected, and no limit is a better answer than a wrong one.
*/
@(private)
read_small_file :: proc(path: string, buf: []u8) -> (text: string, ok: bool) {
	f, err := os.open(path)
	if err != nil {
		return "", false
	}
	defer os.close(f)
	n := 0
	for n < len(buf) {
		got, read_err := os.read(f, buf[n:])
		n += got
		// The end of the file arrives as `io.EOF` rather than a zero-length
		// read, so it has to be named: treating every error as a failure would
		// throw away the bytes that were read, and treating every error as the
		// end would accept a file that stopped halfway through a number.
		if read_err == io.Error.EOF {
			break
		}
		if read_err != nil {
			return "", false
		}
		if got == 0 {
			break
		}
	}
	if n <= 0 || n == len(buf) {
		return "", false
	}
	return string(buf[:n]), true
}
