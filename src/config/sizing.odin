package config

import "core:fmt"
import "core:io"
import "core:os"
import "core:strconv"
import "core:strings"
import si "core:sys/info"
import "elodin:dns"

/*
What the server's size is derived from where the file leaves it unset: the
machine it is starting on.

The event loops are sized by the cores, one per usable CPU to eight
(`derive_udp_readers`), since a loop is a thread that is either running or
waiting in `epoll_wait` and one past the core count adds contention rather than
throughput. What is in flight is sized by memory instead: a query that waits on
an upstream parks its fiber and costs nothing on the CPU, so how many may wait
at once is a question of what they can come to hold (`derive_max_pending`), and
how many may hold the most a request can (`derive_heavy_decodes`).

Both only when the file leaves them unset. An operator who names a number gets
that number; nothing here overrides a configured value or second-guesses it.
*/

/*
What one query in flight can come to hold, when checking `max_pending` against
memory.

The stack its fiber touched - measured at 7 KB for a cache hit and 21 KB for a
miss that walks a DNSSEC chain, release build - and its scratch, whose first
block is 16 KiB, rounded up to 64 KiB; and on top of that what its readings may
decode without asking for a heavy slot, `dns.REQUEST_ORDINARY_DECODE`. An
ordinary query holds a small fraction of this. The figure is the ceiling an
attacker steering answers can push every query in flight to, and it is that
ceiling that has to fit.
*/
QUERY_MEMORY_BYTES :: 64 * 1024 + dns.REQUEST_ORDINARY_DECODE

/*
The share of memory the queries in flight may come to.

An eighth: the cache and the blocklists are what an operator sizes elodin's
memory for, and the queries in flight are the third thing, at their worst.
*/
QUERY_MEMORY_SHARE :: 8

/*
The bounds of the derived `max_pending`.

The floor is what keeps a small machine answering while one upstream is slow:
sixty-four queries waiting on a stalled upstream still leave room for others.

The ceiling is descriptors as much as memory. Each query in flight may hold an
upstream socket - under `strategy: race` one per server it races
(`Descriptor_Demand.racers`) - and 4096 of them, racing a dozen servers, with the
default connection table fit inside the `LimitNOFILE=65536` the shipped unit sets.
4096 against a 20 ms upstream is two hundred thousand cache misses a
second, more than eight loops answer.

Where memory could not be measured, `DEFAULT_MAX_PENDING`: a figure small
enough to fit any machine elodin runs on and large enough to ride out a slow
upstream.
*/
MIN_DERIVED_PENDING :: 64
MAX_DERIVED_PENDING :: 4096
DEFAULT_MAX_PENDING :: 1024

/*
The share of memory requests decoding past their ordinary allowance may hold,
at `dns.REQUEST_DECODE_BUDGET` each, and the bounds of the derived figure.

A thirty-second (#493): the heavy slots are what a flood of steered answers
reaches for, so a flood holding all of them holds that share and no more. Never
fewer than two, so a request that honestly needs the whole budget - the longest
chain walk measured - is not refused for want of company; never more than 128.
Where memory could not be measured, 16.
*/
HEAVY_DECODE_SHARE :: 32
MIN_DERIVED_HEAVY_DECODES :: 2
MAX_DERIVED_HEAVY_DECODES :: 128
DEFAULT_HEAVY_DECODES :: 16

/*
Memory charged to each connection `server.max_connections` lets the server hold.

Every TCP, DoT and DoH connection has a fiber of its own. Held open after one
query each, a TCP connection measured ~21 KB resident in a release build - the
stack its fiber touched and its scratch - and a DoT or DoH/2 one ~72 KB, most of
it OpenSSL's session (bench/results/2026-10-26-event-loop.md); this rounds up
for the stack a query touches (#526, #547). The scratch a query uses past that is held until its connection
closes and unmapped when it does.
*/
CONNECTION_MEMORY_BYTES :: 128 * 1024

/*
The share of memory past which a full connection table is worth a warning.

The table is configured rather than derived, so nothing here lowers it; a
quarter of memory held by connections alone is worth an operator hearing about.
The default 512 reaches it on a machine of less than 256 MB.
*/
CONNECTION_MEMORY_SHARE :: 4

/*
What a full connection table may hold, said when it is past
`CONNECTION_MEMORY_SHARE` of the memory this process may use. Silent where the
memory could not be measured.
*/
connection_memory_warning :: proc(max_connections: int, m: Machine, allocator := context.temp_allocator) -> (text: string, say: bool) {
	// Divided rather than multiplied: `max_connections` has no upper bound, and
	// a product that wraps would read as fitting.
	if m.memory <= 0 || i64(max_connections) <= m.memory / (CONNECTION_MEMORY_BYTES * CONNECTION_MEMORY_SHARE) {
		return "", false
	}
	// Held at the largest i64 where the product would wrap; that is still more
	// than a quarter of any memory.
	need := max(i64)
	if i64(max_connections) <= max(i64) / CONNECTION_MEMORY_BYTES {
		need = i64(max_connections) * CONNECTION_MEMORY_BYTES
	}
	return fmt.aprintf(
			"server.max_connections is %d: with every connection open that is about %#.1M, more than a quarter of the %#.1M this process may use",
			max_connections,
			need,
			m.memory,
			allocator = allocator,
		),
		true
}

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
Whether the sizes came from the machine or from the file.

Kept so that startup and `--check` can say where the numbers came from. A
derived number that nobody can see is one an operator cannot argue with.
*/
Sizing :: struct {
	machine:             Machine,
	derived_chain_walks:      bool,
	derived_connection_walks: bool,
	derived_udp_readers:      bool,
	derived_max_pending:      bool,
	// `server.max_connections_per_prefix`, from `max_connections`.
	derived_per_prefix:       bool,
}

/*
The most UDP readers the machine will be taken to want, and the fewest.

Readers are sized by parallelism rather than by load, and a reader is an event
loop (#547): one thread that reads its socket, answers what it read and serves
its share of the connections. It is on a core whenever it has work, so one past
the core count adds contention rather than throughput. Hence one per usable CPU
rather than a multiple of it.

Eight is where the derivation stops. A loop drains on the order of a million
datagrams a second on the hardware this was measured on, so eight is past what a
10 GbE link delivers in query-sized packets. An operator on larger hardware can
name a figure; nothing here refuses one up to `MAX_UDP_READERS`.
*/
MIN_DERIVED_UDP_READERS :: 1
MAX_DERIVED_UDP_READERS :: 8

/*
Readers for a machine.

A machine whose CPUs could not be counted gets one, which is what elodin had
before this setting existed: a loop that has no core to run on buys nothing and
costs a thread and a receive buffer, so guessing narrow is the safe direction.
*/
derive_udp_readers :: proc(m: Machine) -> int {
	if m.cpus <= 0 {
		return MIN_DERIVED_UDP_READERS
	}
	return clamp(m.cpus, MIN_DERIVED_UDP_READERS, MAX_DERIVED_UDP_READERS)
}

/*
`server.max_pending` for a machine: an eighth of its memory over what a query
in flight can come to hold, between the bounds.
*/
derive_max_pending :: proc(m: Machine) -> int {
	if m.memory <= 0 {
		return DEFAULT_MAX_PENDING
	}
	return int(clamp(m.memory / QUERY_MEMORY_SHARE / QUERY_MEMORY_BYTES, MIN_DERIVED_PENDING, MAX_DERIVED_PENDING))
}

// The heavy decode slots for a machine; see `HEAVY_DECODE_SHARE`.
derive_heavy_decodes :: proc(m: Machine) -> int {
	if m.memory <= 0 {
		return DEFAULT_HEAVY_DECODES
	}
	return int(
		clamp(
			m.memory / HEAVY_DECODE_SHARE / dns.REQUEST_DECODE_BUDGET,
			MIN_DERIVED_HEAVY_DECODES,
			MAX_DERIVED_HEAVY_DECODES,
		),
	)
}

/*
Queries in flight kept back from the chain walk.

The chain walk waits on the network once per label of a name the client chose,
so without a bound a flood of fresh names holds every query the server may have
in flight, each for up to thirty round trips, and the resolver stops answering
anything at all (issue #356). What has to be guaranteed is that most of what may
be in flight keeps *turning over* - and that is a *reservation* rather than a
ceiling.

Turning over, not idle, and the difference is worth stating because the wrong
reading oversells this. The reserved queries are free of the *walk*, not free of
work: one may be waiting on its own upstream forward, which takes no slot and is
not bounded here. What the reservation buys is that at most `max_chain_walks` of
them can be inside a chain walk, and a walk is up to `MAX_LOOKUPS_PER_QUERY` round
trips against a forward's one - so the rest come back in a round trip rather than
in a second, and new queries keep being admitted instead of shed. Enough of a
flood will still fill `max_pending` and shed; what it can no longer do is hold
it for thirty round trips apiece, which is the whole of #356.

Stated this way round on purpose. A ceiling of half the bound also caps honest
throughput at half, and the walks past it are answered SERVFAIL: every
cache-missing name that is not in the non-cut memo needs a slot, so a resolver
that is merely busy - a restart with real traffic pointed at it, where nearly
every query is a cold walk - would refuse validated answers that resolved fine
before. Reserving instead leaves the honest load nearly untouched and still
denies an attacker the last slot.

A quarter, and never fewer than two. The reserved queries serve what needs no
walk, which is mostly cache hits but also ordinary forwarding at an upstream
round trip, so the number has to be enough to keep that moving rather than
merely non-zero.

What this does not bound tightly is upstream volume - #356's other cost - since
nearly everything in flight may still be walking. That is the trade the issue
asks for in as many words: starvation traded for upstream volume, which is the
difference between a resolver degraded and one down. An operator who would
rather cap the volume has `dnssec.max_chain_walks` to name a smaller number
with.
*/
RESERVED_HANDLERS_SHARE :: 4
MIN_RESERVED_HANDLERS :: 2

/*
Chain-of-trust walks that may be waiting on an upstream at once, for a bound of
`in_flight` queries: everything but the reservation above. At least one whatever
the arithmetic says, since the bound is on walks at once rather than on walks.
*/
derive_chain_walks :: proc(in_flight: int) -> int {
	return max(in_flight - max(in_flight / RESERVED_HANDLERS_SHARE, MIN_RESERVED_HANDLERS), 1)
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
Rounded up - half a CPU is still a machine that can run one loop's worth of
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
miss is a limit an operator can still name a loop count under.
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
consider itself without naming a `max_pending`.
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

/*
Pooled upstream connections this configuration can hold open at once.

`upstream.max_idle` is a per-server figure - `make_upstream` gives every server
its own pool - so the total is that many for each server named anywhere, and a
zone route is named anywhere: `main` builds one group per `upstream.zones` entry,
each with the route's own `max_idle` and its own servers.

Counted rather than estimated because a configuration with a dozen routes has a
pool that is no longer a rounding error against the connection table. The
only caller is `server.start_listeners`, which hands it to
`descriptors_wanted`, and that is the reason this is a figure rather than a
comment.

`tcp` and `tls` servers do not pool at all: they pipeline every query onto one
connection each (RFC 7766 section 6.2, see upstream/pipeline.odin), so for them
this counts up to `max_idle` where one is what is held. Left as it is because
what the only caller wants is a ceiling on descriptors, and a ceiling that is
generous for two of the four transports is still a ceiling.

**Idle sockets only, which is not every socket this server holds upstream.** A
connection checked out of a pool for a round trip is not in the pool, and one
dialled when the pool is empty was never in it - so in-flight exchanges are
bounded by `server.max_pending` rather than by `max_idle`, and are counted there.
Pipelined and HTTP/2 connections are one per upstream, shared by every loop.
This is a ceiling on the pools and not on upstream sockets: what it names is what
can be held open while nothing is being asked.
*/
pooled_upstream_connections :: proc(cfg: Upstream_Config) -> int {
	total := cfg.max_idle * len(cfg.servers)
	for route in cfg.zones {
		total += route.upstream.max_idle * len(route.upstream.servers)
	}
	return total
}
