package metrics

import "core:io"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:sys/posix"

/*
What the kernel will say about this process, gathered at scrape time.

The names these end up under - `process_cpu_seconds_total`,
`process_resident_memory_bytes` and the rest - are the ones every Prometheus
client library exports, deliberately: a dashboard or an alert written against a
Go or a Python service works against this one without being told it is looking
at something else. That convention is the "already pre-made" part of process
metrics; there is nothing else about them worth inventing.

All of it comes from `/proc`, which is read only when something scrapes. A host
without `/proc` - or one where it is not readable after the privilege drop -
leaves `ok` false, and the caller omits the process family rather than
publishing zeros that would read as a process using no CPU and no memory.
*/
Process :: struct {
	ok:             bool,
	cpu_seconds:    f64,
	resident_bytes: i64,
	virtual_bytes:  i64,
	threads:        i64,
	// -1 when `/proc/self/fd` could not be read, which is not the same as none
	// being open. The caller leaves the sample out rather than publishing -1.
	open_fds:       i64,
	max_fds:        i64,
}

/*
Fields of `/proc/self/stat` this reads, counted as `proc(5)` numbers them.

Written out because the file is a single line of unnamed numbers, and an index
off by one there is a plausible-looking value rather than an error: field 23 is
a byte count and field 24 is a page count of the same process, so reading one
for the other is wrong by a factor of the page size and by nothing else.
*/
@(private)
STAT_UTIME :: 14
@(private)
STAT_STIME :: 15
@(private)
STAT_NUM_THREADS :: 20
@(private)
STAT_VSIZE :: 23
@(private)
STAT_RSS :: 24

// Fields 1 and 2 - the pid and the executable name - are consumed separately,
// so the slice below starts at field 3 and has to reach the last field wanted.
@(private)
STAT_FIRST :: 3
@(private)
STAT_FIELDS :: STAT_RSS - STAT_FIRST + 1

process_stats :: proc() -> (p: Process) {
	p.open_fds = open_fd_count()
	if limit := posix.sysconf(._OPEN_MAX); limit > 0 {
		p.max_fds = i64(limit)
	}

	// One line, of about thirty small numbers.
	buf: [1024]u8
	text, read_ok := read_small_file("/proc/self/stat", buf[:])
	if !read_ok {
		return
	}

	/*
	The second field is the executable name in parentheses, and it is neither
	escaped nor length-limited in a way that helps: it can contain spaces and
	parentheses of its own, so splitting the line on spaces from the left puts
	every later field at an offset that depends on what the binary was called.
	The last `)` in the line is the end of that field and nothing else, because
	everything after it is numbers and single letters.
	*/
	close_paren := strings.last_index_byte(text, ')')
	if close_paren < 0 || close_paren + 1 >= len(text) {
		return
	}

	fields: [STAT_FIELDS]string
	if split_fields(text[close_paren + 1:], fields[:]) < STAT_FIELDS {
		return
	}

	utime := stat_u64(fields[:], STAT_UTIME) or_else 0
	stime := stat_u64(fields[:], STAT_STIME) or_else 0
	threads := stat_u64(fields[:], STAT_NUM_THREADS) or_else 0
	vsize := stat_u64(fields[:], STAT_VSIZE) or_else 0
	rss_pages := stat_u64(fields[:], STAT_RSS) or_else 0

	// Both times are in clock ticks, which is a build-time constant of the
	// kernel and 100 on every Linux this runs on - but reading it is one call
	// at scrape time against a number that would be silently wrong if it ever
	// were not.
	ticks := posix.sysconf(._CLK_TCK)
	if ticks <= 0 {
		ticks = 100
	}
	page_size := posix.sysconf(._PAGESIZE)
	if page_size <= 0 {
		page_size = 4096
	}

	p.cpu_seconds = f64(utime + stime) / f64(ticks)
	p.threads = i64(threads)
	p.virtual_bytes = i64(vsize)
	p.resident_bytes = i64(rss_pages) * i64(page_size)
	p.ok = true
	return
}

// `n` is a field number as `proc(5)` counts them; the slice starts at field 3.
@(private)
stat_u64 :: proc(fields: []string, n: int) -> (value: u64, ok: bool) {
	return strconv.parse_u64_of_base(fields[n - STAT_FIRST], 10)
}

/*
Split on spaces into a caller-supplied slice, stopping when it is full.

`strings.fields` would do this and allocate to do it. Everything here is read
under a scrape that must not be able to disturb the process it is measuring, so
the whole of this file works out of stack buffers and takes nothing from an
allocator a query might be waiting on.
*/
@(private)
split_fields :: proc(text: string, out: []string) -> (count: int) {
	i := 0
	for i < len(text) && count < len(out) {
		for i < len(text) && text[i] == ' ' {
			i += 1
		}
		start := i
		for i < len(text) && text[i] != ' ' {
			i += 1
		}
		if i == start {
			break
		}
		out[count] = text[start:i]
		count += 1
	}
	return
}

/*
How many descriptors this process has open.

Worth having next to `elodin_connections_active`: the connection limit counts
threads this server started, and a descriptor leak - or a limit set below what
`server.max_connections` implies - shows up here first, as a count climbing
towards `process_max_fds` while the connection count sits still.

Counted through `readdir` rather than through `os.read_directory`, which clones
a `File_Info` per entry. `.` and `..` are not descriptors; the one `opendir`
itself holds is counted, which is what every other Prometheus client does for
this metric and is off by exactly one for the duration of the scrape.
*/
@(private)
open_fd_count :: proc() -> i64 {
	dir := posix.opendir("/proc/self/fd")
	if dir == nil {
		return -1
	}
	defer posix.closedir(dir)

	count: i64
	for {
		entry := posix.readdir(dir)
		if entry == nil {
			break
		}
		// Compared byte by byte rather than turned into a string: `d_name` is a
		// C array of an implementation-defined character type, and the two
		// names being skipped are three bytes between them.
		name := entry.d_name
		if name[0] == '.' && (name[1] == 0 || (name[1] == '.' && name[2] == 0)) {
			continue
		}
		count += 1
	}
	return count
}

/*
Read a small pseudo-file into a caller-supplied buffer.

The same shape, and for the same reason, as `read_small_file` in
`config/sizing.odin`: `/proc` reports a size of zero, so the read-the-whole-file
path allocates nothing and reads nothing, and a buffer that filled completely
means the file was cut short - here that would be a stat line missing its tail,
which is the half that holds the memory figures.

Kept here rather than shared with the config loader so that this package depends
on nothing: it is read by the one thread that must never be waiting on anything
a query holds.
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
