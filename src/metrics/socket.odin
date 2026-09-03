package metrics

import "core:fmt"
import "core:io"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:sys/posix"

/*
What the kernel threw away before this process could read it.

A datagram that overflows a socket's receive queue is dropped by the socket,
which is to say by nobody this program can ask: it never reaches a read, so no
counter on the query path can see it and its absence looks exactly like a client
that did not send. The kernel does count them, per socket, in the last column of
`/proc/net/udp`, and this is the only way to get at that number without changing
how every datagram is received.

Keyed by inode rather than by the bound address, because with `SO_REUSEPORT`
every reader's socket carries the same address and port: matching on those would
add up every reader's drops for each of them. `/proc/self/fd` gives the inode of
a descriptor this process holds, which names one socket and no other.

Nothing here is required for the server to run, and every failure is reported as
"could not say" rather than as a zero. A zero is a real answer - it means
nothing was dropped - and a `/proc` that could not be read must not be published
as one.
*/

/*
The inode of an open descriptor, the name the `/proc/net` tables know it by.

0 when it could not be read, which is what a platform without `/proc` returns
for everything and is treated as "this socket has no drop counter".
*/
socket_inode :: proc(fd: int) -> u64 {
	// "/proc/self/fd/" plus a descriptor number, with room for the NUL that
	// `readlink` needs and `bprintf` does not write.
	path_buf: [64]u8
	path := fmt.bprintf(path_buf[:len(path_buf) - 1], "/proc/self/fd/%d", fd)
	path_buf[len(path)] = 0

	// "socket:[4294967295]" is 19 bytes; anything longer is not the link this
	// is looking for.
	link_buf: [64]u8
	n := posix.readlink(cstring(&path_buf[0]), raw_data(link_buf[:]), len(link_buf))
	// `readlink` does not terminate what it writes and truncates silently, so a
	// full buffer is a link that may have been cut short rather than one read.
	if n <= 0 || int(n) >= len(link_buf) {
		return 0
	}
	link := string(link_buf[:n])

	PREFIX :: "socket:["
	if !strings.has_prefix(link, PREFIX) || !strings.has_suffix(link, "]") {
		return 0
	}
	inode, ok := strconv.parse_u64(link[len(PREFIX):len(link) - 1])
	if !ok {
		return 0
	}
	return inode
}

/*
Fill `drops` with what the kernel dropped on each of `inodes`.

`false` means the answer is unknown - `/proc` unreadable, or a socket whose line
is not in it - and leaves the caller to publish nothing. An inode of 0 is a
socket whose number could not be read, and is enough on its own to make the
whole answer unknown: a total that quietly leaves one reader out would be read
as the whole listener's, and it would be too small.
*/
socket_drops :: proc(inodes: []u64, drops: []u64, allocator := context.temp_allocator) -> bool {
	assert(len(drops) == len(inodes))
	for &d in drops {
		d = 0
	}
	if len(inodes) == 0 {
		return false
	}
	for inode in inodes {
		if inode == 0 {
			return false
		}
	}

	matched := 0
	// IPv4 and IPv6 sockets are listed in separate files, and a listener bound
	// to `::` is in the second. Both are read: a failure to open one is not a
	// failure to open the other, and the readers are all in one of them.
	//
	// Stopping once every reader has been found, because the readers all bind
	// one endpoint and so are all in one of the two files: reading the other
	// would parse every UDP socket on the host a second time, per scrape, for
	// an answer that is already complete.
	for path in ([]string{"/proc/net/udp", "/proc/net/udp6"}) {
		text, ok := read_proc_file(path, allocator)
		if !ok {
			continue
		}
		matched += add_socket_drops(text, inodes, drops)
		if matched == len(inodes) {
			return true
		}
	}
	return matched == len(inodes)
}

/*
Add the drop counts in one `/proc/net/udp` table to the sockets it names.

Each line is a socket, and the fields are positional:

	sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode ref pointer drops

`inode` is the tenth and `drops` is the last. The last rather than the
thirteenth, because that is the one the kernel's format string has always
finished with and it survives a column being added in front of it; the count of
fields is checked so a line from something that is not this table cannot be read
as one that is.

Returns how many of `inodes` it found, so the caller can tell a socket that
reported no drops from one that was not in the file at all.
*/
@(private)
add_socket_drops :: proc(text: string, inodes: []u64, drops: []u64) -> (matched: int) {
	INODE_FIELD :: 9
	MIN_FIELDS :: 13

	lines := text
	for line in strings.split_lines_iterator(&lines) {
		inode: u64
		last: string
		fields := 0
		rest := line
		for field in strings.fields_iterator(&rest) {
			if fields == INODE_FIELD {
				parsed, ok := strconv.parse_u64(field)
				if !ok {
					break
				}
				inode = parsed
			}
			last = field
			fields += 1
		}
		// The header line, and any line this does not recognise.
		if fields < MIN_FIELDS || inode == 0 {
			continue
		}
		for want, i in inodes {
			if want != inode {
				continue
			}
			if n, ok := strconv.parse_u64(last); ok {
				drops[i] = n
				matched += 1
			}
			break
		}
	}
	return
}

/*
Read a `/proc` file whose size the kernel reports as zero.

`os.read_entire_file` sizes its buffer from the file, so it reads nothing at all
from `/proc`. `read_small_file` next door is for the one-line files and refuses
a buffer that filled, which is the right answer for a number and the wrong one
for a table with a line per socket on the machine. This grows instead, and is
called once per scrape.

Bounded, because the length of this table is not this process's to decide: it is
every UDP socket on the host, and a scrape is what pays to read it. The cap is
some twenty-five thousand sockets, past which the answer is "cannot say" - which
withholds the drop counters rather than misreporting them, since the readers'
lines may be anywhere in a file that was cut short.
*/
@(private)
MAX_PROC_FILE :: 4 * 1024 * 1024

@(private)
read_proc_file :: proc(path: string, allocator := context.temp_allocator) -> (text: string, ok: bool) {
	f, err := os.open(path)
	if err != nil {
		return "", false
	}
	defer os.close(f)

	// One page, which holds about twenty sockets' worth of lines; the append
	// below grows it for a machine with more.
	buf := make([dynamic]u8, 0, 4096, allocator)
	chunk: [4096]u8
	for {
		n, read_err := os.read(f, chunk[:])
		if n > 0 {
			append(&buf, ..chunk[:n])
		}
		// The end arrives as `io.EOF` rather than as a zero-length read, the
		// same as it does in `read_small_file`.
		if read_err == io.Error.EOF || n == 0 {
			break
		}
		if read_err != nil {
			return "", false
		}
		if len(buf) > MAX_PROC_FILE {
			return "", false
		}
	}
	if len(buf) == 0 {
		return "", false
	}
	return string(buf[:]), true
}
