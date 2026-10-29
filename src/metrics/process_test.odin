package metrics

import "core:c/libc"
import "core:sys/posix"
import "core:testing"

/*
Telling `.` and `..` apart reads a directory entry no further than its name.

`readdir` hands out records only `d_reclen` long, packed in one buffer, so the
last record can end a few bytes past the start of `d_name` - short of the 256
bytes the struct declares. Each record here is allocated exactly that short, the
way the last one in glibc's buffer sits: a copy of the whole array reads past
the allocation, which AddressSanitizer reports (a scrape with ~1,500 descriptors
open killed an ASan server this way in the soak of PR #549). Without ASan the
answers are what is checked.
*/
@(test)
test_a_dot_entry_is_read_no_further_than_its_name :: proc(t: ^testing.T) {
	Case :: struct {
		name: string,
		dots: bool,
	}
	for c in ([]Case{{".", true}, {"..", true}, {"a", false}, {".a", false}, {"..a", false}}) {
		// The name and its terminator, and not a byte more.
		size := int(offset_of(posix.dirent, d_name)) + len(c.name) + 1
		// malloc, as glibc's buffer is: Odin's allocators round up for alignment,
		// which would leave room past the record for a long read to land in.
		p := libc.malloc(uint(size))
		if !testing.expect(t, p != nil, "no memory") {
			return
		}
		record := ([^]u8)(p)[:size]
		copy(record[offset_of(posix.dirent, d_name):], c.name)
		record[size - 1] = 0
		got := is_dot_entry((^posix.dirent)(p))
		testing.expectf(t, got == c.dots, "%q read as a dot entry: %v, want %v", c.name, got, c.dots)
		libc.free(p)
	}
}
