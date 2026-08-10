package metrics

import "core:strings"
import "core:testing"

@(test)
test_scalar_writes_help_type_and_sample :: proc(t: ^testing.T) {
	b := strings.builder_make(context.temp_allocator)
	scalar(&b, "elodin_queries_total", .Counter, "Queries accepted from clients.", u64(42))

	want := `# HELP elodin_queries_total Queries accepted from clients.
# TYPE elodin_queries_total counter
elodin_queries_total 42
`
	testing.expect_value(t, strings.to_string(b), want)
}

/*
A family is opened once and its samples differ only in their labels.

A `# TYPE` repeated between the samples of one family is a duplicate the scraper
rejects, so the split between `family` and `sample` is not a convenience.
*/
@(test)
test_family_is_opened_once_for_every_sample :: proc(t: ^testing.T) {
	b := strings.builder_make(context.temp_allocator)
	family(&b, "elodin_answers_total", .Counter, "Queries by how they were answered.")
	sample(&b, "elodin_answers_total", u64(3), Label{"outcome", "forwarded"})
	sample(&b, "elodin_answers_total", u64(1), Label{"outcome", "blocked"})

	want := `# HELP elodin_answers_total Queries by how they were answered.
# TYPE elodin_answers_total counter
elodin_answers_total{outcome="forwarded"} 3
elodin_answers_total{outcome="blocked"} 1
`
	testing.expect_value(t, strings.to_string(b), want)
}

@(test)
test_several_labels_are_comma_separated :: proc(t: ^testing.T) {
	b := strings.builder_make(context.temp_allocator)
	sample(&b, "elodin_thing", i64(7), Label{"a", "one"}, Label{"b", "two"})
	testing.expect_value(t, strings.to_string(b), "elodin_thing{a=\"one\",b=\"two\"} 7\n")
}

@(test)
test_gauge_is_typed_as_a_gauge :: proc(t: ^testing.T) {
	b := strings.builder_make(context.temp_allocator)
	scalar(&b, "elodin_cache_entries", .Gauge, "Answers held in the cache.", i64(0))
	testing.expect(
		t,
		strings.contains(strings.to_string(b), "# TYPE elodin_cache_entries gauge"),
		"a gauge was not typed as one",
	)
}

/*
The one label whose bytes come from outside this source is the upstream name,
which an operator writes in the configuration file.

Unescaped, a quote in it closes the label value and the rest of the line becomes
whatever the parser makes of it - and a newline ends the sample early, which
puts the remainder of the name where a metric name is expected. Both are refused
by a scraper, and what it refuses is not the one line but everything after it in
the response.
*/
@(test)
test_label_values_cannot_break_out_of_the_line :: proc(t: ^testing.T) {
	b := strings.builder_make(context.temp_allocator)
	sample(&b, "elodin_upstream_up", u64(1), Label{"upstream", "a\"b\\c\nd"})
	testing.expect_value(t, strings.to_string(b), `elodin_upstream_up{upstream="a\"b\\c\nd"} 1` + "\n")
}

// A `# HELP` line ends at the newline, so a newline inside the text would leave
// the rest of it on a line of its own where a sample is expected.
@(test)
test_help_text_cannot_break_out_of_the_line :: proc(t: ^testing.T) {
	b := strings.builder_make(context.temp_allocator)
	family(&b, "elodin_thing", .Gauge, "first\nsecond\\third")
	testing.expect(
		t,
		strings.contains(strings.to_string(b), `# HELP elodin_thing first\nsecond\\third`+"\n"),
		"a newline in the help text was not escaped",
	)
}

/*
Floats are written in full rather than in the shortest form that round trips.

`1.7e+09` is valid in the format and is the thing an operator reading a scrape
by eye gets wrong; the process start time is exactly that magnitude.
*/
@(test)
test_floats_are_written_without_an_exponent :: proc(t: ^testing.T) {
	b := strings.builder_make(context.temp_allocator)
	sample(&b, "process_start_time_seconds", 1786361798.5)
	testing.expect_value(t, strings.to_string(b), "process_start_time_seconds 1786361798.500000\n")
}

/*
`/proc` is where every number under `process_` comes from, and this test runs on
the same kind of host the server does.

Asserted loosely on purpose: the exact figures belong to whatever ran the test.
What is worth pinning is that the parse landed on the right fields - a resident
size read out of the field beside it would be a page count rather than bytes,
and would still look like a plausible number.
*/
@(test)
test_process_stats_are_read_from_proc :: proc(t: ^testing.T) {
	p := process_stats()
	if !testing.expect(t, p.ok, "/proc/self/stat could not be read on this host") {
		return
	}
	testing.expect(t, p.threads >= 1, "a running process has at least one thread")
	testing.expect(t, p.cpu_seconds >= 0, "CPU time cannot be negative")
	// A test binary holds a few hundred kilobytes at the very least; a figure
	// under that means pages were reported as bytes.
	testing.expectf(
		t,
		p.resident_bytes > 256 * 1024,
		"resident memory reported as %d bytes, which is too small to be bytes",
		p.resident_bytes,
	)
	testing.expect(t, p.virtual_bytes >= p.resident_bytes, "the virtual size cannot be under the resident size")
	testing.expect(t, p.open_fds >= 1, "the test binary has at least one descriptor open")
	testing.expect(t, p.max_fds >= p.open_fds, "more descriptors are open than the limit allows")
}

// The `stat` line's second field is the executable name, in parentheses, and it
// may contain spaces and parentheses of its own - so the fields after it are
// found from the last `)` rather than by counting from the left.
@(test)
test_stat_fields_are_found_after_a_hostile_comm :: proc(t: ^testing.T) {
	line := "1234 (od in) (weird) S 1 1234 1234 0 -1 4194304 100 0 0 0 11 22 0 0 20 0 7 0 999 1048576 512"
	close_paren := strings.last_index_byte(line, ')')
	fields: [STAT_FIELDS]string
	testing.expect_value(t, split_fields(line[close_paren + 1:], fields[:]), STAT_FIELDS)

	testing.expect_value(t, fields[STAT_UTIME - STAT_FIRST], "11")
	testing.expect_value(t, fields[STAT_STIME - STAT_FIRST], "22")
	testing.expect_value(t, fields[STAT_NUM_THREADS - STAT_FIRST], "7")
	testing.expect_value(t, fields[STAT_VSIZE - STAT_FIRST], "1048576")
	testing.expect_value(t, fields[STAT_RSS - STAT_FIRST], "512")
}
