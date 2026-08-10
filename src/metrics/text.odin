package metrics

import "core:fmt"
import "core:strings"

/*
The Prometheus text exposition format, written out by hand.

There is no Prometheus client library for Odin, and most of what one would bring
is already here: a client library is a registry of counters, the code that
increments them, and a renderer. This server has the first two of those already
- every number below is a counter the query path keeps anyway, for the
`msg=stats` log line - so what was missing is only the last, and the format is
small enough to be worth writing rather than depending on.

It is also frozen. Version 0.0.4 is what every scraper reads and what
`text/plain; version=0.0.4` names, and it has not changed in a decade: one
sample per line, a `# HELP` and a `# TYPE` before the first sample of a family,
and the samples of a family sharing a name and differing only in their labels.
That is the whole of what is written here.

Nothing in this file touches the query path. It runs on the metrics listener's
own thread, reading counters that were going to be incremented whether anything
scraped them or not.
*/

// What a scraper is told the body is. The version is part of the negotiation,
// not decoration: a scraper reads the format it names and nothing else.
CONTENT_TYPE :: "text/plain; version=0.0.4; charset=utf-8"

Kind :: enum u8 {
	Counter,
	Gauge,
}

Label :: struct {
	name:  string,
	value: string,
}

/*
A sample value, in the three shapes the counters behind them actually have.

A union rather than one procedure per width, so that a family and its samples
read the same at the call site whichever it is. Callers convert explicitly,
which is what stops a `u64` counter arriving as a float and gaining a `.000000`
it never had.
*/
Value :: union {
	u64,
	i64,
	f64,
}

/*
Open a family: its name, what kind of number it carries, and what it means.

Written once per family, before its first sample. A scraper does not need
either line - it will take bare samples - but without them the metric arrives
with no type, so `rate()` over a counter is a guess the query author has to
make, and nothing in a dashboard's autocomplete says what the number is.
*/
family :: proc(b: ^strings.Builder, name: string, kind: Kind, help: string) {
	strings.write_string(b, "# HELP ")
	strings.write_string(b, name)
	strings.write_byte(b, ' ')
	write_help(b, help)
	strings.write_string(b, "\n# TYPE ")
	strings.write_string(b, name)
	strings.write_byte(b, ' ')
	strings.write_string(b, "counter" if kind == .Counter else "gauge")
	strings.write_byte(b, '\n')
}

// One sample of an already-opened family.
sample :: proc(b: ^strings.Builder, name: string, value: Value, labels: ..Label) {
	strings.write_string(b, name)
	if len(labels) > 0 {
		strings.write_byte(b, '{')
		for label, i in labels {
			if i > 0 {
				strings.write_byte(b, ',')
			}
			strings.write_string(b, label.name)
			strings.write_string(b, "=\"")
			write_label_value(b, label.value)
			strings.write_byte(b, '"')
		}
		strings.write_byte(b, '}')
	}
	strings.write_byte(b, ' ')
	write_value(b, value)
	strings.write_byte(b, '\n')
}

// A family with exactly one, unlabelled, sample - which most of them are.
scalar :: proc(b: ^strings.Builder, name: string, kind: Kind, help: string, value: Value) {
	family(b, name, kind, help)
	sample(b, name, value)
}

/*
Escape a label value.

The format gives a label value three escapes and no more - a backslash, a double
quote and a line feed - and every one of them would otherwise end the value
early or end the line, which puts the rest of the exposition in whatever place
the parser recovers into. Only one label here carries anything an operator
wrote, the upstream name, but the escaping belongs to the writer rather than to
each call site that might one day pass something else.

A carriage return has no escape of its own in the format and is written as its
own byte; it cannot end a sample line, which is terminated by a line feed.
*/
@(private)
write_label_value :: proc(b: ^strings.Builder, value: string) {
	for i in 0 ..< len(value) {
		switch c := value[i]; c {
		case '\\', '"':
			strings.write_byte(b, '\\')
			strings.write_byte(b, c)
		case '\n':
			strings.write_string(b, "\\n")
		case:
			strings.write_byte(b, c)
		}
	}
}

// A `# HELP` line ends at the newline, so the two escapes the format gives it
// are the backslash and the line feed. Every help string here is a literal in
// this repository, so this is a guard against a future edit rather than
// against input.
@(private)
write_help :: proc(b: ^strings.Builder, help: string) {
	for i in 0 ..< len(help) {
		switch c := help[i]; c {
		case '\\':
			strings.write_string(b, "\\\\")
		case '\n':
			strings.write_string(b, "\\n")
		case:
			strings.write_byte(b, c)
		}
	}
}

/*
Write the number.

Floats are written in fixed notation rather than the shortest round trip. The
format accepts an exponent, but a value like `1.7e+09` in a metrics file is the
one thing an operator reading it by eye gets wrong, and six decimal places is
finer than anything measured here - CPU time comes off a 100 Hz clock.

A `nil` value cannot arise from the calls in this repository; it is written as 0
rather than left to print as `%!v` inside a line a scraper then rejects along
with everything after it.
*/
@(private)
write_value :: proc(b: ^strings.Builder, value: Value) {
	switch v in value {
	case u64:
		strings.write_u64(b, v)
	case i64:
		strings.write_i64(b, v)
	case f64:
		fmt.sbprintf(b, "%.6f", v)
	case:
		strings.write_byte(b, '0')
	}
}
