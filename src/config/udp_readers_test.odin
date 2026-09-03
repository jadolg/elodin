package config

import "core:strings"
import "core:testing"

/*
One reader per usable CPU, between one and the ceiling.

The shape it is meant to have: the four-core VM the bystander loss was measured
on gets four readers, a home box gets what its two cores can drain, and a large
resolver stops at the ceiling rather than spending a thread and a receive buffer
on every core it has.
*/
@(test)
test_derive_udp_readers_scales_with_cpus :: proc(t: ^testing.T) {
	testing.expect_value(t, derive_udp_readers(Machine{cpus = 1, memory = 2 * 1024 * 1024 * 1024}), 1)
	testing.expect_value(t, derive_udp_readers(Machine{cpus = 2}), 2)
	testing.expect_value(t, derive_udp_readers(Machine{cpus = 4}), 4)
	testing.expect_value(t, derive_udp_readers(Machine{cpus = 8}), MAX_DERIVED_UDP_READERS)
	testing.expect_value(t, derive_udp_readers(Machine{cpus = 64}), MAX_DERIVED_UDP_READERS)
}

/*
A machine that could not be counted gets one reader, not a guess.

The opposite of `derive_workers`, which answers its ceiling to the same unknown,
and the asymmetry is the point: a worker that turns out to be unnecessary is
memory, while a reader with no core to run on is a thread contending for the
core the reader beside it is using.
*/
@(test)
test_derive_udp_readers_does_not_guess :: proc(t: ^testing.T) {
	testing.expect_value(t, derive_udp_readers(Machine{}), MIN_DERIVED_UDP_READERS)
	testing.expect_value(t, derive_udp_readers(Machine{memory = 64 * 1024 * 1024 * 1024}), MIN_DERIVED_UDP_READERS)
}

// A figure in the file is the operator's, and is neither derived nor reported
// as though the machine had chosen it.
@(test)
test_configured_udp_readers_are_not_derived :: proc(t: ^testing.T) {
	src := "upstream:\n  servers: [1.1.1.1]\nlisteners:\n  udp:\n    readers: 3\n"
	cfg, err := load_string(src, context.temp_allocator)
	testing.expect(t, err == nil, "expected a clean load")
	testing.expect_value(t, cfg.listeners.udp.readers, 3)
	testing.expect(t, !cfg.server.sizing.derived_udp_readers, "a configured count is not a derived one")
	free_all(context.temp_allocator)
}

// Unset is what every shipped configuration has, so the derivation is what
// almost every installation runs.
@(test)
test_unset_udp_readers_are_derived :: proc(t: ^testing.T) {
	cfg, err := load_string("upstream:\n  servers: [1.1.1.1]\n", context.temp_allocator)
	testing.expect(t, err == nil, "expected a clean load")
	testing.expect(t, cfg.server.sizing.derived_udp_readers, "an unset reader count should be derived")
	testing.expect(
		t,
		cfg.listeners.udp.readers >= MIN_DERIVED_UDP_READERS &&
		cfg.listeners.udp.readers <= MAX_DERIVED_UDP_READERS,
		"the derived reader count is outside its own bounds",
	)
	// The listener that is off has no readers to derive, and no reader count of
	// its own is meaningful for it either.
	off, oerr := load_string(
		"upstream:\n  servers: [1.1.1.1]\nlisteners:\n  udp: { enabled: false }\n",
		context.temp_allocator,
	)
	testing.expect(t, oerr == nil, "expected a clean load")
	testing.expect_value(t, off.listeners.udp.readers, 0)
	testing.expect(t, !off.server.sizing.derived_udp_readers, "a listener that is off derived a reader count")
	free_all(context.temp_allocator)
}

/*
A number this server will not honour fails the check rather than being clamped.

The same reasoning as `server.max_udp_response`: the figure decides how much
traffic this server can hear at all, so a file naming one it is not going to get
is a file whose author should be told.
*/
@(test)
test_impossible_udp_reader_counts_are_refused :: proc(t: ^testing.T) {
	_, negative := load_string(
		"upstream:\n  servers: [1.1.1.1]\nlisteners:\n  udp:\n    readers: -1\n",
		context.temp_allocator,
	)
	e, has := negative.?
	if testing.expect(t, has, "a negative reader count was accepted") {
		testing.expect(t, strings.contains(e.messages[0], "listeners.udp.readers"), e.messages[0])
	}

	_, huge := load_string(
		"upstream:\n  servers: [1.1.1.1]\nlisteners:\n  udp:\n    readers: 1000\n",
		context.temp_allocator,
	)
	he, has_huge := huge.?
	if testing.expect(t, has_huge, "a reader count past the ceiling was accepted") {
		testing.expect(t, strings.contains(he.messages[0], "listeners.udp.readers"), he.messages[0])
	}

	// The ceiling itself is allowed: it is the first figure that is not.
	at, aerr := load_string(
		"upstream:\n  servers: [1.1.1.1]\nlisteners:\n  udp:\n    readers: 64\n",
		context.temp_allocator,
	)
	testing.expect(t, aerr == nil, "the ceiling itself should be accepted")
	testing.expect_value(t, at.listeners.udp.readers, MAX_UDP_READERS)

	// A reader count under a listener that is off is still a number somebody
	// will turn on one day.
	_, off := load_string(
		"upstream:\n  servers: [1.1.1.1]\nlisteners:\n  udp: { enabled: false, readers: -2 }\n",
		context.temp_allocator,
	)
	_, has_off := off.?
	testing.expect(t, has_off, "a bad reader count under a disabled listener was accepted")

	free_all(context.temp_allocator)
}

// A size, written the way every other size in this file is, and bounded at both
// ends: below one datagram the socket drops traffic on an idle server.
@(test)
test_udp_receive_buffer_is_a_size :: proc(t: ^testing.T) {
	cfg, err := load_string(
		"upstream:\n  servers: [1.1.1.1]\nlisteners:\n  udp:\n    receive_buffer: 4MiB\n",
		context.temp_allocator,
	)
	testing.expect(t, err == nil, "expected a clean load")
	testing.expect_value(t, cfg.listeners.udp.receive_buffer, 4 * 1024 * 1024)

	base, berr := load_string("upstream:\n  servers: [1.1.1.1]\n", context.temp_allocator)
	testing.expect(t, berr == nil, "expected a clean load")
	testing.expect_value(t, base.listeners.udp.receive_buffer, DEFAULT_UDP_RECEIVE_BUFFER)

	_, small := load_string(
		"upstream:\n  servers: [1.1.1.1]\nlisteners:\n  udp:\n    receive_buffer: 1KiB\n",
		context.temp_allocator,
	)
	e, has := small.?
	if testing.expect(t, has, "a receive buffer under one datagram was accepted") {
		testing.expect(t, strings.contains(e.messages[0], "listeners.udp.receive_buffer"), e.messages[0])
	}

	_, huge := load_string(
		"upstream:\n  servers: [1.1.1.1]\nlisteners:\n  udp:\n    receive_buffer: 4GiB\n",
		context.temp_allocator,
	)
	_, has_huge := huge.?
	testing.expect(t, has_huge, "a receive buffer past the ceiling was accepted")

	free_all(context.temp_allocator)
}

// Neither key is read for the transports it says nothing about: they are
// properties of a socket that reads datagrams, and a stream listener has none.
@(test)
test_reader_settings_are_udp_only :: proc(t: ^testing.T) {
	cfg, err := load_string(
		"upstream:\n  servers: [1.1.1.1]\nlisteners:\n  tcp:\n    readers: 4\n    receive_buffer: 4MiB\n",
		context.temp_allocator,
	)
	testing.expect(t, err == nil, "expected a clean load")
	testing.expect_value(t, cfg.listeners.tcp.readers, 0)
	testing.expect_value(t, cfg.listeners.tcp.receive_buffer, 0)
	free_all(context.temp_allocator)
}
