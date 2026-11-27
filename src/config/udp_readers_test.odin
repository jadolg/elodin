package config

import "core:fmt"
import "core:mem"
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
	testing.expect_value(t, derive_udp_readers(Machine{cpus = 1, memory = 2 * mem.Gigabyte}), 1)
	testing.expect_value(t, derive_udp_readers(Machine{cpus = 2}), 2)
	testing.expect_value(t, derive_udp_readers(Machine{cpus = 4}), 4)
	testing.expect_value(t, derive_udp_readers(Machine{cpus = 8}), MAX_DERIVED_UDP_READERS)
	testing.expect_value(t, derive_udp_readers(Machine{cpus = 64}), MAX_DERIVED_UDP_READERS)
}

/*
A machine that could not be counted gets one reader, not a guess.

The opposite of `derive_max_pending`, which answers a default bound to the same
unknown, and the asymmetry is the point: a query slot that turns out to be
unnecessary is memory nobody touched, while a loop with no core to run on is a
thread contending for the core the loop beside it is using.
*/
@(test)
test_derive_udp_readers_does_not_guess :: proc(t: ^testing.T) {
	testing.expect_value(t, derive_udp_readers(Machine{}), MIN_DERIVED_UDP_READERS)
	testing.expect_value(t, derive_udp_readers(Machine{memory = 64 * mem.Gigabyte}), MIN_DERIVED_UDP_READERS)
}

// A figure in the file is the operator's, and is neither derived nor reported
// as though the machine had chosen it.
@(test)
test_configured_udp_readers_are_not_derived :: proc(t: ^testing.T) {
	src := MINIMAL + "listeners:\n  udp:\n    readers: 3\n"
	cfg, ok := expect_loads(t, src)
	if !ok {
		return
	}
	testing.expect_value(t, cfg.listeners.udp.readers, 3)
	testing.expect(t, !cfg.server.sizing.derived_udp_readers, "a configured count is not a derived one")
	free_all(context.temp_allocator)
}

// Unset is what every shipped configuration has, so the derivation is what
// almost every installation runs.
@(test)
test_unset_udp_readers_are_derived :: proc(t: ^testing.T) {
	cfg, ok := expect_loads(t, MINIMAL)
	if !ok {
		return
	}
	testing.expect(t, cfg.server.sizing.derived_udp_readers, "an unset reader count should be derived")
	testing.expect(
		t,
		cfg.listeners.udp.readers >= MIN_DERIVED_UDP_READERS &&
		cfg.listeners.udp.readers <= MAX_DERIVED_UDP_READERS,
		"the derived reader count is outside its own bounds",
	)
	// With the UDP listener off the count is derived all the same: it is the
	// number of event loops, and the stream listeners run on them (#547).
	if off, ook := expect_loads(t, MINIMAL + "listeners:\n  udp: { enabled: false }\n"); ook {
		testing.expect_value(t, off.listeners.udp.readers, cfg.listeners.udp.readers)
		testing.expect(t, off.server.sizing.derived_udp_readers, "the loop count was left underived with UDP off")
	}
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
	NEGATIVE :: "listeners.udp.readers must not be negative"
	expect_refused(t, MINIMAL + "listeners:\n  udp:\n    readers: -1\n", NEGATIVE, exact = true)
	past := fmt.tprintf(MINIMAL + "listeners:\n  udp:\n    readers: %d\n", MAX_UDP_READERS + 1)
	expect_refused(t, past, "listeners.udp.readers must be at most", prefix = true)

	// The ceiling itself is the largest figure allowed.
	at := fmt.tprintf(MINIMAL + "listeners:\n  udp:\n    readers: %d\n", MAX_UDP_READERS)
	if cfg, ok := expect_loads(t, at); ok {
		testing.expect_value(t, cfg.listeners.udp.readers, MAX_UDP_READERS)
	}

	// A reader count under a listener that is off is still a number somebody
	// will turn on one day.
	expect_refused(t, MINIMAL + "listeners:\n  udp: { enabled: false, readers: -2 }\n", NEGATIVE, exact = true)

	free_all(context.temp_allocator)
}

// A size, written the way every other size in this file is, and bounded at both
// ends: below one datagram the socket drops traffic on an idle server.
@(test)
test_udp_receive_buffer_is_a_size :: proc(t: ^testing.T) {
	if cfg, ok := expect_loads(t, MINIMAL + "listeners:\n  udp:\n    receive_buffer: 4MiB\n"); ok {
		testing.expect_value(t, cfg.listeners.udp.receive_buffer, 4 * mem.Megabyte)
	}
	if base, ok := expect_loads(t, MINIMAL); ok {
		testing.expect_value(t, base.listeners.udp.receive_buffer, DEFAULT_UDP_RECEIVE_BUFFER)
	}

	BOUNDS :: "listeners.udp.receive_buffer must be between"
	expect_refused(t, MINIMAL + "listeners:\n  udp:\n    receive_buffer: 1KiB\n", BOUNDS, prefix = true)
	expect_refused(t, MINIMAL + "listeners:\n  udp:\n    receive_buffer: 4GiB\n", BOUNDS, prefix = true)

	free_all(context.temp_allocator)
}

// Neither key means anything for the transports it says nothing about: they are
// properties of a socket that reads datagrams, and a stream listener has none.
// So under one they are refused like any other key nobody reads, rather than
// sitting in the file looking like a setting.
@(test)
test_reader_settings_are_udp_only :: proc(t: ^testing.T) {
	_, err := load_string(
		MINIMAL + "listeners:\n  tcp:\n    readers: 4\n    receive_buffer: 4MiB\n",
		context.temp_allocator,
	)
	e, has := err.?
	if testing.expect(t, has, "reader settings under a stream listener were accepted") {
		testing.expect_value(t, len(e.messages), 2)
		testing.expect_value(t, e.messages[0], "listeners.tcp.readers: unknown key")
		testing.expect_value(t, e.messages[1], "listeners.tcp.receive_buffer: unknown key")
	}
	free_all(context.temp_allocator)
}
