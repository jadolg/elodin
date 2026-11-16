package config

import "core:strings"
import "core:testing"
import "elodin:dns"

// A bare word picks a mode; a quoted one is a text, whatever it says.
@(test)
test_server_identity_reads_its_three_modes :: proc(t: ^testing.T) {
	Case :: struct {
		value: string,
		mode:  Identity,
		text:  string,
	}
	cases := []Case {
		{"version", .Version, ""},
		{"off", .Off, ""},
		{"false", .Off, ""},
		{"\"resolver\"", .Text, "resolver"},
		{"'off'", .Text, "off"},
		{"\"version\"", .Text, "version"},
		{"\"a b ~\"", .Text, "a b ~"},
	}
	for c in cases {
		src := strings.concatenate({MINIMAL, "server:\n  identity: ", c.value, "\n"}, context.temp_allocator)
		cfg, ok := expect_loads(t, src)
		if !ok {
			continue
		}
		testing.expectf(t, cfg.server.identity == c.mode, "%s: mode %v, want %v", c.value, cfg.server.identity, c.mode)
		testing.expectf(t, cfg.server.identity_text == c.text, "%s: text %q, want %q", c.value, cfg.server.identity_text, c.text)
	}

	cfg, ok := expect_loads(t, MINIMAL)
	if ok {
		testing.expectf(t, cfg.server.identity == .Version, "unset: mode %v, want Version", cfg.server.identity)
	}
}

// What is refused, by why: never a default left in force, never a text taken
// from a bare word.
@(test)
test_server_identity_refuses_what_it_cannot_answer :: proc(t: ^testing.T) {
	Case :: struct {
		value, want: string,
	}
	cases := []Case {
		{"true", "neither version nor off"},
		{"of", "neither version nor off"},
		{"Version", "neither version nor off"},
		{"\"\"", "a text is 1 to"},
		{strings.concatenate({"\"", strings.repeat("x", dns.MAX_CHARACTER_STRING + 1, context.temp_allocator), "\""}, context.temp_allocator), "a text is 1 to"},
		{"\"tab\there\"", "byte 0x09"},
		{"\"café\"", "byte 0xc3"},
		{"[x]", "expected version, off, or a quoted text"},
		{"{x: y}", "expected version, off, or a quoted text"},
		{"~", "expected version, off, or a quoted text"},
	}
	for c in cases {
		src := strings.concatenate({MINIMAL, "server:\n  identity: ", c.value, "\n"}, context.temp_allocator)
		expect_refused(t, src, "server.identity", c.want)
	}

	// The longest text one <character-string> holds is taken.
	longest := strings.repeat("x", dns.MAX_CHARACTER_STRING, context.temp_allocator)
	src := strings.concatenate({MINIMAL, "server:\n  identity: \"", longest, "\"\n"}, context.temp_allocator)
	if cfg, ok := expect_loads(t, src); ok {
		testing.expectf(t, cfg.server.identity_text == longest, "a %d-byte text read as %d bytes", dns.MAX_CHARACTER_STRING, len(cfg.server.identity_text))
	}
}
