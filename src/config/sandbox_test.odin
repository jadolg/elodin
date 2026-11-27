package config

import "core:strings"
import "core:testing"
import "elodin:sandbox"

// Basic unless the file says otherwise; each mode by name, in any case.
@(test)
test_server_sandbox_reads_its_three_modes :: proc(t: ^testing.T) {
	if cfg, ok := expect_loads(t, MINIMAL); ok {
		testing.expectf(t, cfg.server.sandbox == .Basic, "unset: %v, want Basic", cfg.server.sandbox)
	}
	Case :: struct {
		value: string,
		mode:  sandbox.Mode,
	}
	for c in ([]Case{{"off", .Off}, {"basic", .Basic}, {"strict", .Strict}, {"Strict", .Strict}, {"\"off\"", .Off}}) {
		src := strings.concatenate({MINIMAL, "server:\n  sandbox: ", c.value, "\n"}, context.temp_allocator)
		if cfg, ok := expect_loads(t, src); ok {
			testing.expectf(t, cfg.server.sandbox == c.mode, "%s: %v, want %v", c.value, cfg.server.sandbox, c.mode)
		}
	}
}

// A word that is no mode is refused, never read as YAML's false or left at the
// default: `sandbox: no` asked for something, and nothing says what.
@(test)
test_server_sandbox_refuses_what_is_not_a_mode :: proc(t: ^testing.T) {
	Case :: struct {
		value, want: string,
	}
	cases := []Case {
		{"false", "server.sandbox: unknown mode"},
		{"no", "server.sandbox: unknown mode"},
		{"strct", "server.sandbox: unknown mode"},
		{"[strict]", "server.sandbox: expected a string"},
	}
	for c in cases {
		expect_refused(t, strings.concatenate({MINIMAL, "server:\n  sandbox: ", c.value, "\n"}, context.temp_allocator), c.want)
	}
}
