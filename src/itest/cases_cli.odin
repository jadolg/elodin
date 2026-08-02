package itest

import "core:fmt"
import "core:os"
import "core:path/filepath"
import "core:strings"

/*
Command-line behaviour: the checks an operator relies on before a deploy.
*/

@(private = "file")
Run_Result :: struct {
	exit_code: int,
	output:    string,
	ok:        bool,
}

@(private = "file")
run_binary :: proc(r: ^Runner, args: []string, tag: string) -> Run_Result {
	out_path := filepath.join({r.work_dir, fmt.tprintf("cli-%s.txt", tag)}, context.temp_allocator) or_else ""
	out_file, oerr := os.open(out_path, {.Write, .Create, .Trunc}, os.Permissions_Read_All + {.Write_User})
	if oerr != nil {
		return {}
	}

	command := make([dynamic]string, 0, len(args) + 1, context.temp_allocator)
	append(&command, r.binary)
	append(&command, ..args)

	process, perr := os.process_start(
		os.Process_Desc{command = command[:], stdout = out_file, stderr = out_file},
	)
	if perr != nil {
		os.close(out_file)
		return {}
	}
	state, werr := os.process_wait(process)
	os.close(out_file)
	if werr != nil {
		return {}
	}

	data, rerr := os.read_entire_file(out_path, context.temp_allocator)
	text := rerr == nil ? string(data) : ""
	return Run_Result{exit_code = state.exit_code, output = text, ok = true}
}

run_cli_cases :: proc(r: ^Runner) {
	start_case(r, "cli: --version prints the build")
	{
		res := run_binary(r, []string{"--version"}, "version")
		if check(r, res.ok, "could not run the binary") {
			check_eq_int(r, res.exit_code, 0, "exit code")
			check(r, strings.has_prefix(res.output, "elodin "), "unexpected output %q", res.output)
		}
	}
	end_case(r)

	start_case(r, "cli: --help prints usage")
	{
		res := run_binary(r, []string{"--help"}, "help")
		if check(r, res.ok, "could not run the binary") {
			check_eq_int(r, res.exit_code, 0, "exit code")
			check(r, strings.contains(res.output, "--config"), "usage does not mention --config")
		}
	}
	end_case(r)

	start_case(r, "cli: an unknown option fails with a message")
	{
		res := run_binary(r, []string{"--nonsense"}, "unknown")
		if check(r, res.ok, "could not run the binary") {
			check(r, res.exit_code != 0, "an unknown option exited 0")
			check(r, strings.contains(res.output, "unknown option"), "no explanation was printed")
		}
	}
	end_case(r)

	start_case(r, "cli: --check accepts a valid config")
	{
		path := filepath.join({r.work_dir, "valid.yaml"}, context.temp_allocator) or_else ""
		_ = os.write_entire_file(
			path,
			transmute([]u8)string("upstream:\n  servers: [1.1.1.1]\nblocking:\n  rules: [\"||a.test^\"]\n"),
		)
		res := run_binary(r, []string{"--config", path, "--check"}, "check-ok")
		if check(r, res.ok, "could not run the binary") {
			check_eq_int(r, res.exit_code, 0, "exit code")
			check(r, strings.contains(res.output, "is valid"), "no confirmation was printed")
		}
	}
	end_case(r)

	start_case(r, "cli: --check rejects a config with no upstreams")
	{
		path := filepath.join({r.work_dir, "no-upstream.yaml"}, context.temp_allocator) or_else ""
		_ = os.write_entire_file(path, transmute([]u8)string("log:\n  level: info\n"))
		res := run_binary(r, []string{"--config", path, "--check"}, "check-empty")
		if check(r, res.ok, "could not run the binary") {
			check(r, res.exit_code != 0, "an unusable config exited 0")
			check(r, strings.contains(res.output, "upstream"), "the error does not mention upstreams")
		}
	}
	end_case(r)

	start_case(r, "cli: --check reports every problem at once, with line numbers")
	{
		path := filepath.join({r.work_dir, "bad.yaml"}, context.temp_allocator) or_else ""
		_ = os.write_entire_file(
			path,
			transmute([]u8)string("upstream:\n  strategy: teleport\n  servers: [1.1.1.1]\nblocking:\n  response: explode\n"),
		)
		res := run_binary(r, []string{"--config", path, "--check"}, "check-bad")
		if check(r, res.ok, "could not run the binary") {
			check(r, res.exit_code != 0, "a bad config exited 0")
			check(r, strings.contains(res.output, "teleport"), "the unknown strategy was not reported")
			check(r, strings.contains(res.output, "explode"), "the unknown block mode was not reported")
		}
	}
	end_case(r)

	start_case(r, "cli: a missing config file is reported, not ignored")
	{
		res := run_binary(r, []string{"--config", "/nonexistent/elodin.yaml", "--check"}, "check-missing")
		if check(r, res.ok, "could not run the binary") {
			check(r, res.exit_code != 0, "a missing config exited 0")
			check(r, strings.contains(res.output, "cannot read"), "the error does not say the file is unreadable")
		}
	}
	end_case(r)

	start_case(r, "cli: malformed YAML is reported with a line number")
	{
		path := filepath.join({r.work_dir, "malformed.yaml"}, context.temp_allocator) or_else ""
		_ = os.write_entire_file(path, transmute([]u8)string("upstream:\n  servers: [1.1.1.1]\nthis is not a mapping\n"))
		res := new_check(r, path, "check-yaml")
		check(r, res.exit_code != 0, "malformed YAML exited 0")
		check(r, strings.contains(res.output, "line 3"), "the failing line was not identified: %q", res.output)
	}
	end_case(r)

	start_case(r, "cli: a DoT listener without a certificate is refused")
	{
		path := filepath.join({r.work_dir, "nocert.yaml"}, context.temp_allocator) or_else ""
		_ = os.write_entire_file(
			path,
			transmute([]u8)string("upstream:\n  servers: [1.1.1.1]\nlisteners:\n  dot:\n    enabled: true\n"),
		)
		res := new_check(r, path, "check-nocert")
		check(r, res.exit_code != 0, "a DoT listener with no certificate exited 0")
		check(r, strings.contains(res.output, "cert_file"), "the missing certificate was not reported")
	}
	end_case(r)

	start_case(r, "cli: the shipped example config is valid")
	{
		res := new_check(r, "examples/elodin.yaml", "check-example")
		check_eq_int(r, res.exit_code, 0, "exit code for examples/elodin.yaml")
	}
	end_case(r)
}

@(private = "file")
new_check :: proc(r: ^Runner, path: string, tag: string) -> Run_Result {
	return run_binary(r, []string{"--config", path, "--check"}, tag)
}
