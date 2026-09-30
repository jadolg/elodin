package re2diff_elodin

import "core:encoding/hex"
import "core:fmt"
import "core:os"
import "core:strings"
import "elodin:dns"
import "elodin:filter"

/*
The elodin half of `scripts/re2diff`: each line of the first file is a rule's
pattern, each of the second a query name's wire bytes in hex. For every pattern
it prints `-` when `/pattern/` is not kept as a rule, or else one `0` or `1` per
name for whether the rule blocks it. A name goes through `dns.decode_name`, as a
query's does, so what the rule sees is what it would see in the server.
*/
main :: proc() {
	if len(os.args) != 3 {
		fmt.eprintln("usage: re2diff-elodin PATTERNS NAMES")
		os.exit(2)
	}
	pattern_text, perr := os.read_entire_file(os.args[1], context.allocator)
	name_text, nerr := os.read_entire_file(os.args[2], context.allocator)
	if perr != nil || nerr != nil {
		fmt.eprintln("re2diff-elodin: cannot read the input")
		os.exit(2)
	}
	names: [dynamic]string
	lines := string(name_text)
	for line in strings.split_lines_iterator(&lines) {
		wire, ok := hex.decode(transmute([]u8)line)
		name, _, err := dns.decode_name(wire, 0)
		if !ok || err != nil {
			fmt.eprintfln("re2diff-elodin: bad name %q", line)
			os.exit(2)
		}
		append(&names, name)
	}
	out: strings.Builder
	patterns := string(pattern_text)
	for pattern in strings.split_lines_iterator(&patterns) {
		block, allow := filter.set_make(), filter.set_make()
		if filter.parse_rule(block, allow, fmt.tprintf("/%s/", pattern)) != 1 {
			strings.write_byte(&out, '-')
		} else {
			e := filter.engine_make()
			filter.engine_swap(e, block, allow)
			for name in names {
				strings.write_byte(&out, '1' if filter.engine_match(e, name) == .Blocked else '0')
			}
			filter.engine_swap(e, nil, nil)
			filter.engine_destroy(e)
		}
		strings.write_byte(&out, '\n')
		filter.set_destroy(block)
		filter.set_destroy(allow)
		free_all(context.temp_allocator)
	}
	os.write_string(os.stdout, strings.to_string(out))
}
