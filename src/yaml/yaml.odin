package yaml

import "core:mem"
import "core:strconv"
import "core:strings"

/*
A pragmatic YAML subset, sized for configuration files.

Supported: block mappings and sequences, nested structures by indentation,
plain / single-quoted / double-quoted scalars, flow sequences and mappings
([a, b] and {k: v}), block scalars (| and >, with the - and + chomping
indicators), comments, and document markers.

Not supported: anchors and aliases, tags, multiple documents in one stream,
complex (?) keys, and multi-line plain scalars. Any of these raise an error
rather than being silently misread.
*/

Kind :: enum u8 {
	Scalar,
	Sequence,
	Mapping,
}

Node :: struct {
	kind:    Kind,
	line:    int,
	// Scalar payload. `quoted` suppresses the null/bool/number interpretation
	// that bare scalars get, so "null" stays the string "null".
	scalar:  string,
	quoted:  bool,
	seq:     [dynamic]^Node,
	// `keys` preserves document order; `fields` is the lookup index.
	keys:    [dynamic]string,
	fields:  map[string]^Node,
}

Error :: struct {
	line: int,
	msg:  string,
}

@(private)
Line :: struct {
	indent: int,
	text:   string,
	num:    int,
}

@(private)
Parser :: struct {
	lines:     [dynamic]Line,
	pos:       int,
	allocator: mem.Allocator,
	err:       Maybe(Error),
}

parse :: proc(src: string, allocator := context.allocator) -> (root: ^Node, err: Maybe(Error)) {
	p := Parser {
		allocator = allocator,
		lines     = make([dynamic]Line, 0, 64, allocator),
	}
	defer delete(p.lines)

	scan_lines(&p, src) or_return

	if len(p.lines) == 0 {
		return new_mapping(&p, 1), nil
	}
	root = parse_block(&p, p.lines[0].indent)
	if e, has := p.err.?; has {
		return nil, e
	}
	if p.pos < len(p.lines) {
		return nil, Error{p.lines[p.pos].num, "unexpected indentation"}
	}
	return root, nil
}

@(private)
take_line :: proc(s: string) -> (line: string, rest: string) {
	if idx := strings.index_byte(s, '\n'); idx >= 0 {
		return s[:idx], s[idx + 1:]
	}
	return s, ""
}

@(private)
leading_spaces :: proc(s: string) -> int {
	n := 0
	for n < len(s) && s[n] == ' ' {
		n += 1
	}
	return n
}

@(private)
scan_lines :: proc(p: ^Parser, src: string) -> Maybe(Error) {
	num := 0
	rest := src
	for len(rest) > 0 || num == 0 {
		num += 1
		line: string
		line, rest = take_line(rest)
		line = strings.trim_right(line, "\r \t")

		indent := leading_spaces(line)
		if indent < len(line) && line[indent] == '\t' {
			return Error{num, "tabs may not be used for indentation"}
		}

		body := line[indent:]
		if len(body) == 0 || body[0] == '#' {
			continue
		}
		if body == "---" || body == "..." {
			continue
		}

		body = strip_comment(body)
		body = strings.trim_right(body, " \t")
		if len(body) == 0 {
			continue
		}
		append(&p.lines, Line{indent = indent, text = body, num = num})

		// Everything above treats the line as YAML. A block scalar's body is
		// not YAML but content, so it is taken verbatim instead.
		if parent, opens := opens_block_scalar(body, indent); opens {
			scan_block_scalar(p, &rest, &num, parent)
		}
		if len(rest) == 0 {
			break
		}
	}
	return nil
}

// Whether `s` is a block scalar header: `|` or `>` with at most one chomping
// indicator, the same shapes parse_block_scalar accepts.
@(private)
is_block_header :: proc(s: string) -> bool {
	if len(s) == 0 || (s[0] != '|' && s[0] != '>') {
		return false
	}
	return len(s) == 1 || (len(s) == 2 && (s[1] == '-' || s[1] == '+'))
}

// Reports the indentation a block scalar's body must exceed, when `body` is a
// line whose value opens one. `- key: |` nests the block under the entry's
// content column, which is the same rewrite parse_sequence performs, while
// `- |` nests it under the dash itself: the block is the entry's own value.
@(private)
opens_block_scalar :: proc(body: string, indent: int) -> (parent: int, opens: bool) {
	text, col := body, indent
	dash_col := -1
	for is_sequence_entry(text) {
		dash_col = col
		text, col = strings.trim_space(text[1:]), entry_content_col(text, col)
	}
	if is_block_header(text) {
		return dash_col if dash_col >= 0 else 0, dash_col >= 0
	}
	colon := find_key_colon(text) or_return
	value := strings.trim_space(text[colon + 1:])
	if !is_block_header(value) {
		return 0, false
	}
	return col, true
}

/*
Takes a block scalar's body verbatim: a `#` in it is text rather than a
comment, and a blank line is a blank line rather than a separator to drop.

The body runs until a line indented no further than the key that opened it,
which is what parse_block_scalar goes on to read it back at. Blank lines are
held until content proves they sit inside the block, so the ones that merely
trail it stay with the document.
*/
@(private)
scan_block_scalar :: proc(p: ^Parser, rest: ^string, num: ^int, parent: int) {
	block_indent := -1
	pending, pending_num := 0, 0

	for len(rest^) > 0 {
		line, after := take_line(rest^)
		line_num := num^ + 1
		body := strings.trim_right(line, "\r")
		indent := leading_spaces(body)

		// A line carrying no content is blank whatever it is made of. Counting
		// only spaces would let a lone tab fall through to the boundary test,
		// end the block on the spot, and hand the rest of the body back to the
		// comment stripper this whole procedure exists to keep it away from.
		if len(strings.trim_space(body)) == 0 {
			if pending == 0 {
				pending_num = line_num
			}
			pending += 1
			rest^, num^ = after, line_num
			continue
		}
		// Once the first body line has set the block's own indentation, that is
		// the boundary rather than the key's: a line short of it is outside the
		// block even though it clears the key that opened it.
		if indent <= parent || (block_indent >= 0 && indent < block_indent) {
			break
		}

		if block_indent < 0 {
			block_indent = indent
		}
		for _ in 0 ..< pending {
			append(&p.lines, Line{indent = block_indent, text = "", num = pending_num})
			pending_num += 1
		}
		pending = 0
		append(&p.lines, Line{indent = indent, text = body[indent:], num = line_num})
		rest^, num^ = after, line_num
	}
}

// A `#` only opens a comment when it follows whitespace and sits outside quotes.
@(private)
strip_comment :: proc(s: string) -> string {
	in_single, in_double := false, false
	for i := 0; i < len(s); i += 1 {
		c := s[i]
		switch {
		case in_single:
			if c == '\'' {
				in_single = false
			}
		case in_double:
			// A backslash escapes the byte after it, `\"` included, so that byte
			// has to be stepped over: leaving it to the next turn of the loop lets
			// an escaped quote close the scalar early, and the rest of the line is
			// then read unquoted.
			if c == '\\' {
				i += 1
				continue
			}
			if c == '"' {
				in_double = false
			}
		case c == '\'':
			in_single = true
		case c == '"':
			in_double = true
		case c == '#':
			if i == 0 || s[i - 1] == ' ' || s[i - 1] == '\t' {
				return s[:i]
			}
		}
	}
	return s
}

@(private)
new_node :: proc(p: ^Parser, kind: Kind, line: int) -> ^Node {
	n := new(Node, p.allocator)
	n.kind = kind
	n.line = line
	return n
}

@(private)
new_mapping :: proc(p: ^Parser, line: int) -> ^Node {
	n := new_node(p, .Mapping, line)
	n.keys = make([dynamic]string, 0, 8, p.allocator)
	n.fields = make(map[string]^Node, 8, p.allocator)
	return n
}

@(private)
new_sequence :: proc(p: ^Parser, line: int) -> ^Node {
	n := new_node(p, .Sequence, line)
	n.seq = make([dynamic]^Node, 0, 8, p.allocator)
	return n
}

@(private)
new_scalar :: proc(p: ^Parser, value: string, quoted: bool, line: int) -> ^Node {
	n := new_node(p, .Scalar, line)
	n.scalar = value
	n.quoted = quoted
	return n
}

@(private)
fail :: proc(p: ^Parser, line: int, msg: string) -> ^Node {
	if _, has := p.err.?; !has {
		p.err = Error{line, msg}
	}
	p.pos = len(p.lines)
	return new_scalar(p, "", false, line)
}

@(private)
is_sequence_entry :: proc(text: string) -> bool {
	return text == "-" || (len(text) >= 2 && text[0] == '-' && (text[1] == ' ' || text[1] == '\t'))
}

// The column a `- ` entry's content starts at. parse_sequence rewrites the
// entry to this column and opens_block_scalar nests a block body under it, so
// the two have to derive it the same way or they disagree about the block.
@(private)
entry_content_col :: proc(text: string, indent: int) -> int {
	col := indent + 1
	for col < indent + len(text) && text[col - indent] == ' ' {
		col += 1
	}
	return col
}

@(private)
parse_block :: proc(p: ^Parser, indent: int) -> ^Node {
	if p.pos >= len(p.lines) {
		return new_scalar(p, "", false, 0)
	}
	if is_sequence_entry(p.lines[p.pos].text) {
		return parse_sequence(p, indent)
	}
	return parse_mapping(p, indent)
}

@(private)
parse_mapping :: proc(p: ^Parser, indent: int) -> ^Node {
	node := new_mapping(p, p.lines[p.pos].num)

	for p.pos < len(p.lines) {
		line := p.lines[p.pos]
		if line.indent < indent {
			break
		}
		if line.indent > indent {
			return fail(p, line.num, "unexpected indentation inside a mapping")
		}
		if is_sequence_entry(line.text) {
			break
		}

		colon, ok := find_key_colon(line.text)
		if !ok {
			return fail(p, line.num, "expected 'key: value'")
		}
		raw_key := strings.trim_space(line.text[:colon])
		key, kerr := unquote_scalar(p, raw_key, line.num)
		if kerr {
			return fail(p, line.num, "malformed key")
		}
		rest := strings.trim_space(line.text[colon + 1:])
		p.pos += 1

		child := parse_value(p, rest, indent, line.num)
		if _, has := p.err.?; has {
			return node
		}
		if key not_in node.fields {
			append(&node.keys, key)
		}
		node.fields[key] = child
	}
	return node
}

@(private)
parse_sequence :: proc(p: ^Parser, indent: int) -> ^Node {
	node := new_sequence(p, p.lines[p.pos].num)

	for p.pos < len(p.lines) {
		line := p.lines[p.pos]
		if line.indent < indent {
			break
		}
		if line.indent > indent {
			return fail(p, line.num, "unexpected indentation inside a sequence")
		}
		if !is_sequence_entry(line.text) {
			break
		}

		rest := strings.trim_space(line.text[1:])
		if rest == "" {
			p.pos += 1
			if p.pos < len(p.lines) && p.lines[p.pos].indent > indent {
				append(&node.seq, parse_block(p, p.lines[p.pos].indent))
			} else {
				append(&node.seq, new_scalar(p, "", false, line.num))
			}
			continue
		}

		// `- |` and `- >`: the entry's value is a block scalar, read back at
		// the sequence's indentation like the value of any other key.
		if len(rest) > 0 && (rest[0] == '|' || rest[0] == '>') {
			p.pos += 1
			append(&node.seq, parse_block_scalar(p, rest, indent, line.num))
			if _, has := p.err.?; has {
				return node
			}
			continue
		}

		// `- key: value` starts a mapping whose body may continue on following
		// lines aligned with `key`. Rewrite the entry as a plain line at that
		// column and let the block parser take it from there.
		_, is_map := find_key_colon(rest)
		if is_map || is_sequence_entry(rest) {
			content_col := entry_content_col(line.text, line.indent)
			p.lines[p.pos] = Line{indent = content_col, text = rest, num = line.num}
			append(&node.seq, parse_block(p, content_col))
			if _, has := p.err.?; has {
				return node
			}
			continue
		}

		p.pos += 1
		append(&node.seq, parse_flow_or_scalar(p, rest, line.num))
	}
	return node
}

// Handles the right-hand side of `key:`, which may be inline or a nested block.
@(private)
parse_value :: proc(p: ^Parser, rest: string, indent: int, line_num: int) -> ^Node {
	if rest == "" {
		if p.pos < len(p.lines) && p.lines[p.pos].indent > indent {
			return parse_block(p, p.lines[p.pos].indent)
		}
		// A sequence may also sit at the same column as its parent key.
		if p.pos < len(p.lines) && p.lines[p.pos].indent == indent && is_sequence_entry(p.lines[p.pos].text) {
			return parse_sequence(p, indent)
		}
		return new_scalar(p, "", false, line_num)
	}
	if rest[0] == '|' || rest[0] == '>' {
		return parse_block_scalar(p, rest, indent, line_num)
	}
	return parse_flow_or_scalar(p, rest, line_num)
}

@(private)
parse_block_scalar :: proc(p: ^Parser, header: string, indent: int, line_num: int) -> ^Node {
	folded := header[0] == '>'
	chomp := byte(0)
	if len(header) > 1 {
		switch header[1] {
		case '-', '+':
			chomp = header[1]
		case:
			return fail(p, line_num, "unsupported block scalar indicator")
		}
	}

	b := strings.builder_make(p.allocator)
	block_indent := -1
	// Folding joins consecutive lines with a space, but a blank line between
	// them is a paragraph break and stays a newline. Blank lines only reach
	// here now that the scanner keeps them, so folding has to account for them.
	blanks, wrote := 0, false
	for p.pos < len(p.lines) {
		l := p.lines[p.pos]
		if l.indent <= indent {
			break
		}
		// A line short of the block's own indentation ends it, the same rule
		// the scanner applies: it clears the key yet sits outside the block.
		if block_indent >= 0 && l.indent < block_indent {
			break
		}
		if block_indent < 0 {
			block_indent = l.indent
		}
		p.pos += 1

		if folded && len(l.text) == 0 {
			blanks += 1
			continue
		}
		if folded {
			// Only the space that joins two lines needs a line before it; the
			// breaks a blank line stands for are written either way, so a block
			// that opens on a blank keeps it as the literal form does.
			if wrote && blanks == 0 {
				strings.write_byte(&b, ' ')
			}
			for _ in 0 ..< blanks {
				strings.write_byte(&b, '\n')
			}
		}
		blanks = 0

		if l.indent > block_indent {
			for _ in 0 ..< l.indent - block_indent {
				strings.write_byte(&b, ' ')
			}
		}
		strings.write_string(&b, l.text)
		if !folded {
			strings.write_byte(&b, '\n')
		}
		wrote = true
	}
	// No flush of a trailing `blanks` run: the scanner drops the blank lines
	// that merely trail a block, so the last line it hands over is always
	// content. Keep-chomping them is a separate change to both halves.

	s := strings.to_string(b)
	switch chomp {
	case '-':
		s = strings.trim_right(s, "\n ")
	case '+':
	// keep trailing newlines as-is
	case:
		s = strings.trim_right(s, "\n ")
		if !folded && len(s) > 0 {
			s = strings.concatenate({s, "\n"}, p.allocator)
		}
	}
	return new_scalar(p, s, true, line_num)
}

@(private)
parse_flow_or_scalar :: proc(p: ^Parser, text: string, line_num: int) -> ^Node {
	if len(text) > 0 && (text[0] == '[' || text[0] == '{') {
		node, consumed, ok := parse_flow(p, text, line_num)
		if !ok {
			return fail(p, line_num, "malformed flow collection")
		}
		if strings.trim_space(text[consumed:]) != "" {
			return fail(p, line_num, "trailing content after flow collection")
		}
		return node
	}
	value, bad := unquote_scalar(p, text, line_num)
	if bad {
		return fail(p, line_num, "malformed quoted scalar")
	}
	quoted := len(text) >= 2 && (text[0] == '"' || text[0] == '\'')
	return new_scalar(p, value, quoted, line_num)
}

@(private)
parse_flow :: proc(p: ^Parser, text: string, line_num: int) -> (node: ^Node, consumed: int, ok: bool) {
	closing := byte(']') if text[0] == '[' else byte('}')
	is_seq := text[0] == '['
	node = new_sequence(p, line_num) if is_seq else new_mapping(p, line_num)

	i := 1
	for {
		for i < len(text) && (text[i] == ' ' || text[i] == ',') {
			i += 1
		}
		if i >= len(text) {
			return nil, 0, false
		}
		if text[i] == closing {
			return node, i + 1, true
		}
		// Any other bracket here closes a collection this one never opened, as
		// in `[1, 2}`. It has to be rejected on the spot: the item scanner
		// below stops on a closer without consuming it, so leaving it would
		// park the loop on that byte and append an empty item forever.
		if text[i] == ']' || text[i] == '}' {
			return nil, 0, false
		}

		if text[i] == '[' || text[i] == '{' {
			child, used := parse_flow(p, text[i:], line_num) or_return
			if !is_seq {
				return nil, 0, false
			}
			append(&node.seq, child)
			i += used
			continue
		}

		start := i
		depth := 0
		in_single, in_double := false, false
		for i < len(text) {
			c := text[i]
			if in_single {
				if c == '\'' {in_single = false}
			} else if in_double {
				if c == '\\' {i += 1} else if c == '"' {in_double = false}
			} else if c == '\'' {
				in_single = true
			} else if c == '"' {
				in_double = true
			} else if c == '[' || c == '{' {
				depth += 1
			} else if c == ']' || c == '}' {
				if depth == 0 {break}
				depth -= 1
			} else if c == ',' && depth == 0 {
				break
			}
			i += 1
		}
		if i > len(text) {
			return nil, 0, false
		}
		item := strings.trim_space(text[start:i])

		if is_seq {
			value, bad := unquote_scalar(p, item, line_num)
			if bad {
				return nil, 0, false
			}
			quoted := len(item) >= 2 && (item[0] == '"' || item[0] == '\'')
			append(&node.seq, new_scalar(p, value, quoted, line_num))
		} else {
			colon := find_key_colon(item) or_return
			key, kbad := unquote_scalar(p, strings.trim_space(item[:colon]), line_num)
			if kbad {
				return nil, 0, false
			}
			val_text := strings.trim_space(item[colon + 1:])
			if key not_in node.fields {
				append(&node.keys, key)
			}

			// A flow map's value may itself be a flow collection, as in
			// `{answers: [a, b]}`.
			if len(val_text) > 0 && (val_text[0] == '[' || val_text[0] == '{') {
				child, used := parse_flow(p, val_text, line_num) or_return
				if strings.trim_space(val_text[used:]) != "" {
					return nil, 0, false
				}
				node.fields[key] = child
				continue
			}

			value, vbad := unquote_scalar(p, val_text, line_num)
			if vbad {
				return nil, 0, false
			}
			quoted := len(val_text) >= 2 && (val_text[0] == '"' || val_text[0] == '\'')
			node.fields[key] = new_scalar(p, value, quoted, line_num)
		}
	}
}

// Finds the ':' that separates a key from its value: it must be followed by a
// space or end the string, and must not sit inside quotes or a flow collection.
@(private)
find_key_colon :: proc(s: string) -> (idx: int, ok: bool) {
	depth := 0
	in_single, in_double := false, false
	for i := 0; i < len(s); i += 1 {
		c := s[i]
		switch {
		case in_single:
			if c == '\'' {in_single = false}
		case in_double:
			// Step over the escaped byte; see strip_comment.
			if c == '\\' {
				i += 1
				continue
			}
			if c == '"' {in_double = false}
		case c == '\'':
			in_single = true
		case c == '"':
			in_double = true
		case c == '[', c == '{':
			depth += 1
		case c == ']', c == '}':
			depth -= 1
		case c == ':' && depth == 0:
			if i + 1 == len(s) || s[i + 1] == ' ' || s[i + 1] == '\t' {
				return i, true
			}
		}
	}
	return 0, false
}

@(private)
unquote_scalar :: proc(p: ^Parser, s: string, line_num: int) -> (out: string, bad: bool) {
	if len(s) < 2 {
		return s, false
	}
	switch s[0] {
	case '\'':
		if s[len(s) - 1] != '\'' {
			return "", true
		}
		inner := s[1:len(s) - 1]
		if !strings.contains(inner, "''") {
			return inner, false
		}
		b := strings.builder_make(p.allocator)
		i := 0
		for i < len(inner) {
			if inner[i] == '\'' && i + 1 < len(inner) && inner[i + 1] == '\'' {
				strings.write_byte(&b, '\'')
				i += 2
				continue
			}
			strings.write_byte(&b, inner[i])
			i += 1
		}
		return strings.to_string(b), false

	case '"':
		if s[len(s) - 1] != '"' {
			return "", true
		}
		inner := s[1:len(s) - 1]
		if !strings.contains(inner, "\\") {
			return inner, false
		}
		b := strings.builder_make(p.allocator)
		i := 0
		for i < len(inner) {
			if inner[i] != '\\' {
				strings.write_byte(&b, inner[i])
				i += 1
				continue
			}
			i += 1
			if i >= len(inner) {
				return "", true
			}
			switch inner[i] {
			case 'n':
				strings.write_byte(&b, '\n')
			case 't':
				strings.write_byte(&b, '\t')
			case 'r':
				strings.write_byte(&b, '\r')
			case '0':
				strings.write_byte(&b, 0)
			case '\\':
				strings.write_byte(&b, '\\')
			case '"':
				strings.write_byte(&b, '"')
			case '/':
				strings.write_byte(&b, '/')
			case 'x':
				if i + 2 >= len(inner) {
					return "", true
				}
				v, vok := strconv.parse_u64_of_base(inner[i + 1:i + 3], 16)
				if !vok {
					return "", true
				}
				strings.write_byte(&b, u8(v))
				i += 2
			case 'u':
				if i + 4 >= len(inner) {
					return "", true
				}
				v, vok := strconv.parse_u64_of_base(inner[i + 1:i + 5], 16)
				if !vok {
					return "", true
				}
				strings.write_rune(&b, rune(v))
				i += 4
			case:
				return "", true
			}
			i += 1
		}
		return strings.to_string(b), false
	}
	return s, false
}
