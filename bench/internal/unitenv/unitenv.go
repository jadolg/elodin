// Package unitenv reads the Environment= assignments of the systemd unit
// elodin ships with, so a harness can start the server the way the unit does.
// The unit's MALLOC_MMAP_THRESHOLD_ changes how glibc serves memory, and a
// server started without it measures an allocator setup that does not ship.
package unitenv

import (
	"fmt"
	"os"
	"slices"
	"strings"
)

// File is the unit, relative to the repository root.
const File = "packaging/elodin.service"

// Parse returns the KEY=VALUE assignments of the unit's Environment=
// lines, read with the rules of unit_environment in
// src/itest/cases_list_memory.odin. Quoting, specifiers, an empty assignment
// (which resets the list), a field without `=` or with a name systemd refuses,
// a key set twice, an Environment= outside [Service] and any other environment
// directive (UnsetEnvironment=, EnvironmentFile=, PassEnvironment=) are refused
// rather than interpreted, so a value this does not read cannot pass as one.
// Lines a backslash continues belong to the directive before them.
func Parse(text string) ([]string, error) {
	var env []string
	inService, continued := false, false
	for raw := range strings.SplitSeq(text, "\n") {
		// systemd strips ASCII blanks around the directive and its `=`.
		line := strings.TrimLeft(raw, " \t")
		comment := isComment(line)
		// A line ending in a backslash goes on into the next, comments between
		// them aside, so what follows it is part of that directive and not one
		// of its own. Environment= is never continued: its value would hold
		// the backslash, which environmentFields refuses.
		if continued {
			continued = comment || continues(line)
			continue
		}
		continued = !comment && continues(line)
		if strings.HasPrefix(line, "[") {
			inService = strings.TrimRight(line, " \t\r") == "[Service]"
			continue
		}
		fields, err := environmentFields(line, comment, inService)
		if err != nil {
			return nil, err
		}
		for _, field := range fields {
			if env, err = addAssignment(env, field); err != nil {
				return nil, err
			}
		}
	}
	return env, nil
}

// isComment is whether systemd reads line, blanks already trimmed, as a comment.
func isComment(line string) bool {
	return strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";")
}

// environmentFields is the fields of line if it is an Environment= directive
// of [Service], none if it names no environment, and an error for any other
// environment directive or a value this does not interpret.
func environmentFields(line string, comment, inService bool) ([]string, error) {
	directive, value, found := strings.Cut(line, "=")
	if !found || comment {
		return nil, nil
	}
	directive = strings.TrimRight(directive, " \t")
	if !strings.Contains(directive, "Environment") {
		return nil, nil
	}
	if directive != "Environment" || !inService || strings.ContainsAny(value, `"'\%`) || strings.TrimSpace(value) == "" {
		return nil, fmt.Errorf("%q is not read here", line)
	}
	// systemd splits on ASCII blanks only.
	return strings.FieldsFunc(value, func(c rune) bool { return c == ' ' || c == '\t' || c == '\r' }), nil
}

// addAssignment appends one KEY=VALUE field to env, refusing a field that is
// not an assignment to a name systemd takes, or a key env already sets.
func addAssignment(env []string, field string) ([]string, error) {
	sep := strings.IndexByte(field, '=')
	if sep <= 0 || !validName(field[:sep]) {
		return nil, fmt.Errorf("%q is not an assignment", field)
	}
	key := field[:sep+1]
	if slices.ContainsFunc(env, func(set string) bool { return strings.HasPrefix(set, key) }) {
		return nil, fmt.Errorf("%s is set twice", key)
	}
	return append(env, field), nil
}

// continues is whether systemd joins the next line onto this one: the line ends
// in a backslash that does not escape another, with nothing after it but the
// line's \r. A blank after the backslash, or `\\`, ends the directive there.
func continues(line string) bool {
	line = strings.TrimSuffix(line, "\r")
	return (len(line)-len(strings.TrimRight(line, `\`)))%2 == 1
}

// validName is an environment variable name systemd takes: a letter or `_`,
// then letters, digits and `_`. systemd refuses any other, so the process
// would never see it.
func validName(key string) bool {
	for i, c := range key {
		if c != '_' && !('A' <= c && c <= 'Z') && !('a' <= c && c <= 'z') && (i == 0 || !('0' <= c && c <= '9')) {
			return false
		}
	}
	return key != ""
}

// Shipped is what elodin is started with: the unit's assignments
// first, then this process's environment without any MALLOC_ setting,
// GLIBC_TUNABLES or LD_PRELOAD (which can replace the allocator), so the
// allocator is configured by the unit and nothing else. An inherited key the
// unit also sets is dropped too: os/exec keeps the last of a key set twice, and
// under systemd the unit's value is the one the process sees.
func Shipped(unit, inherited []string) []string {
	env := slices.Clone(unit)
	for _, kv := range inherited {
		key, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(kv, "MALLOC_") || strings.HasPrefix(kv, "GLIBC_TUNABLES=") || strings.HasPrefix(kv, "LD_PRELOAD=") ||
			slices.ContainsFunc(unit, func(set string) bool { return strings.HasPrefix(set, key+"=") }) {
			continue
		}
		env = append(env, kv)
	}
	return env
}

// Load reads and parses the unit at path.
func Load(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	env, err := Parse(string(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return env, nil
}

// Check reads back the environment the kernel holds for pid and
// fails unless every one of want is in it, so a server that did not get the
// unit's settings - a wrapper that dropped them - cannot be measured as if it
// had.
func Check(pid int, want []string) error {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return err
	}
	have := strings.Split(string(data), "\x00")
	for _, kv := range want {
		if !slices.Contains(have, kv) {
			return fmt.Errorf("pid %d runs without the unit's %s", pid, kv)
		}
	}
	return nil
}
