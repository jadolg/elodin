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
// (which resets the list), a field without `=`, a key set twice, an
// Environment= outside [Service] and any other environment directive
// (UnsetEnvironment=, EnvironmentFile=, PassEnvironment=) are refused rather
// than interpreted, so a value this does not read cannot pass as one.
func Parse(text string) ([]string, error) {
	var env []string
	inService := false
	for raw := range strings.SplitSeq(text, "\n") {
		// systemd strips ASCII blanks around the directive and its `=`.
		line := strings.TrimLeft(raw, " \t")
		if strings.HasPrefix(line, "[") {
			inService = strings.TrimRight(line, " \t\r") == "[Service]"
			continue
		}
		directive, value, found := strings.Cut(line, "=")
		if !found || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		directive = strings.TrimRight(directive, " \t")
		if !strings.Contains(directive, "Environment") {
			continue
		}
		if directive != "Environment" || !inService || strings.ContainsAny(value, `"'\%`) || strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("%s: %q is not read here", File, line)
		}
		// systemd splits on ASCII blanks only.
		for field := range strings.FieldsFuncSeq(value, func(c rune) bool { return c == ' ' || c == '\t' || c == '\r' }) {
			sep := strings.IndexByte(field, '=')
			if sep <= 0 {
				return nil, fmt.Errorf("%s: %q is not an assignment", File, field)
			}
			key := field[:sep+1]
			if slices.ContainsFunc(env, func(set string) bool { return strings.HasPrefix(set, key) }) {
				return nil, fmt.Errorf("%s: %s is set twice", File, key)
			}
			env = append(env, field)
		}
	}
	return env, nil
}

// Shipped is what elodin is started with: the unit's assignments
// first, then this process's environment without any MALLOC_ setting,
// GLIBC_TUNABLES or LD_PRELOAD (which can replace the allocator), so the
// allocator is configured by the unit and nothing else. getenv takes the first
// of a key set twice, and under systemd the unit's value is the one the process
// sees.
func Shipped(unit, inherited []string) []string {
	env := slices.Clone(unit)
	for _, kv := range inherited {
		if !strings.HasPrefix(kv, "MALLOC_") && !strings.HasPrefix(kv, "GLIBC_TUNABLES=") && !strings.HasPrefix(kv, "LD_PRELOAD=") {
			env = append(env, kv)
		}
	}
	return env
}

// Load reads and parses the unit at path.
func Load(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(string(data))
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
			return fmt.Errorf("pid %d runs without %s from %s", pid, kv, File)
		}
	}
	return nil
}
