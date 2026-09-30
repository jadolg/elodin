// Command re2diff checks that elodin reads an adblock `/regex/` rule as
// AdGuard Home does.
//
// It draws random patterns from fragments of RE2 syntax, valid and not, and
// random query names from wire bytes, and asks both urlfilter's DNSEngine - the
// engine AdGuard Home filters with - and elodin (through the driver built from
// ./elodin) which names each `/pattern/` rule blocks. urlfilter is handed a name
// as miekg/dns presents it, which is how AdGuard Home receives one; elodin
// decodes the same wire bytes itself.
//
// A pattern elodin keeps must block exactly the names urlfilter blocks. One
// elodin refuses is not a divergence: it keeps only a subset of RE2, and
// refuses a pattern that matches the empty string. Those are counted, not
// failed.
//
//	mise run re2-diff                         # or:
//	go run . -elodin ../../bin/re2diff-elodin -n 50000 -seed 7
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/miekg/dns"
)

// Pieces a pattern is built from: every construct of the subset elodin reads,
// the RE2 it refuses, and what is neither.
var fragments = []string{
	"a", "b", "k", "s", "z", "A", "K", "S", "Z", "0", "9", "-", "_", ".", " ",
	`\.`, `\-`, `\_`, `\ `, `\#`, `\\`, `\$`, `\^`, `\|`, `\{`, `\}`, `\(`, `\)`,
	`\*`, `\+`, `\?`, `\[`, `\]`, `\/`, `\'`, `\@`, `\;`, `\"`,
	`\d`, `\D`, `\w`, `\W`, `\s`, `\S`, `\b`, `\B`,
	"(", ")", "(?:", "(?i)", "(?P<n>", "(?=", "|", "*", "+", "?", "*?", "+?", "??",
	"{2}", "{1,3}", "{0,}", "{2,}", "{,2}", "{}", "{a}", "{0}", "{0,0}", "{-1}",
	"{2,1}", "{1000}", "{1001}", "{500}", "{02}", "{+2}", "{1_0}", "{ 2}", "{2,03}",
	"{", "}", "[", "]", "[^", "[]", "[^]", "a-z", "0-9", "A-Z", "a-", "-]", "--",
	"[:alpha:]", "[[:", "^", "$", "#", "!", "~", ",", "/", ":", "=", "'", "@", ";",
	`"`, `\n`, `\t`, `\x41`, `\pL`, `\A`, `\z`, `\1`, `\0`, `\Q`,
	"$important", "$badfilter", "/$", "$match-case",
}

// Bytes a label is built from, with every one miekg/dns and elodin present
// differently.
const labelBytes = "abkszAKZ09-_.\\ '@;()\"*#$^~/+\x01\x7f\xc3"

func main() {
	driver := flag.String("elodin", "", "the re2diff-elodin driver binary")
	count := flag.Int("n", 20000, "patterns to draw")
	seed := flag.Uint64("seed", 0, "seed; 0 draws one")
	verbose := flag.Bool("v", false, "list refused patterns urlfilter matches with")
	flag.Parse()
	if *driver == "" {
		fmt.Fprintln(os.Stderr, "re2diff: -elodin is required")
		os.Exit(2)
	}
	if *seed == 0 {
		*seed = uint64(time.Now().UnixNano())
	}
	fmt.Printf("seed %d\n", *seed)
	// Seeded, so that a divergence is reproduced from the printed seed; no
	// secret is drawn from it.
	r := rand.New(rand.NewPCG(*seed, 0)) // nosemgrep: go.lang.security.audit.crypto.math_random.math-random-used

	patterns := drawPatterns(r, *count)
	wires, names := drawNames(r)
	got := runElodin(*driver, patterns, wires)
	if compare(patterns, names, got, *verbose) > 0 {
		os.Exit(1)
	}
}

// What the driver answers for each pattern: `-`, or a bit per name.
func runElodin(driver string, patterns []string, wires [][]byte) []string {
	dir, err := os.MkdirTemp("", "re2diff")
	check(err)
	defer os.RemoveAll(dir)
	patternFile := filepath.Join(dir, "patterns.txt")
	nameFile := filepath.Join(dir, "names.hex")
	check(os.WriteFile(patternFile, []byte(strings.Join(patterns, "\n")+"\n"), 0o600))
	hexNames := make([]string, len(wires))
	for i, w := range wires {
		hexNames[i] = hex.EncodeToString(w)
	}
	check(os.WriteFile(nameFile, []byte(strings.Join(hexNames, "\n")+"\n"), 0o600))

	out, err := exec.Command(driver, patternFile, nameFile).Output()
	check(err)
	got := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	if len(got) != len(patterns) {
		fmt.Fprintf(os.Stderr, "re2diff: %d results for %d patterns\n", len(got), len(patterns))
		os.Exit(2)
	}
	return got
}

// Holds elodin's answers to urlfilter's, and returns how many kept patterns
// disagree.
func compare(patterns, names, got []string, verbose bool) (divergent int) {
	kept, refused, declined := 0, 0, 0
	for i, p := range patterns {
		want := urlfilterBits(p, names)
		if got[i] == "-" {
			refused++
			if strings.Contains(want, "1") {
				declined++
				if verbose {
					fmt.Printf("REFUSED %q\n", p)
				}
			}
			continue
		}
		kept++
		if got[i] != want {
			divergent++
			if divergent <= 40 {
				report(p, names, got[i], want)
			}
		}
	}
	fmt.Printf("patterns %d, kept %d, refused %d (%d that urlfilter blocks with), divergent %d\n", len(patterns), kept, refused, declined, divergent)
	return divergent
}

func report(pattern string, names []string, got, want string) {
	fmt.Printf("DIVERGENT %q\n", pattern)
	for j := range names {
		if got[j] != want[j] {
			fmt.Printf("  %q: elodin %c, urlfilter %c\n", names[j], got[j], want[j])
		}
	}
}

func drawPatterns(r *rand.Rand, n int) []string {
	patterns := make([]string, 0, n)
	for len(patterns) < n {
		var b strings.Builder
		for k := r.IntN(8) + 1; k > 0; k-- {
			b.WriteString(fragments[r.IntN(len(fragments))])
		}
		patterns = append(patterns, b.String())
	}
	return patterns
}

// Query names as wire bytes, and as miekg/dns presents each: lowercased and
// without the trailing dot, as AdGuard Home hands one to urlfilter.
func drawNames(r *rand.Rand) (wires [][]byte, names []string) {
	add := func(labels ...string) {
		var w []byte
		for _, l := range labels {
			w = append(w, byte(len(l)))
			w = append(w, l...)
		}
		w = append(w, 0)
		name, _, err := dns.UnpackDomainName(w, 0)
		check(err)
		wires = append(wires, w)
		names = append(names, strings.ToLower(strings.TrimSuffix(name, ".")))
	}
	for _, n := range []string{"a", "b", "k", "s", "z", "0", "_", "-", "ab", "aa", "ba", "a-b", "a_b", "a9"} {
		add(n)
	}
	add("a", "b")
	add("ads", "example", "com")
	for i := 0; i < 90; i++ {
		labels := make([]string, r.IntN(3)+1)
		for j := range labels {
			var l strings.Builder
			for k := r.IntN(6) + 1; k > 0; k-- {
				// Mostly the letters, digits and `-` a hostname holds.
				if r.IntN(4) == 0 {
					l.WriteByte(labelBytes[r.IntN(len(labelBytes))])
				} else {
					l.WriteByte(labelBytes[r.IntN(12)])
				}
			}
			labels[j] = l.String()
		}
		add(labels...)
	}
	return wires, names
}

// Which of names the rule `/pattern/` blocks, to urlfilter.
func urlfilterBits(pattern string, names []string) string {
	storage, err := filterlist.NewRuleStorage([]filterlist.Interface{
		filterlist.NewString(&filterlist.StringConfig{ID: 1, RulesText: "/" + pattern + "/"}),
	})
	check(err)
	engine := urlfilter.NewDNSEngine(storage)
	var bits strings.Builder
	for _, name := range names {
		res, ok := engine.Match(name)
		if ok && res.NetworkRule != nil && !res.NetworkRule.Whitelist {
			bits.WriteByte('1')
		} else {
			bits.WriteByte('0')
		}
	}
	return bits.String()
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "re2diff:", err)
		os.Exit(2)
	}
}
