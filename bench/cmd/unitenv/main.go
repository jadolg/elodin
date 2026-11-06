// Command unitenv prints the environment elodin runs with under the shipped
// unit: the unit's Environment= assignments, then this process's environment
// without allocator settings (see internal/unitenv). One NUL-terminated
// KEY=VALUE per variable, for `env -i` in scripts/load-smoke.sh, so the script
// and the benchmarks read the unit the same way.
package main

import (
	"fmt"
	"os"

	"elodin.bench/internal/unitenv"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: unitenv <path to elodin.service>")
		os.Exit(2)
	}
	unit, err := unitenv.Load(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "unitenv:", err)
		os.Exit(1)
	}
	for _, kv := range unitenv.Shipped(unit, os.Environ()) {
		fmt.Print(kv, "\x00")
	}
}
