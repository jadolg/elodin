package main

import (
	"os"
	"strings"
	"testing"

	"elodin.bench/internal/procstat"
)

// loadgen's end-of-warmup line restarts the CPU count and is kept out of its
// complaint; a run without it is reported, not counted from the start.
func TestWatchWarmup(t *testing.T) {
	sp := procstat.NewSampler(os.Getpid())
	rest, marked := watchWarmup(strings.NewReader("a\n"+loadgenMeasuring+"\nb\n"), sp)
	if !marked || rest != "a b" {
		t.Errorf("got %q, %v", rest, marked)
	}
	if _, marked := watchWarmup(strings.NewReader("loadgen: oops\n"), sp); marked {
		t.Error("marked without the line")
	}
}
