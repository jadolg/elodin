package unitenv

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

// The shipped unit is read, and it sets the threshold the issue is about.
func TestShippedUnit(t *testing.T) {
	env, err := Load(filepath.Join("..", "..", "..", File))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(env, "MALLOC_MMAP_THRESHOLD_=131072") {
		t.Fatalf("unit environment %v has no MALLOC_MMAP_THRESHOLD_=131072", env)
	}
}

func TestParse(t *testing.T) {
	got, err := Parse("[Unit]\nDescription=x\n[Service]\n# Environment=A=0\n  Environment = A=1\tB=2\nEnvironment=C=3\n[Install]\n")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"A=1", "B=2", "C=3"}; !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// A line a backslash continues is part of the directive before it, as it is
// to systemd, including past a comment between them.
func TestParseContinuation(t *testing.T) {
	got, err := Parse("[Service]\nExecStart=/usr/bin/elodin \\\n  Environment=X=1\nExecStartPre=/bin/true \\\n# a comment\n  Environment=Y=1\nExecStopPost=/bin/true \\\r\nEnvironment=Z=1\nEnvironment=A=1\n" +
		// Neither of these continues: systemd 259 sets both B and C.
		"ExecStartPost=/bin/true \\ \nEnvironment=B=1\nExecReload=/bin/true \\\\\nEnvironment=C=1\n")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"A=1", "B=1", "C=1"}; !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// Anything this does not interpret the way systemd does is refused.
func TestParseRefuses(t *testing.T) {
	for _, unit := range []string{
		"[Service]\nEnvironment=\"A=1 2\"\n",
		"[Service]\nEnvironment='A=1'\n",
		"[Service]\nEnvironment=A=%h\n",
		"[Service]\nEnvironment=A=\\x\n",
		"[Service]\nEnvironment=\n",
		"[Service]\nEnvironment=A\n",
		"[Service]\nEnvironment==1\n",
		"[Service]\nEnvironment=A-B=1\n",
		"[Service]\nEnvironment=1A=1\n",
		"[Service]\nEnvironment=A=1 A=2\n",
		"[Unit]\nEnvironment=A=1\n",
		"[Service]\nUnsetEnvironment=A\n",
		"[Service]\nEnvironmentFile=/etc/x\n",
		"[Service]\nPassEnvironment=A\n",
	} {
		if env, err := Parse(unit); err == nil {
			t.Errorf("%q read as %v", unit, env)
		}
	}
}

// The unit's assignments come first, and an allocator setting of the caller's
// own does not reach the server.
func TestShipped(t *testing.T) {
	got := Shipped([]string{"MALLOC_MMAP_THRESHOLD_=131072", "TZ=UTC"},
		[]string{"PATH=/bin", "MALLOC_ARENA_MAX=1", "GLIBC_TUNABLES=glibc.malloc.trim_threshold=1", "LD_PRELOAD=x.so", "TZ=Europe/Berlin", "HOME=/h"})
	if want := []string{"MALLOC_MMAP_THRESHOLD_=131072", "TZ=UTC", "PATH=/bin", "HOME=/h"}; !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// Check reads the environment the kernel holds for a process.
func TestCheck(t *testing.T) {
	cmd := exec.Command("sleep", "5")
	cmd.Env = Shipped([]string{"ELODIN_UNITENV_TEST=1"}, os.Environ())
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	if err := Check(cmd.Process.Pid, []string{"ELODIN_UNITENV_TEST=1"}); err != nil {
		t.Fatal(err)
	}
	if err := Check(cmd.Process.Pid, []string{"ELODIN_UNITENV_TEST=2"}); err == nil {
		t.Fatal("a value the process does not hold passed")
	}
	if err := Check(os.Getpid(), []string{"ELODIN_UNITENV_TEST=1"}); err == nil {
		t.Fatal("a process started without the unit's environment passed")
	}
}
