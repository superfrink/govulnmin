package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// capture swaps the output writers for the duration of a test and collects
// what was written.
type capture struct{ out, err bytes.Buffer }

func (c *capture) start(t *testing.T) {
	t.Helper()
	oldOut, oldErr := outW, errW
	outW, errW = &c.out, &c.err
	t.Cleanup(func() { outW, errW = oldOut, oldErr })
}

// testModule writes a throwaway module that requires an old x/text, plus a
// fake govulncheck that replays a recorded scan. No network and no real
// govulncheck needed.
func testModule(t *testing.T, scanJSON string) (dir, fake string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake govulncheck is a shell script")
	}
	dir = t.TempDir()
	gomod := "module example.com/fx\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.0\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fx.go"), []byte("package fx\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scan.json"), []byte(scanJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	fake = filepath.Join(dir, "govulncheck")
	script := "#!/bin/sh\ncat " + filepath.Join(dir, "scan.json") + "\nexit 3\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir, fake
}

func TestDryRunPrintsPlanAndLeavesGoModAlone(t *testing.T) {
	data, err := os.ReadFile("testdata/scan.json")
	if err != nil {
		t.Fatal(err)
	}
	dir, fake := testModule(t, string(data))
	before, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}

	var c capture
	c.start(t)
	code := run([]string{"-n", "-no-toolchain", "-govulncheck", fake, "-dir", dir})
	if code != 0 {
		t.Fatalf("exit %d, want 0\nstderr: %s", code, c.err.String())
	}
	out := c.out.String()
	if !strings.Contains(out, "golang.org/x/text  v0.3.0 -> ") {
		t.Errorf("plan does not mention the x/text bump:\n%s", out)
	}
	if !strings.Contains(out, "dry run: no changes made") {
		t.Errorf("no dry-run notice:\n%s", out)
	}

	after, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("go.mod changed during a dry run:\n%s", after)
	}
}

func TestReachableSkipsUncalledFindings(t *testing.T) {
	data, err := os.ReadFile("testdata/scan.json")
	if err != nil {
		t.Fatal(err)
	}
	dir, fake := testModule(t, string(data))

	var c capture
	c.start(t)
	code := run([]string{"-n", "-reachable", "-govulncheck", fake, "-dir", dir})
	if code != 0 {
		t.Fatalf("exit %d, want 0\nstderr: %s", code, c.err.String())
	}
	out := c.out.String()
	if !strings.Contains(out, "no advisories with a call path") {
		t.Errorf("expected a clean -reachable result:\n%s", out)
	}
	if strings.Contains(out, "golang.org/x/text  v0.3.0") {
		t.Errorf("-reachable still planned a bump:\n%s", out)
	}
}

func TestCleanScanExitsZero(t *testing.T) {
	dir, fake := testModule(t, "{}")

	var c capture
	c.start(t)
	code := run([]string{"-n", "-govulncheck", fake, "-dir", dir})
	if code != 0 {
		t.Fatalf("exit %d, want 0\nstderr: %s", code, c.err.String())
	}
	if !strings.Contains(c.out.String(), "clean: no advisories") {
		t.Errorf("expected a clean result:\n%s", c.out.String())
	}
}

func TestNoGoModIsAnError(t *testing.T) {
	var c capture
	c.start(t)
	code := run([]string{"-n", "-dir", t.TempDir()})
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(c.err.String(), "govulnmin:") {
		t.Errorf("expected an error message, got %q", c.err.String())
	}
}

func TestBadFlagExitsTwo(t *testing.T) {
	var c capture
	c.start(t)
	if code := run([]string{"-nope"}); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
}
