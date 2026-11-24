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
	code := run([]string{"-n", "-all", "-no-toolchain", "-govulncheck", fake, "-dir", dir})
	// A dry run with work to do is a check that failed: exit 1.
	if code != 1 {
		t.Fatalf("exit %d, want 1\nstderr: %s", code, c.err.String())
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

func TestDefaultSkipsUncalledFindings(t *testing.T) {
	data, err := os.ReadFile("testdata/scan.json")
	if err != nil {
		t.Fatal(err)
	}
	dir, fake := testModule(t, string(data))

	var c capture
	c.start(t)
	code := run([]string{"-n", "-govulncheck", fake, "-dir", dir})
	if code != 0 {
		t.Fatalf("exit %d, want 0\nstderr: %s", code, c.err.String())
	}
	out := c.out.String()
	if !strings.Contains(out, "no advisories with a call path") {
		t.Errorf("expected a clean default (reachable) result:\n%s", out)
	}
	if strings.Contains(out, "golang.org/x/text  v0.3.0") {
		t.Errorf("the default still planned a bump:\n%s", out)
	}
}

func TestAllIncludesUncalledFindings(t *testing.T) {
	data, err := os.ReadFile("testdata/scan.json")
	if err != nil {
		t.Fatal(err)
	}
	dir, fake := testModule(t, string(data))

	var c capture
	c.start(t)
	code := run([]string{"-n", "-all", "-govulncheck", fake, "-dir", dir})
	if code != 1 {
		t.Fatalf("exit %d, want 1\nstderr: %s", code, c.err.String())
	}
	out := c.out.String()
	if !strings.Contains(out, "golang.org/x/text  v0.3.0") {
		t.Errorf("-all did not plan the bump:\n%s", out)
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

// An advisory with no fixed release leaves nothing to bump, but the module is
// still vulnerable, so a dry run has to fail the same way a real run does.
func TestNothingToBumpExitsOne(t *testing.T) {
	scanJSON := `{"config":{"scanner_name":"govulncheck","scanner_version":"1.8.0","go_version":"go1.25.0"}}
{"osv":{"id":"GO-TEST-0002","summary":"no fix yet","affected":[{"package":{"name":"golang.org/x/text","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}}
{"finding":{"osv":"GO-TEST-0002","trace":[{"module":"golang.org/x/text","version":"v0.3.0","package":"golang.org/x/text/language","function":"Parse"}]}}
`
	dir, fake := testModule(t, scanJSON)

	for _, args := range [][]string{
		{"-n", "-no-toolchain", "-govulncheck", fake, "-dir", dir},
		{"-no-toolchain", "-govulncheck", fake, "-dir", dir},
	} {
		var c capture
		c.start(t)
		code := run(args)
		if code != 1 {
			t.Errorf("%v: exit %d, want 1\nstdout: %s", args, code, c.out.String())
		}
		if !strings.Contains(c.out.String(), "nothing to bump") {
			t.Errorf("%v: expected a nothing-to-bump notice:\n%s", args, c.out.String())
		}
	}
}

// A replace directive decides which code is compiled, so bumping the require
// line cannot fix the finding. govulnmin has to see the replacement's version
// and say that the directive is the thing to edit.
func TestReplacedModuleIsReportedNotBumped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake govulncheck is a shell script")
	}
	dir := t.TempDir()
	dep := filepath.Join(dir, "dep")
	if err := os.MkdirAll(dep, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(dir, "go.mod"), "module example.com/fx\n\ngo 1.22\n\n"+
		"require example.com/dep v0.1.0\n\nreplace example.com/dep => ./dep\n")
	write(filepath.Join(dir, "fx.go"), "package fx\n")
	write(filepath.Join(dep, "go.mod"), "module example.com/dep\n\ngo 1.22\n")
	write(filepath.Join(dep, "dep.go"), "package dep\n")

	scanJSON := `{"config":{"scanner_name":"govulncheck","scanner_version":"1.8.0","go_version":"go1.25.0"}}
{"osv":{"id":"GO-TEST-0003","summary":"replaced module","affected":[{"package":{"name":"example.com/dep","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.2.0"}]}]}]}}
{"finding":{"osv":"GO-TEST-0003","trace":[{"module":"example.com/dep","version":"v0.1.0","package":"example.com/dep","function":"Foo"}]}}
`
	write(filepath.Join(dir, "scan.json"), scanJSON)
	fake := filepath.Join(dir, "govulncheck")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\ncat "+filepath.Join(dir, "scan.json")+"\nexit 3\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	var c capture
	c.start(t)
	code := run([]string{"-n", "-no-toolchain", "-govulncheck", fake, "-dir", dir})
	out := c.out.String()
	if code != 1 {
		t.Fatalf("exit %d, want 1\nstdout: %s\nstderr: %s", code, out, c.err.String())
	}
	if !strings.Contains(out, "replaced by a local directory") {
		t.Errorf("no note about the replace directive:\n%s", out)
	}
	if strings.Contains(out, "example.com/dep  v0.1.0 ->") {
		t.Errorf("planned a bump that the replace directive would undo:\n%s", out)
	}
}
