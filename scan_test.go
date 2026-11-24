package main

import (
	"os"
	"strings"
	"testing"
)

func loadScan(t *testing.T, path string) *scan {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s, err := parseScan(f)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return s
}

func testBuild() *build {
	return &build{
		path:     "example.com/fx",
		goVer:    "1.21",
		resolved: "go1.25.0",
		modules: map[string]string{
			"example.com/fx":    "",
			"golang.org/x/text": "v0.3.0",
		},
	}
}

func TestNextFixedPicksLowestAboveCurrent(t *testing.T) {
	e := &osvEntry{ID: "x", Affected: []osvAffect{{
		Package: struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		}{Name: "golang.org/x/text", Ecosystem: "Go"},
		Ranges: []struct {
			Type   string              `json:"type"`
			Events []map[string]string `json:"events"`
		}{{Type: "SEMVER", Events: []map[string]string{
			{"introduced": "0"}, {"fixed": "0.3.3"},
			{"introduced": "0.4.0"}, {"fixed": "0.5.0"},
		}}},
	}}}

	cur, _ := parseVersion("v0.3.0")
	got, ok := nextFixed(e, "golang.org/x/text", cur)
	if !ok || got.String() != "0.3.3" {
		t.Fatalf("got %v %v, want 0.3.3", got, ok)
	}

	cur, _ = parseVersion("v0.4.5")
	got, ok = nextFixed(e, "golang.org/x/text", cur)
	if !ok || got.String() != "0.5.0" {
		t.Fatalf("got %v %v, want 0.5.0", got, ok)
	}

	// Above every fix range: nothing to do.
	cur, _ = parseVersion("v0.6.0")
	if got, ok := nextFixed(e, "golang.org/x/text", cur); ok {
		t.Fatalf("got %v, want no fix", got)
	}
}

func TestNextFixedToolchainMinorBranch(t *testing.T) {
	// A stdlib advisory with one fix per release branch: the fix for 1.25.x
	// must win over the 1.27.x one.
	s := loadScan(t, "testdata/scan.json")
	e := s.entries["GO-2026-6603"]
	if e == nil {
		t.Fatal("GO-2026-6603 missing from testdata")
	}
	cur, _ := parseVersion("go1.25.0")
	got, ok := nextFixed(e, "stdlib", cur)
	if !ok || got.String() != "1.26.9" {
		t.Fatalf("got %v %v, want 1.26.9", got, ok)
	}
}

func TestBuildPlanMinimalBumps(t *testing.T) {
	s := loadScan(t, "testdata/scan.json")
	p := buildPlan(s, testBuild(), false)

	if p.toolchain == nil {
		t.Fatal("expected a toolchain change")
	}
	if p.toolchain.to != "go1.26.11" {
		t.Errorf("toolchain to = %s, want go1.26.11", p.toolchain.to)
	}
	if len(p.modules) != 1 {
		t.Fatalf("got %d module changes, want 1: %+v", len(p.modules), p.modules)
	}
	m := p.modules[0]
	if m.module != "golang.org/x/text" || m.to != "v0.41.0" || m.from != "v0.3.0" {
		t.Errorf("module change = %+v, want golang.org/x/text v0.3.0 -> v0.41.0", m)
	}
}

func TestBuildPlanReachable(t *testing.T) {
	// Every finding in the fixture is package-level, so -reachable leaves
	// nothing to do.
	s := loadScan(t, "testdata/scan.json")
	p := buildPlan(s, testBuild(), true)
	if !p.empty() {
		t.Fatalf("expected an empty plan, got %+v", p)
	}
	if p.findings != 0 || p.skipped != 66 {
		t.Errorf("findings = %d, skipped = %d, want 0 and 66", p.findings, p.skipped)
	}
}

func TestBuildPlanModuleOnly(t *testing.T) {
	s := loadScan(t, "testdata/module-only.json")
	p := buildPlan(s, testBuild(), false)
	if p.toolchain != nil {
		t.Errorf("unexpected toolchain change: %+v", p.toolchain)
	}
	if len(p.modules) != 1 || p.modules[0].to != "v0.3.8" {
		t.Fatalf("got %+v", p.modules)
	}
	if !strings.Contains(p.modules[0].osvs[0], "GO-TEST-0001") {
		t.Errorf("osvs = %v", p.modules[0].osvs)
	}
}
