package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strings"
)

// govulncheck -json emits a stream of JSON objects: config, SBOM, osv,
// finding, summary. We read the "osv" entries (the advisories) and the
// "finding" records (what matched in this build).

type osvEntry struct {
	ID       string      `json:"id"`
	Summary  string      `json:"summary"`
	Affected []osvAffect `json:"affected"`
}

type osvAffect struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Ranges []struct {
		Type   string              `json:"type"`
		Events []map[string]string `json:"events"`
	} `json:"ranges"`
}

type finding struct {
	OSV          string  `json:"osv"`
	FixedVersion string  `json:"fixed_version"`
	Trace        []frame `json:"trace"`
}

type frame struct {
	Module   string `json:"module,omitempty"`
	Version  string `json:"version,omitempty"`
	Package  string `json:"package,omitempty"`
	Function string `json:"function,omitempty"`
}

// called reports whether govulncheck found a call path to vulnerable code.
// Findings without one are either module-level (the module is in the build
// graph) or package-level (the package is imported).
func (f finding) called() bool {
	return len(f.Trace) > 0 && f.Trace[0].Function != ""
}

func (f finding) where() string {
	if len(f.Trace) == 0 || f.Trace[0].Package == "" {
		return "module level"
	}
	t := f.Trace[0]
	if t.Function == "" {
		return t.Package
	}
	return t.Package + "." + t.Function
}

type scan struct {
	scanner   string
	toolchain string // the Go version govulncheck scanned, e.g. "go1.25.0"
	findings  []finding
	entries   map[string]*osvEntry
}

type scanMsg struct {
	OSV     *osvEntry `json:"osv"`
	Finding *finding  `json:"finding"`
	Config  *struct {
		ScannerName    string `json:"scanner_name"`
		ScannerVersion string `json:"scanner_version"`
		GoVersion      string `json:"go_version"`
	} `json:"config"`
	SBOM *struct {
		GoVersion string `json:"go_version"`
	} `json:"SBOM"`
}

// scanVulns runs govulncheck over pkgs and parses its JSON stream. A non-zero
// exit status is not an error: govulncheck exits 3 when it finds something.
func scanVulns(r *runner, govulncheckPath string, pkgs []string) (*scan, error) {
	name, args := govulncheckInvocation(r, govulncheckPath)
	args = append(append(args, "-json"), pkgs...)

	cmd := exec.Command(name, args...)
	cmd.Dir = r.dir
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("running %s: %w", name, err)
	}

	s, perr := parseScan(stdout)
	if perr != nil {
		_ = cmd.Wait()
		return nil, perr
	}
	if err := cmd.Wait(); err != nil {
		if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 3 {
			msg := strings.TrimSpace(stderr.String())
			if msg == "" {
				msg = err.Error()
			}
			return nil, fmt.Errorf("govulncheck failed: %s", firstLines(msg, 20))
		}
	}
	return s, nil
}

// parseScan reads a govulncheck -json stream.
func parseScan(r io.Reader) (*scan, error) {
	s := &scan{entries: map[string]*osvEntry{}}
	dec := json.NewDecoder(bufio.NewReaderSize(r, 1<<20))
	for {
		var m scanMsg
		if err := dec.Decode(&m); err == io.EOF {
			return s, nil
		} else if err != nil {
			return nil, fmt.Errorf("parsing govulncheck output: %w", err)
		}
		switch {
		case m.Config != nil:
			v := m.Config.ScannerVersion
			if !strings.HasPrefix(v, "v") {
				v = "v" + v
			}
			s.scanner = m.Config.ScannerName + "@" + v
			s.toolchain = m.Config.GoVersion
		case m.SBOM != nil && s.toolchain == "":
			s.toolchain = m.SBOM.GoVersion
		case m.OSV != nil:
			s.entries[m.OSV.ID] = m.OSV
		case m.Finding != nil:
			s.findings = append(s.findings, *m.Finding)
		}
	}
}

// govulncheckInvocation prefers the copy on PATH, then falls back to running
// the latest release with "go run" so that an old local binary cannot produce
// stale results.
func govulncheckInvocation(r *runner, override string) (string, []string) {
	if override != "" {
		return override, nil
	}
	if p, err := exec.LookPath("govulncheck"); err == nil {
		return p, nil
	}
	r.note("no govulncheck on PATH, using go run golang.org/x/vuln/cmd/govulncheck@latest")
	return "go", []string{"run", "golang.org/x/vuln/cmd/govulncheck@latest"}
}

type modChange struct {
	module string
	from   string
	to     string
	osvs   []string
}

type toolchainChange struct {
	from string
	to   string
	osvs []string
}

type plan struct {
	findings  int // distinct advisories to fix
	called    int // of those, how many have a call path
	skipped   int // findings left alone by -reachable
	modules   []modChange
	toolchain *toolchainChange
	notes     []string
}

// buildPlan works out the smallest set of bumps that clears the findings: one
// module bump per affected module, plus a toolchain bump for standard library
// findings, each to the lowest fixed version above what the build uses.
func buildPlan(s *scan, b *build, reachableOnly bool) *plan {
	p := &plan{}

	// One bump per module has to clear every advisory for it, so keep the
	// highest of the per-advisory minimum fixed versions.
	target := map[string]version{}
	osvs := map[string][]string{}
	unfixable := map[string]bool{}
	seen := map[string]bool{}

	for _, f := range s.findings {
		if reachableOnly && !f.called() {
			if !seen[f.OSV] {
				seen[f.OSV] = true
				p.skipped++
			}
			continue
		}
		if !seen[f.OSV] {
			seen[f.OSV] = true
			p.findings++
			if f.called() {
				p.called++
			}
		}
		entry := s.entries[f.OSV]
		if entry == nil {
			unfixable[f.OSV] = true
			continue
		}
		mod, cur := b.affectedModule(f, entry)
		if mod == "" {
			unfixable[f.OSV] = true
			continue
		}
		curVer, ok := parseVersion(cur)
		if !ok {
			unfixable[f.OSV] = true
			continue
		}
		fixed, ok := nextFixed(entry, mod, curVer)
		if !ok {
			unfixable[f.OSV] = true
			continue
		}
		if t, dup := target[mod]; !dup || compareVersion(fixed, t) > 0 {
			target[mod] = fixed
		}
		if !contains(osvs[mod], f.OSV) {
			osvs[mod] = append(osvs[mod], f.OSV)
		}
	}

	mods := make([]string, 0, len(target))
	for m := range target {
		mods = append(mods, m)
	}
	sort.Strings(mods)

	for _, mod := range mods {
		v := target[mod]
		list := dedupe(osvs[mod])
		if mod == "stdlib" {
			p.toolchain = &toolchainChange{
				from: b.toolchainVersion(),
				to:   "go" + v.String(),
				osvs: list,
			}
			continue
		}
		// A replace directive decides what is built, so bumping the require
		// line would not change the compiled code.
		if why, ok := b.replaced[mod]; ok {
			p.notes = append(p.notes, fmt.Sprintf(
				"%s: replaced by %s in go.mod; fixed by editing the replace directive, since a version bump would not change what is built",
				mod, why))
			continue
		}
		cur, _ := parseVersion(b.modules[mod])
		// A fix in a new major version is a code change, not a bump: the
		// module path itself would have to change.
		if v.major != cur.major && moduleMajor(mod) == 0 && cur.major < 2 {
			p.notes = append(p.notes, fmt.Sprintf(
				"%s: the only fix is v%s, a new major version; skipping (needs a code change and a module path change)",
				mod, v.String()))
			continue
		}
		p.modules = append(p.modules, modChange{
			module: mod,
			from:   b.modules[mod],
			to:     "v" + v.String(),
			osvs:   list,
		})
	}

	for id := range unfixable {
		p.notes = append(p.notes, fmt.Sprintf("%s: no fixed version applies to this build; skipped", id))
	}
	sort.Strings(p.notes)
	return p
}

// affectedModule finds the module a finding belongs to and the version of it
// in the current build.
func (b *build) affectedModule(f finding, e *osvEntry) (string, string) {
	if len(f.Trace) > 0 && f.Trace[0].Module != "" {
		m := f.Trace[0].Module
		if m == "stdlib" {
			return "stdlib", b.toolchainVersion()
		}
		if v, ok := b.modules[m]; ok {
			return m, v
		}
		return m, f.Trace[0].Version
	}
	// No trace: the advisory names the affected module.
	for _, a := range e.Affected {
		switch name := a.Package.Name; name {
		case "stdlib":
			return "stdlib", b.toolchainVersion()
		case "":
		default:
			if v, ok := b.modules[name]; ok {
				return name, v
			}
		}
	}
	return "", ""
}

// nextFixed returns the lowest "fixed" version in the advisory for module that
// is above cur, taken only from a range that actually contains cur. The same
// advisory can list several fix ranges, one per release branch.
func nextFixed(e *osvEntry, module string, cur version) (version, bool) {
	var best version
	found := false
	for _, a := range e.Affected {
		if !sameModule(module, a.Package.Name) {
			continue
		}
		for _, rg := range a.Ranges {
			active := true // affected from the beginning until the first event
			for _, ev := range rg.Events {
				if s, ok := ev["introduced"]; ok {
					if v, ok := parseVersion(s); ok {
						active = compareVersion(v, cur) <= 0
					}
				}
				if s, ok := ev["fixed"]; ok {
					if !active {
						continue
					}
					active = false
					v, ok := parseVersion(s)
					if !ok || compareVersion(v, cur) <= 0 {
						continue
					}
					if !found || compareVersion(v, best) < 0 {
						best, found = v, true
					}
				}
				if _, ok := ev["last_affected"]; ok {
					active = false
				}
			}
		}
	}
	return best, found
}

func sameModule(module, pkg string) bool {
	if module == "stdlib" {
		return pkg == "stdlib"
	}
	return pkg == module
}

func dedupe(in []string) []string {
	sort.Strings(in)
	out := in[:0]
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func (p *plan) empty() bool {
	return len(p.modules) == 0 && p.toolchain == nil
}
