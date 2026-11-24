package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// build is the state of the module being fixed: its go.mod versions and the
// module versions currently selected by the build list.
type build struct {
	path     string
	goVer    string            // go directive, e.g. "1.22" (always present)
	toolVer  string            // toolchain directive, e.g. "go1.25.0" (optional)
	resolved string            // toolchain actually in use, e.g. "go1.25.0"
	modules  map[string]string // module path -> version, from the build list
}

// toolchainVersion is the Go version the binary is built with: the toolchain
// in effect for this module, which is what govulncheck scans the standard
// library as.
func (b *build) toolchainVersion() string {
	if b.resolved != "" {
		return b.resolved
	}
	if b.toolVer != "" {
		return b.toolVer
	}
	return "go" + b.goVer
}

func readBuild(r *runner) (*build, error) {
	out, err := r.output("go", "mod", "edit", "-json")
	if err != nil {
		return nil, fmt.Errorf("reading go.mod: %w", err)
	}
	var raw struct {
		Module    struct{ Path string }
		Go        string
		Toolchain string
		Require   []struct {
			Path    string
			Version string
		}
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, fmt.Errorf("parsing go.mod: %w", err)
	}
	b := &build{
		path:    raw.Module.Path,
		goVer:   raw.Go,
		toolVer: raw.Toolchain,
		modules: map[string]string{},
	}
	if b.goVer == "" {
		return nil, fmt.Errorf("go.mod has no go directive")
	}

	if out, err := r.output("go", "env", "GOVERSION"); err == nil {
		b.resolved = strings.TrimSpace(out)
	}

	// The build list is the truth about which version of a module is
	// actually compiled, which can be higher than the go.mod require line.
	out, err = r.output("go", "list", "-m", "-f", "{{.Path}} {{.Version}}", "all")
	if err != nil {
		// Usually a missing go.sum entry in a read-only module. The require
		// lines still tell us what version of each module would be used.
		r.note("go list -m all failed, using the require lines in go.mod: %v", err)
		for _, req := range raw.Require {
			b.modules[req.Path] = req.Version
		}
		b.modules[b.path] = ""
		return b, nil
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || f[1] == "" {
			continue
		}
		b.modules[f[0]] = f[1]
	}
	if b.path != "" {
		b.modules[b.path] = ""
	}
	return b, nil
}

// runner runs commands in the module directory.
type runner struct {
	dir     string
	verbose bool
}

func (r *runner) note(format string, args ...any) {
	fmt.Fprintf(outW, "note: "+format+"\n", args...)
}

func (r *runner) cmdline(format string, args ...any) {
	fmt.Fprintf(outW, "$ "+format+"\n", args...)
}

func (r *runner) output(name string, args ...string) (string, error) {
	var sb strings.Builder
	cmd := exec.Command(name, args...)
	cmd.Dir = r.dir
	cmd.Stdout = &sb
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if r.verbose {
		r.cmdline("%s %s", name, strings.Join(args, " "))
	}
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return "", fmt.Errorf("%s: %s", err, firstLines(msg, 20))
		}
		return "", err
	}
	return sb.String(), nil
}

// run executes a command, streaming its output to the user's terminal.
func (r *runner) run(name string, args ...string) error {
	r.cmdline("%s %s", name, strings.Join(args, " "))
	cmd := exec.Command(name, args...)
	cmd.Dir = r.dir
	cmd.Stdout = outW
	cmd.Stderr = errW
	return cmd.Run()
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = append(lines[:n], "...")
	}
	return strings.Join(lines, "\n")
}
