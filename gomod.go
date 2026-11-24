package main

import (
	"encoding/json"
	"fmt"
	"io"
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
	replaced map[string]string // module path -> what go.mod replaces it with
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
		Replace []struct {
			Old struct{ Path, Version string }
			New struct{ Path, Version string }
		}
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, fmt.Errorf("parsing go.mod: %w", err)
	}
	b := &build{
		path:     raw.Module.Path,
		goVer:    raw.Go,
		toolVer:  raw.Toolchain,
		modules:  map[string]string{},
		replaced: map[string]string{},
	}
	if b.goVer == "" {
		return nil, fmt.Errorf("go.mod has no go directive")
	}

	if out, err := r.output("go", "env", "GOVERSION"); err == nil {
		b.resolved = strings.TrimSpace(out)
	}

	// The build list is the truth about which version of a module is
	// actually compiled, which can be higher than the go.mod require line
	// and lower than it when a replace directive pins the module back.
	mods, err := listModules(r)
	if err != nil {
		// Usually a missing go.sum entry in a read-only module. The require
		// lines still tell us what version of each module would be used.
		r.note("go list -m all failed, using the require lines in go.mod: %v", err)
		replaces := map[string]struct{ path, version string }{}
		for _, rep := range raw.Replace {
			replaces[rep.Old.Path] = struct{ path, version string }{rep.New.Path, rep.New.Version}
		}
		for _, req := range raw.Require {
			b.modules[req.Path] = req.Version
			if rep, ok := replaces[req.Path]; ok {
				b.replaced[req.Path] = describeReplace(rep.path, rep.version, "")
				// The require line is not what gets built.
				if rep.version == "" {
					delete(b.modules, req.Path)
				} else {
					b.modules[req.Path] = rep.version
				}
			}
		}
		b.modules[b.path] = ""
		return b, nil
	}
	for _, m := range mods {
		if m.Main || m.Path == b.path || m.Version == "" {
			continue
		}
		version := m.Version
		if m.Replace != nil {
			// go.mod replaces this module: the replacement is what is built,
			// and its version is the one that has to be clear of advisories.
			b.replaced[m.Path] = describeReplace(m.Replace.Path, m.Replace.Version, m.Replace.Dir)
			version = m.Replace.Version
			if version == "" {
				// Replaced by a directory: there is no version to compare.
				continue
			}
		}
		b.modules[m.Path] = version
	}
	if b.path != "" {
		b.modules[b.path] = ""
	}
	return b, nil
}

// listedModule is the part of "go list -m -json" that matters here.
type listedModule struct {
	Path    string
	Version string
	Main    bool
	Replace *struct {
		Path    string
		Version string
		Dir     string
	}
}

func listModules(r *runner) ([]listedModule, error) {
	out, err := r.output("go", "list", "-m", "-json", "all")
	if err != nil {
		return nil, err
	}
	var mods []listedModule
	dec := json.NewDecoder(strings.NewReader(out))
	for {
		var m listedModule
		if err := dec.Decode(&m); err == io.EOF {
			return mods, nil
		} else if err != nil {
			return nil, fmt.Errorf("parsing go list -m output: %w", err)
		}
		mods = append(mods, m)
	}
}

// describeReplace says what a replace directive points at, for a note.
func describeReplace(path, version, dir string) string {
	switch {
	case version != "":
		return path + " " + version
	case dir != "":
		return "a local directory " + dir
	case path != "":
		return path
	}
	return "another version"
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
