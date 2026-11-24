// Command govulnmin fixes Go vulnerabilities with the smallest possible version
// bumps, then proves the fix worked.
//
// It runs govulncheck, works out the lowest fixed version for each affected
// module and for the Go toolchain, applies those bumps, runs go build and
// go test, and scans again. If any finding survives, it exits 1.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

const usage = `govulnmin - minimal-fix Go vulnerabilities

usage: govulnmin [flags] [packages]

It scans with govulncheck, bumps only to the lowest version that fixes each
finding, then runs go build, go test and a second scan to prove the result.

flags:
  -n              dry run: print the plan, change nothing
  -reachable      only fix findings with a call path, not every finding
  -no-modules     do not touch module versions
  -no-toolchain   do not touch the go/toolchain directives
  -dir string     module directory (default ".")
  -govulncheck s  govulncheck binary to use (default: the one on PATH,
                  falling back to "go run golang.org/x/vuln/cmd/govulncheck@latest")
  -v              echo each command

exit status: 0 fixed or clean, 1 vulnerabilities remain, 2 error
`

var (
	outW io.Writer = os.Stdout
	errW io.Writer = os.Stderr
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	fs := flag.NewFlagSet("govulnmin", flag.ContinueOnError)
	fs.SetOutput(errW)
	fs.Usage = func() { fmt.Fprint(errW, usage) }

	dryRun := fs.Bool("n", false, "dry run")
	reachable := fs.Bool("reachable", false, "only fix findings with a call path")
	noModules := fs.Bool("no-modules", false, "skip module fixes")
	noToolchain := fs.Bool("no-toolchain", false, "skip toolchain fixes")
	dir := fs.String("dir", ".", "module directory")
	gvc := fs.String("govulncheck", "", "govulncheck binary")
	verbose := fs.Bool("v", false, "verbose")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	pkgs := fs.Args()
	if len(pkgs) == 0 {
		pkgs = []string{"./..."}
	}

	r := &runner{dir: *dir, verbose: *verbose}
	code, err := fix(r, options{
		dryRun:      *dryRun,
		reachable:   *reachable,
		noModules:   *noModules,
		noToolchain: *noToolchain,
		govulncheck: *gvc,
		pkgs:        pkgs,
	})
	if err != nil {
		fmt.Fprintf(errW, "govulnmin: %v\n", err)
		if code == 0 {
			code = 2
		}
	}
	return code
}

type options struct {
	dryRun      bool
	reachable   bool
	noModules   bool
	noToolchain bool
	govulncheck string
	pkgs        []string
}

func fix(r *runner, o options) (int, error) {
	b, err := readBuild(r)
	if err != nil {
		return 2, err
	}

	fmt.Fprintf(outW, "scanning %s with %s\n", b.path, b.toolchainVersion())
	s, err := scanVulns(r, o.govulncheck, o.pkgs)
	if err != nil {
		return 2, err
	}
	if s.scanner != "" {
		fmt.Fprintf(outW, "scanner: %s\n", s.scanner)
	}

	p := buildPlan(s, b, o.reachable)
	if !o.reachable && p.findings > p.called {
		p.notes = append(p.notes,
			fmt.Sprintf("%d advisory(s) have no call path in this build; -reachable would skip them",
				p.findings-p.called))
	}
	if o.noToolchain {
		p.toolchain = nil
	}
	if o.noModules {
		p.modules = nil
	}

	if p.findings == 0 {
		if p.skipped > 0 {
			fmt.Fprintf(outW, "clean: no advisories with a call path (%d skipped by -reachable)\n", p.skipped)
		} else {
			fmt.Fprintln(outW, "clean: no advisories")
		}
		return 0, nil
	}
	fmt.Fprintf(outW, "%d advisory(s), %d with a call path\n", p.findings, p.called)
	if !p.empty() {
		printPlan(p)
	}
	printNotes(p)
	if p.empty() {
		fmt.Fprintln(outW, "nothing to bump")
		return 0, nil
	}

	if o.dryRun {
		fmt.Fprintln(outW, "\ndry run: no changes made")
		return 0, nil
	}

	if err := apply(r, p); err != nil {
		return 2, err
	}
	return verify(r, o)
}

func apply(r *runner, p *plan) error {
	// The toolchain first: a newer Go can change module selection, and it is
	// what compiles everything that follows.
	if p.toolchain != nil {
		if err := r.run("go", "mod", "edit", "-toolchain="+p.toolchain.to); err != nil {
			return fmt.Errorf("setting toolchain to %s: %w", p.toolchain.to, err)
		}
	}
	if len(p.modules) > 0 {
		args := []string{"get"}
		for _, m := range p.modules {
			args = append(args, m.module+"@"+m.to)
		}
		if err := r.run("go", args...); err != nil {
			return fmt.Errorf("updating modules: %w", err)
		}
		// go get may have picked up newer indirect requirements; tidy keeps
		// go.sum honest.
		if err := r.run("go", "mod", "tidy"); err != nil {
			return fmt.Errorf("go mod tidy: %w", err)
		}
	}
	return nil
}

func verify(r *runner, o options) (int, error) {
	if err := r.run("go", append([]string{"build"}, o.pkgs...)...); err != nil {
		return 2, fmt.Errorf("%w\n\nthe version bumps are still in go.mod; check the diff with \"git diff go.mod go.sum\"", err)
	}
	if err := r.run("go", append([]string{"test"}, o.pkgs...)...); err != nil {
		return 2, fmt.Errorf("%w\n\nthe version bumps are still in go.mod; check the diff with \"git diff go.mod go.sum\"", err)
	}

	fmt.Fprintln(outW, "rescanning")
	s, err := scanVulns(r, o.govulncheck, o.pkgs)
	if err != nil {
		return 2, err
	}
	left := 0
	seen := map[string]bool{}
	for _, f := range s.findings {
		if o.reachable && !f.called() {
			continue
		}
		if seen[f.OSV] {
			continue
		}
		seen[f.OSV] = true
		left++
		fmt.Fprintf(outW, "  %s  %s  %s\n", f.OSV, f.where(), f.FixedVersion)
	}
	if left > 0 {
		fmt.Fprintf(outW, "\n%d advisory(s) remain\n", left)
		return 1, nil
	}
	fmt.Fprintln(outW, "clean: 0 advisories")
	return 0, nil
}

func printPlan(p *plan) {
	fmt.Fprintln(outW)
	if p.toolchain != nil {
		fmt.Fprintf(outW, "  %s  %s -> %s  %s\n", "toolchain", p.toolchain.from, p.toolchain.to, osvList(p.toolchain.osvs))
		if from, ok := parseVersion(p.toolchain.from); ok {
			if to, ok := parseVersion(p.toolchain.to); ok && (from.major != to.major || from.minor != to.minor) {
				fmt.Fprintf(outW, "             no fix exists for Go %d.%d; the lowest fixed release is %s\n", from.major, from.minor, p.toolchain.to)
			}
		}
	}
	for _, m := range p.modules {
		fmt.Fprintf(outW, "  %s  %s -> %s  %s\n", m.module, m.from, m.to, osvList(m.osvs))
	}
}

// osvList keeps the column readable when an advisory covers many packages.
func osvList(ids []string) string {
	if len(ids) <= 3 {
		return "(" + strings.Join(ids, ", ") + ")"
	}
	return fmt.Sprintf("(%s and %d more)", strings.Join(ids[:3], ", "), len(ids)-3)
}

func printNotes(p *plan) {
	if len(p.notes) == 0 {
		return
	}
	fmt.Fprintln(outW)
	for _, n := range p.notes {
		fmt.Fprintf(outW, "note: %s\n", n)
	}
}
