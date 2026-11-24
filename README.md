# govulnmin

[![ci](https://github.com/superfrink/govulnmin/actions/workflows/ci.yml/badge.svg)](https://github.com/superfrink/govulnmin/actions/workflows/ci.yml)
[![vulncheck](https://github.com/superfrink/govulnmin/actions/workflows/vulncheck.yml/badge.svg)](https://github.com/superfrink/govulnmin/actions/workflows/vulncheck.yml)

Fixes Go vulnerabilities with the smallest version bump that clears them, then proves the fix.

`govulncheck` tells you what is vulnerable. Most of the time the answer is a version bump, and most of the time you want the *smallest* one: the lowest release that contains the fix, not the latest release of everything. govulnmin works that out and applies it.

## What it does

1. Runs `govulncheck` and reads the JSON output.
2. For each affected module, takes the lowest fixed version above the one in your build, and for standard library findings, the lowest fixed Go release. Go versions are read from the advisory's own ranges, not from govulncheck's `fixed_version` field, which reports the fix in the *latest* range and can be several releases too high.
3. Bumps the toolchain first, then runs one `go get` for the modules and `go mod tidy`.
4. Runs `go build ./...` and `go test ./...`.
5. Scans again. If anything is still there, it says so and exits non-zero.

If the build or the tests fail, go.mod and go.sum are left as they are so you can inspect the diff.

## Install

```
go install github.com/superfrink/govulnmin@latest
```

Or take a binary from [releases](https://github.com/superfrink/govulnmin/releases).

It needs `govulncheck`. If that is not on your PATH, govulnmin runs the latest one with `go run`, so the scan is never done by a stale copy.

## Use

```
govulnmin            # fix this module
govulnmin -n         # dry run: show the plan, change nothing
govulnmin ./cmd/...  # limit the scan
```

Typical output:

```
$ govulnmin -n
scanning github.com/you/thing with go1.25.0
scanner: govulncheck@v1.8.0
66 advisory(s), 3 with a call path

  toolchain  go1.25.0 -> go1.26.11  (GO-2025-3955, GO-2025-4006, GO-2025-4007 and 58 more)
             no fix exists for Go 1.25; the lowest fixed release is go1.26.11
  golang.org/x/text  v0.3.0 -> v0.41.0  (GO-2020-0015, GO-2021-0113, GO-2022-1059 and 2 more)

dry run: no changes made
```

Flags:

| flag | meaning |
| --- | --- |
| `-n` | dry run |
| `-reachable` | only fix findings with a call path, instead of every finding |
| `-no-modules` | leave module versions alone |
| `-no-toolchain` | leave the go and toolchain directives alone |
| `-dir` | module directory (default `.`) |
| `-govulncheck` | govulncheck binary to use |
| `-v` | echo each command |

Exit status: `0` fixed or already clean, `1` vulnerabilities remain, `2` error (including a failed build or test).

## What "smallest" means

An advisory can list several fix ranges, one per release branch:

```json
{"introduced": "0"},      {"fixed": "1.26.11"},
{"introduced": "1.27.0"}, {"fixed": "1.27.4"}
```

Only the range that contains your current version counts, so a build on Go 1.25 gets 1.26.11, not 1.27.4. The same applies to modules: x/text 0.3.0 gets the lowest release that clears *every* advisory for x/text, which can still be a big jump if several old advisories share one fix.

Two cases are reported instead of applied:

- **A new major version.** If the only fix is v3 of a module you use at v1, that is a code change and a module path change, not a bump. govulnmin skips it and says so.
- **No fix.** Some advisories have no fixed release yet. They are listed, not applied.

## Library or application

For an application, bumping the toolchain is what you want. For a library, `go mod edit -toolchain=...` pins the patch release your consumers will use, which is usually fine but is a decision you should make consciously: `-no-toolchain` turns it off, and the plan still tells you which Go release you need.

## Run it on a branch

govulnmin edits go.mod and go.sum in place. Start from a clean tree:

```
git switch -c vuln-fix
govulnmin -n
govulnmin
```

If the build or tests fail, nothing is reverted:

```
git diff go.mod go.sum
git restore go.mod go.sum
```

## Build and test

```
go test ./...            # unit tests, plus end-to-end dry runs against a fake govulncheck
go vet ./...
gofmt -l .
```

CI runs those on Go 1.22 and stable, cross-compiles linux/darwin/windows on amd64 and arm64, and validates `.goreleaser.yaml`. Pushing a `v*` tag builds the release binaries.

## License

BSD 3-Clause. See [LICENSE](LICENSE).
