# govulnmin

[![ci](https://github.com/superfrink/govulnmin/actions/workflows/ci.yml/badge.svg)](https://github.com/superfrink/govulnmin/actions/workflows/ci.yml)
[![vulncheck](https://github.com/superfrink/govulnmin/actions/workflows/vulncheck.yml/badge.svg)](https://github.com/superfrink/govulnmin/actions/workflows/vulncheck.yml)

Fixes Go vulnerabilities with the smallest version bump that clears them, then proves the fix.

`govulncheck` tells you what is vulnerable. Most of the time the answer is a version bump, and most of the time you want the *smallest* one: the lowest release that contains the fix, not the latest release of everything. govulnmin works that out and applies it.

## What it does

1. Runs `govulncheck` over the packages you name (default `./...`) and reads the JSON output.
2. Works out the lowest fixed version for each affected module, and for standard library findings the lowest fixed Go release. Versions are read from the advisory's own ranges, not from govulncheck's `fixed_version` field, which reports the fix in the *latest* range and can be several releases too high.
3. Bumps the toolchain first with `go mod edit -toolchain`, then runs one `go get` for the modules and `go mod tidy`.
4. Runs `go build` and `go test` over the same packages.
5. Scans again. Anything that survives is listed, and the exit status is 1.

With `-n` it stops after step 2: it prints the plan, changes nothing, and exits 1 if the plan is not empty. So a plain `govulnmin -n` is a vulnerability check you can put in CI.

## Exit status

| code | meaning |
| --- | --- |
| `0` | nothing to do, or the fixes were applied and the rescan came back clean |
| `1` | advisories remain: a dry run with work to do, an advisory with no applicable fix, or a finding that survived the fix |
| `2` | error: bad flags, a failed scan, a failed `go get` or `go mod tidy`, or a failed build or test |

Exit 2 is a tool-level error, so it never means "nothing happened". A failed build or test leaves the tree modified; see below.

## When the build or the tests fail

Nothing is reverted. The bumps are already in go.mod by the time the build runs, so a failure stops there, exits 2, and leaves go.mod, go.sum and the rest of the tree exactly as govulnmin left them — new versions included — for you to look at:

```
$ govulnmin
scanning example.com/fx with go1.25.0
scanner: govulncheck@v1.8.0
1 advisory(s), 1 with a call path

  golang.org/x/text  v0.3.0 -> v0.3.7  (GO-2021-0113)
$ go get golang.org/x/text@v0.3.7
go: upgraded golang.org/x/text v0.3.0 => v0.3.7
$ go mod tidy
$ go build ./...
./fx.go:3:24: cannot use "boom" (untyped string constant) as int value
govulnmin: exit status 1

the version bumps are still in go.mod; check the diff with "git diff go.mod go.sum"
```

```
git diff go.mod go.sum      # what changed
git restore go.mod go.sum   # put it back
```

What the diff contains is decided by `go get` and `go mod tidy`, not just by the plan. go.sum is rewritten; tidy can add indirect requirements or drop a require line that nothing imports any more; if only the toolchain was bumped, that directive is all that moves. If `go get` itself fails, the toolchain bump that ran before it is still in go.mod.

Two consequences worth knowing:

- govulnmin starts from the tree in front of it, not from HEAD. A dirty go.mod after a failure changes the next run's starting point, so restore it before trying again.
- A failed build or test does not mean the bump was wrong. It means the new version did not compile or did not pass. Read the error before reaching for `git restore`.

## Install

```
go install github.com/superfrink/govulnmin@latest
```

Or take a binary from [releases](https://github.com/superfrink/govulnmin/releases).

It needs `govulncheck`. If that is not on your PATH, govulnmin runs `go run golang.org/x/vuln/cmd/govulncheck@latest`, so the scan is never done by a stale copy. That is a deliberate exception to pinning; CI pins the version instead.

## Verifying a release

Releases are signed and attested. No account and no key needed to check them:

```
# 1. Check the signature on the checksum list.
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/superfrink/govulnmin/.github/workflows/release.yml@refs/tags/v.+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

# 2. Check your download against the signed list.
sha256sum -c --ignore-missing checksums.txt

# 3. Check which commit and workflow run built the file.
gh attestation verify govulnmin_0.1.0_linux_amd64.tar.gz --repo superfrink/govulnmin
```

Signing is keyless: cosign takes a short-lived certificate from Fulcio, issued to the workflow itself, and records the signing in the Rekor transparency log. That certificate cannot be produced by anything but a run of `.github/workflows/release.yml` in this repository on a `v*` tag, which is what ties the signature to the code: the attestation pins the commit SHA, `go version -m govulnmin` prints the same revision embedded in the binary, and the build is reproducible (`-trimpath`, commit timestamps), so a tag can be rebuilt and the hashes compared.

## Use

```
govulnmin            # fix this module
govulnmin -n         # dry run: show the plan, change nothing, exit 1 if there is work
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

dry run: no changes made, 2 change(s) needed
```

Flags:

| flag | meaning |
| --- | --- |
| `-n` | dry run: print the plan, change nothing, exit 1 if there is something to fix |
| `-reachable` | only fix findings with a call path, instead of every finding |
| `-no-modules` | leave module versions alone |
| `-no-toolchain` | leave the go and toolchain directives alone |
| `-dir` | module directory (default `.`) |
| `-govulncheck` | govulncheck binary to use |
| `-v` | echo each command |

## What "smallest" means

An advisory can list several fix ranges, one per release branch:

```json
{"introduced": "0"},      {"fixed": "1.26.11"},
{"introduced": "1.27.0"}, {"fixed": "1.27.4"}
```

Only the range that contains your current version counts, so a build on Go 1.25 gets 1.26.11, not 1.27.4. The same applies to modules: x/text 0.3.0 gets the lowest release that clears *every* advisory for x/text, which can still be a big jump if several old advisories share one fix.

Two cases are reported instead of applied:

- **A new major version.** If the only fix is v3 of a module you use at v1, that is a code change and a module path change, not a bump. govulnmin skips it and says so.
- **No fix.** Some advisories have no fixed release yet. They are listed, not applied, and the exit status is 1: the module is still vulnerable.

## Library or application

For an application, bumping the toolchain is what you want. For a library, `go mod edit -toolchain=...` pins the patch release your consumers will use, which is usually fine but is a decision you should make consciously: `-no-toolchain` turns it off, and the plan still tells you which Go release you need.

## Run it on a branch

govulnmin edits go.mod and go.sum in place, and does not roll them back when a build or test fails. Start from a clean tree:

```
git switch -c vuln-fix
govulnmin -n
govulnmin
git diff go.mod go.sum
```

If the build or the tests fail, the diff is still there to read; `git restore go.mod go.sum` discards it.

## Limitations

### It only knows about go.mod

govulnmin fixes the module in `-dir`: the `go`, `toolchain` and `require` lines, and go.sum. A Go version is usually pinned in several more places, and it touches none of them:

- `FROM golang:1.21` in a Dockerfile, and any `--build-arg GO_VERSION=`
- `go-version:` in CI workflows, and the go versions in a test matrix
- `.tool-versions`, `mise.toml`, `asdf`, `goenv`, a Makefile default, a devcontainer image
- `golang:` image tags in docker-compose or Helm values

Bumping the toolchain for a Dockerfile means editing the Dockerfile by hand after govulnmin tells you which release you need.

Also not covered:

- **Nested modules and workspaces.** One module per run, the one in `-dir`. Sibling modules listed in a `go.work` are left alone; run it once per module.
- **`vendor/`.** govulnmin runs `go get` and `go mod tidy`, never `go mod vendor`. In a vendored repo the build after a bump fails with `inconsistent vendoring`; run `go mod vendor` and commit the result.
- **`replace` directives.** govulnmin reads the *replacement's* version, since the replacement is what gets compiled. A replaced module is reported, never bumped: bumping the require line would not change what is built, so the note names the replacement and you edit the directive by hand.
- **Code changes.** govulnmin moves versions. If an advisory needs a new major version, an API change, or work in your own code, it reports it and stops.
- **One build configuration.** `go build ./...` and `go test ./...` run on the host platform, with no build tags, so platform-specific files and tag-gated code are not compiled. A bump can still break them.

### Versions have to be semver

Go module versions are always semver, a pseudo-version (`v0.0.0-20200101120000-abcdef123456`) or `vX.Y.Z+incompatible`, and govulnmin parses all three. Build metadata is ignored, a pre-release sorts below its release, and `gopkg.in`'s `.vN` and module paths ending in `/vN` are recognised as majors.

Anything else is not understood. If an advisory's `fixed` value will not parse as a version, that advisory is skipped with a note and the exit status stays 1, so nothing is silently dropped. One soft spot: a pseudo-version is compared as the pre-release of its base version, which orders it correctly against tagged releases but can be slightly off when two pseudo-versions are compared to each other. This is rare, since advisories list tagged fixes.

### It is only as complete as govulncheck

Findings come from `govulncheck`'s symbol-level analysis. Calls that only happen through reflection, `unsafe`, plugins or generated wrappers can be missed, and by default govulnmin fixes findings with and without a call path (`-reachable` narrows it to the ones it can trace). A clean exit means govulncheck is clean, not that the program is safe.

## Build and test

```
go test ./...            # unit tests, plus end-to-end dry runs against a fake govulncheck
go vet ./...
gofmt -l .
```

CI runs those on Go 1.22 and stable, cross-compiles linux/darwin/windows on amd64 and arm64, and validates `.goreleaser.yaml`. Pushing a `v*` tag builds the release binaries on a pinned Go patch, signs `checksums.txt` with cosign and attests the provenance of every upload.

The workflows pin each action to a commit SHA (the tag is in the comment), and pin `goreleaser`, `govulncheck` and cosign to exact versions: those run before anything is verified, so what they do should not change without a commit.

## License

BSD 3-Clause. See [LICENSE](LICENSE).
