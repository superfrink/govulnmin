# Changelog

## v0.1.0 — 2026-11-24

First release.

- Scans a Go module with govulncheck, bumps affected modules and the
  toolchain to the lowest versions that fix each finding, then proves the
  result with go build, go test and a second scan.
- Default analysis is reachable-only, matching govulncheck; `-all` also
  fixes findings with no call path.
- Dry run (`-n`) exits 1 when there is something to fix; advisories with
  no applicable fix exit 1 too.
- Replaced modules are reported instead of bumped: editing the replace
  directive is the only thing that changes what gets built.
- Exit 0 means clean, 1 means work remains, 2 means error.
- Release binaries are signed with cosign (keyless, sigstore bundle) and
  attested by the release workflow; see "Verifying a release" in README.md.
