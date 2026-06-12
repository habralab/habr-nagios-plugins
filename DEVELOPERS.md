# Developer Notes

## Purpose

This repository is intended to host a family of small, self-contained monitoring binaries.

Primary use case:

- run from Nagios, Icinga, LibreNMS service checks, or similar schedulers
- return a compact one-line status with a correct exit code
- provide progressively deeper diagnostics through verbosity flags

The project is intentionally biased toward:

- static binary delivery where practical
- low operational complexity
- predictable CLI behavior
- safe failure modes for monitoring
- separate binaries per probe, with only needed code linked into each one

Severity across all probes should aggregate to:

- `OK`: no findings
- `WARNING`: degraded but still partially useful state
- `CRITICAL`: broken or unsafe state
- `UNKNOWN`: plugin or invocation problem

## Why Go

Go is the default implementation language for this repository because it optimizes for delivery speed and operational simplicity:

- easy self-contained binaries
- straightforward cross-compilation
- good standard library for CLI and network-heavy systems tools
- low maintenance burden for small operational utilities

## Repository Architecture

Current layout:

- `cmd/<probe>`: thin binary entrypoints
- `internal/app/<probe>`: CLI parsing and command wiring
- `internal/probe/<probe>`: probe implementation
- `internal/core/...`: shared building blocks
- `internal/probe/<probe>/testdata`: local fixtures for no-network tests

Internal flow:

1. A binary in `cmd/...` calls its matching app module.
2. The app module parses CLI flags into a probe config.
3. The probe resolves its target and runs domain-specific checks.
4. Findings are created through shared policy modules.
5. Output is rendered as a compact summary or a more verbose diagnostic report.

## Modular Direction

The intended long-term shape is:

- `cmd/<probe>`: one binary per probe
- `internal/app/<probe>`: CLI wiring for that probe
- `internal/probe/<probe>`: domain-specific check logic
- `internal/core/...`: reusable building blocks shared across probes

Important constraints:

- each final binary must remain self-contained
- each binary should link only the modules it imports
- no global runtime plugin loader
- no auto-registration through blank imports
- no monolithic mega-binary as the primary deployment model

This keeps deployment simple:

- build one binary
- copy one binary
- run one binary

## Build System

The root `Makefile` is intentionally generic.

Current behavior:

- discovers binaries from `cmd/*/main.go`
- treats the `cmd/` directory name as the probe slug
- builds each discovered probe into `build/check_<slug>`
- uses a release-oriented default build with `-trimpath` and stripped ldflags
- keeps a separate `build-debug` target for local symbol-rich binaries
- cross-builds each discovered binary for the supported target matrix
- keeps Go cache local to the repository through `.gocache/`
- keeps module cache local to the repository through `.gomodcache/`
- injects build metadata into binaries, using repository state when available

This is important for the intended growth model:

- adding a new probe should usually mean adding a new `cmd/<probe>/main.go`
- the main `make build` and `make cross` flows should start including it automatically
- existing binaries should not require manual Makefile duplication per probe

If a probe eventually needs custom packaging, that should be added without breaking the generic default path for ordinary binaries.

## Version Metadata

Binary version output should come from build-time metadata, not hardcoded constants inside probe apps.

Current policy:

- if `HEAD` is exactly on a git tag, use that tag as the version
- otherwise use the current branch name when available
- if git metadata is unavailable or `HEAD` is detached, fall back to `dev`
- always append the short commit hash when available
- append `-dirty` to the commit hash when the worktree is not clean

Examples:

- `check_example v0.1.0 (abc123def456)`
- `check_example main (abc123def456)`
- `check_example dev (abc123def456-dirty)`

Implementation rule:

- shared formatting lives in `internal/core/buildinfo`
- build metadata is injected by `Makefile` through `go build -ldflags`
- probe binaries should only ask the shared module for a display string

## Shared Core

Shared modules should stay narrow and reusable.

Likely core areas:

- probe metadata and naming policy
- finding catalog and suppression policy
- HTTP client and tracing helpers
- DNS helpers
- TLS helpers
- output rendering

Probe-specific logic should stay out of shared modules until there is a real second consumer.

The current HTTP/TLS transport options are intended to converge in shared modules rather than being redefined per probe.

Current direction:

- shared client construction lives in `internal/core/httpx`
- shared HTTP/TLS-related help text should live near that module
- probe apps should aggregate shared and probe-local flags into one help output
- shared options should appear in a stable order in CLI help

## Probe Identity And Naming

Each probe should have a stable internal identity based on a slug.

Current example:

- slug: `example`

The slug is the canonical probe identity and should be used for:

- package paths
- probe metadata
- package naming
- future release asset naming

Binary names are deployment-specific and should be derived from metadata rather than hardcoded ad hoc in multiple places.

Current convention:

- `cmd/<slug>` is the canonical CLI entrypoint path
- default local/developer binary name: `check_<slug>`
- shared/system install binary name: `check_<vendor>_<slug>`
- Debian package name: `<vendor>-nagios-plugin-<slug>`

Current example values for example:

- dev binary: `check_example`
- namespaced install binary: `check_habr_example`
- package name: `habr-nagios-plugin-example`

Implementation rule:

- generic naming helpers live in `internal/core/probemeta`
- probe-local metadata lives near the probe, e.g. `internal/probe/example/meta.go`
- CLI help, version output, and later packaging helpers should read from probe metadata instead of duplicating names

## Deliberate Constraints

The repository should stay conservative by default:

- no third-party dependencies unless they remove real risk or complexity
- no global plugin loader
- no blank-import registration model
- no hidden runtime dependency on external services
- no assumption that every probe needs every shared module

This keeps final binaries easy to audit, move, and run.

## Testing Direction

Tests should prefer local and deterministic coverage:

- fixture-driven parsing tests
- mock transport tests for HTTP-facing probes
- no-network unit tests by default
- integration tests only where they add real confidence

For HTTP-heavy probes, both styles are useful:

- mock transport tests for precise error classification and summary/detail assertions
- opt-in live tests with a lightweight local HTTP server for redirects, headers, and parser behavior under real `net/http`

Each new probe should reserve a place for:

- package-local unit tests
- `testdata/` fixtures when format-heavy parsing exists
- mockable transport or resolver interfaces where external I/O is involved

The root `Makefile` may expose a separate target for opt-in integration suites, such as `test-live`, when those tests require a local listener and are not safe in every sandboxed environment.

## CLI Philosophy

Each binary should stay small and predictable.

Expected Nagios-style flags for concrete probes:

- `-H/--hostname`
- `-u/--url`
- `-t/--timeout`
- `-v/--verbose`
- `-h/--help`
- `-V/--version`

CLI design principles:

- sane defaults
- explicit strictness toggles
- bounded resource usage
- stable exit code mapping
- compact primary output with optional deeper diagnostics

Concrete probe flags should be documented alongside each binary once they exist.

If a probe uses shared HTTP/TLS options, the shared flag descriptions should stay attached to the shared module and be rendered into the final help text rather than duplicated manually across probe apps.

## Build and Release Expectations

This project should remain easy to build on macOS and Linux, and easy to cross-compile for:

- `linux/386`
- `linux/amd64`
- `linux/arm`
- `linux/arm64`
- `darwin/amd64`
- `darwin/arm64`

Preferred outcome:

- one repository
- shared internal modules
- multiple independent binaries
- no unnecessary code pulled into a given final artifact

Build-size expectation:

- production-facing binaries should default to stripped builds
- debug symbols should be opt-in for local development
- if a binary becomes unexpectedly large, inspect sections and symbols before guessing

## Documentation Split

Keep public and developer-facing documentation separate:

- `README.md`: repository purpose, current probes, basic build commands, release-facing overview
- `DEVELOPERS.md`: architecture, module boundaries, build model, testing expectations, future extension rules

When adding a new probe, update both only where it changes repository-level understanding. Detailed probe behavior belongs near the probe code or in probe-specific docs later.
