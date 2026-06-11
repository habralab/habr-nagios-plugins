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
- `internal/app/<probe>cmd`: CLI parsing and command wiring
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
- `internal/app/<probe>cmd`: CLI wiring for that probe
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

## Shared Core

Shared modules should stay narrow and reusable.

Likely core areas:

- finding catalog and suppression policy
- HTTP client and tracing helpers
- DNS helpers
- TLS helpers
- output rendering

Probe-specific logic should stay out of shared modules until there is a real second consumer.

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

Each new probe should reserve a place for:

- package-local unit tests
- `testdata/` fixtures when format-heavy parsing exists
- mockable transport or resolver interfaces where external I/O is involved

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
