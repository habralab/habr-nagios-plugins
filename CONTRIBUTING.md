# Contributing

## Scope

This repository hosts small, self-contained monitoring binaries with shared internal building blocks.

Please keep contributions aligned with these constraints:

- separate probe binaries under `cmd/probes/`
- internal helper tools under `cmd/tools/` when needed
- reusable shared logic under `internal/core/`
- domain-specific logic under `internal/probe/`
- static, portable binaries as a first-class goal

## Development

```bash
make build
make test
make cross
```

Tests should avoid external network calls by default. Prefer in-process mocks and `testdata/` fixtures.

## Changes

When adding a new probe:

1. add a thin binary in `cmd/probes/<name>`
2. add CLI wiring in `internal/app/<name>cmd`
3. add probe logic in `internal/probe/<name>`
4. reuse shared modules instead of duplicating transport, finding, or output logic

## Reporting

For bugs, include:

- command line used
- actual output
- expected output
- target URL or a minimal reproducer if sharing the real target is not possible
