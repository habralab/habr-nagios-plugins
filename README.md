# habr-nagios-plugins

Small self-contained monitoring plugins for Nagios, Icinga, LibreNMS, and similar systems.

Repository: `https://github.com/habralab/habr-nagios-plugins`

## Current State

- repository skeleton
- shared layout for future probe binaries
- project-level build and contribution scaffolding

The repository is still early, but the base structure is already aligned with a multi-binary monitoring toolkit.

## Goals

- separate binary per check type
- static or otherwise self-contained deliverables
- predictable Nagios-style CLI behavior
- minimal runtime dependencies

## Build

```bash
make build
```

This builds every binary that has an entrypoint at `cmd/*/main.go` into `build/`.

## Cross-build

```bash
make cross
```

## Versioning

Built binaries report version metadata via `-V`:

- tagged build: release tag plus commit hash
- untagged build on a branch: branch name plus commit hash
- detached `HEAD` or no git metadata: `dev` plus commit hash when available
- dirty worktree: `-dirty` suffix on the commit hash

## Cross-build Behavior

This cross-builds every discovered binary for the supported Linux and macOS targets.

## Status

The repository is being bootstrapped in layers. The structure is intended to remain stable while individual probes are added and evolved.

## License

MIT. See [LICENSE](LICENSE).
