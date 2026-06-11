# habr-nagios-plugins

Small self-contained monitoring plugins for Nagios, Icinga, LibreNMS, and similar systems.

Repository: `https://github.com/habralab/habr-nagios-plugins`

## Current State

- repository skeleton
- shared layout for future probe binaries
- project-level build and contribution scaffolding

The first functional probes will be added in follow-up commits.

## Goals

- separate binary per check type
- static or otherwise self-contained deliverables
- predictable Nagios-style CLI behavior
- minimal runtime dependencies

## Build

```bash
make build
```

## Cross-build

```bash
make cross
```

## Status

The repository is being bootstrapped in layers. Code, tests, and the first working probe may appear after the initial skeleton commit.

## License

MIT. See [LICENSE](LICENSE).
