# habr-nagios-plugins

Small self-contained monitoring plugins for Nagios, Icinga, LibreNMS, and similar systems.

Repository: `https://github.com/habralab/habr-nagios-plugins`

## Current Probe

The first released probe is `check_sitemap`.

It validates sitemap discovery and sitemap tree integrity in a way that is useful for monitoring:

- `OK`, `WARNING`, `CRITICAL`, and `UNKNOWN` exit codes
- short Nagios-style summary output by default
- deeper diagnostics through `-v`, `-vv`, and `-vvv`
- support for `robots.txt`, sitemap indexes, XML/text sitemaps, and `.gz`
- Debian packaging as `habr-nagios-plugin-sitemap`

## Goals

- separate binary per check type
- self-contained operational delivery
- predictable Nagios-style CLI behavior
- minimal runtime dependencies

## Build

```bash
make build
```

This builds every probe entrypoint found under `cmd/probes/*/main.go` into `build/`.

Default local output for the sitemap probe:

```bash
build/check_sitemap
```

If you need a debug-friendlier local build with symbols intact:

```bash
make build-debug
```

## Usage

```bash
./build/check_sitemap -H example.com
./build/check_sitemap -H example.com -vv
./build/check_sitemap --entrypoint https://example.com/sitemap.xml
```

Installed Debian package payload:

```bash
/usr/lib/nagios/plugins/check_habr_sitemap
```

## Cross-build

```bash
make cross
```

## Debian Packaging

Prepare committed Debian manifests derived from probe metadata:

```bash
make package-prepare
```

Build a Debian package:

```bash
make package-deb
```

For target-specific Ubuntu builds, refresh the changelog entry first:

```bash
make package-changelog DEB_DISTRIBUTION=noble VERSION=v1.0.0
make package-deb
```

## Versioning

Built binaries report version metadata via `-V`:

- tagged build: release tag plus commit hash
- untagged build on a branch: branch name plus commit hash
- detached `HEAD` or no git metadata: `dev` plus commit hash when available
- dirty worktree: `-dirty` suffix on the commit hash

## License

MIT. See [LICENSE](LICENSE).
