# habr-nagios-plugins

Small self-contained monitoring plugins for Nagios, Icinga, LibreNMS, and similar systems.

Repository: `https://github.com/habralab/habr-nagios-plugins`

## Current Probes

Released probes:

- `check_sitemap`
- `check_robots`

`check_sitemap` validates sitemap discovery and sitemap tree integrity in a way that is useful for monitoring:

- `OK`, `WARNING`, `CRITICAL`, and `UNKNOWN` exit codes
- short Nagios-style summary output by default
- deeper diagnostics through `-v`, `-vv`, and `-vvv`
- support for `robots.txt`, sitemap indexes, XML/text sitemaps, and `.gz`
- redirect-aware discovery traces for `robots.txt` and common fallback paths
- cross-submit verification through delegated `robots.txt` discovery on foreign hosts
- UTF-8 and URL-escaping checks for text sitemap payloads
- validation of sitemap extensions: `xhtml:hreflang`, `image:image`, `news:news`, and `video:video`
- Debian packaging as `habr-nagios-plugin-sitemap`

`check_robots` validates `robots.txt` availability and policy shape:

- `OK`, `WARNING`, `CRITICAL`, and `UNKNOWN` exit codes
- short Nagios-style summary output by default
- deeper diagnostics through `-v`, `-vv`, and `-vvv`
- base URL or explicit `robots.txt` targeting
- checks for syntax, duplicate or invalid `Sitemap:` directives, and empty payloads
- built-in registry for core, well-known extension, and AI crawler tokens with provenance metadata
- optional policy assertions such as required `Sitemap`, required `User-agent`, required `Disallow`, and forbidden `Disallow`
- Debian packaging as `habr-nagios-plugin-robots`

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

Default local output for the robots probe:

```bash
build/check_robots
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
./build/check_robots -H example.com
./build/check_robots --robots-url https://example.com/robots.txt --require-sitemap
./build/check_robots -H example.com --behavior-profile vendor-aware -vv
./build/check_robots --list-known-directives
./build/check_robots --list-known-agents
```

Installed Debian package payloads:

```bash
/usr/lib/nagios/plugins/check_habr_sitemap
/usr/lib/nagios/plugins/check_habr_robots
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
