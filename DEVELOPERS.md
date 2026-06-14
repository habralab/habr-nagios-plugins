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

- `cmd/probes/<probe>`: thin probe binary entrypoints
- `cmd/tools/<tool>`: internal helper entrypoints that support packaging or development but are not deployable monitoring probes
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

Common CLI conventions across mature probes should stay aligned where the semantics match:

- `-H/--hostname` for hostname-derived target selection
- `-u/--url` only for HTTP-based probes
- `-t/--timeout`
- `-v/--verbose` with shared normalization and clamping
- `-h/--help`
- `-V/--version`
- `--ignore-errors` for finding slugs suppressed from status aggregation
- `--list-error-slugs` for discoverability of suppressible findings

When a probe supports ignored findings:

- ignored findings should disappear from status aggregation
- ignored findings should remain visible in verbose text output
- ignored findings should be exposed separately from active findings in structured output
- slug parsing and validation should reuse shared helpers where possible
- suppressible findings should be discoverable through a structured catalog entry shape: slug, category, default severity, and default message

Current probes:

- `sitemap`: discovery and validation of sitemap entrypoints, trees, and extension payloads
- `robots`: availability, syntax, policy, and documented crawler-behavior checks for `robots.txt`
- `dnschain`: authoritative delegation and DNSSEC chain checker, built around a structured report model and already covering secure delegation hops, parent-side missing-`DS` denial, `NSEC3PARAM` policy/consistency, and sampled final-zone `NSEC3` negative responses while still leaving room for fuller generic authenticated-denial coverage

For DNS-oriented probes, keep target semantics explicit:

- `--zone` means "analyze this zone cut directly"
- `-H/--hostname` means "start from this owner name, derive its enclosing zone, validate the zone chain, and then validate owner-level RR presence appropriate for the probe"
- in `dnschain`, hostname mode currently checks owner-level `CNAME` / `A` / `AAAA` presence and consistency on the final zone authoritative servers, follows same-zone `CNAME` chains to terminal address data, and still does not recurse through foreign-zone `CNAME` targets

For DNSSEC denial handling in `dnschain`, keep the internal model explicit:

- parse denial material into typed proof entities rather than scattering NSEC/NSEC3 logic inline
- keep proof classification (`exact NSEC`, `exact NSEC3`, `closest-encloser opt-out`, unsupported) separate from signature verification
- attach proof evidence to staged checks so both Nagios verbose output and future machine-readable consumers can explain why a delegation was classified as insecure
- keep the parent-side insecure-delegation proofs and final-zone sampled negative-response proofs separate in the model, even if they share common NSEC/NSEC3 helpers
- treat sampled final-zone `NXDOMAIN` / `NODATA` checks as runtime evidence of validator-compatible denial behavior, not as a claim that the checker has exhaustively proven every negative response form for the zone

For DNSSEC algorithm handling in `dnschain`, keep three layers separate:

- cryptographic validity of the active trust path
- policy quality of active and published algorithms or digest types (`recommended`, `acceptable`, `not_recommended`, `must_not`)
- checker capability limits for algorithms or digest types that are known in standards but not implemented by the current crypto stack

This is important for verdict quality:

- active-path use of `must_not` or `not_recommended` material should not be conflated with harmless published rollover tails
- published but unmatched `DS` tails should stay visible in verbose evidence without automatically degrading the summary status
- unsupported-but-published algorithms should be reported explicitly as capability gaps rather than silently treated as valid or invalid

For `dnschain`, keep transport semantics conservative:

- classic authoritative DNS does not have a normal `User-Agent`-style client identification field
- do not invent one by overloading unrelated EDNS options
- TSIG/SIG(0)/EDNS options may be added later when their protocol semantics are actually needed, but they are not a generic checker identity mechanism
- query I/O failures should surface as transport findings regardless of whether the failed query was for `SOA`, `NS`, `DNSKEY`, `DS`, `NSEC3PARAM`, or sampled denial probes
- stage-specific findings such as invalid signatures, non-authoritative answers, or unrecognized denial proofs should remain separate from transport so operators can suppress reachability noise without hiding semantic DNSSEC failures
- unlike the HTTP probes, `dnschain` needs both an overall check timeout and a per-query timeout; the current convention is `-t/--timeout` for the whole run and `--query-timeout` for individual exchanges

## Modular Direction

The intended long-term shape is:

- `cmd/probes/<probe>`: one binary per probe
- `cmd/tools/<tool>`: repository-local helper tools
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

- discovers probes from `cmd/probes/*/main.go`
- treats the probe directory name as the probe slug
- builds each discovered probe into `build/check_<slug>`
- keeps `cmd/tools/*` outside ordinary probe build and cross-build targets
- uses a release-oriented default build with `-trimpath` and stripped ldflags
- keeps a separate `build-debug` target for local symbol-rich binaries
- cross-builds each discovered binary for the supported target matrix
- keeps Go cache local to the repository through `.gocache/`
- keeps module cache local to the repository through `.gomodcache/`
- injects build metadata into binaries, using repository state when available

This is important for the intended growth model:

- adding a new probe should usually mean adding a new `cmd/probes/<probe>/main.go`
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
- shared redirect policy helpers live next to that module in `internal/core/httpx/redirects.go`
- shared HTTP/TLS-related help text should live near that module
- shared verbosity parsing and clamping live in `internal/core/verbosity`
- shared target URL normalization and base-site derivation live in `internal/core/targeturl`
- shared probe CLI helpers for program naming, timeout parsing, CSV parsing, and ignored-slug validation live in `internal/core/probecli`
- shared report structures for staged checks and multi-renderer output live in `internal/core/checkreport`
- shared renderer-facing check presentation helpers also live in `internal/core/checkreport` when they operate only on the shared report model, for example verbosity-aware hiding of low-level checks and aggregation of repeated success checks
- probe apps should aggregate shared and probe-local flags into one help output
- shared options should appear in a stable order in CLI help
- the default HTTP `User-Agent` should identify the whole tool family, not a single probe binary
- the default HTTP `User-Agent` should expose only a release tag or `dev`, not branch names or commit hashes

Practical rule for moving code into `internal/core`:

- only move logic after a real second consumer appears
- prefer tiny helpers with clear inputs and outputs over shared result/rendering frameworks
- keep transport, target normalization, verbosity handling, and finding policy shared
- keep probe-specific parsing, traversal, registries, and output semantics inside the probe package unless a third probe proves a stable abstraction

Current exception:

- a small structured report model is acceptable in shared code when it remains renderer-neutral and does not dictate probe-local wording or evidence shape
- the intended contract is: collector/analyzer code produces structured stages, checks, findings, and metrics; renderers then emit Nagios-style text, JSON, or later external-consumer formats from the same report tree
- the shared report model may also carry target sets, trace events, partial-coverage markers, and suppressed findings when that helps represent mature probe behavior without forcing probe-specific JSON schemas
- the shared report model may also carry renderer hints on individual checks, such as `min_verbosity`, `aggregation_key`, and `aggregation_mode`, so text renderers can collapse repeated success noise without deleting atomic evidence from JSON output

Current renderer policy:

- analyzers should emit atomic checks and evidence first
- JSON output should stay close to that atomic report tree
- text renderers may aggregate only where the report explicitly opts in through shared hints
- aggregation belongs in renderers, not in collectors or analyzers
- default text output should prefer summary and problems
- `-v` should show compact stage-level diagnostics with repeated success checks collapsed
- `-vv` may add trace and grouped low-level success detail
- `-vvv` should be close to the full unaggregated waterfall

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

- `cmd/probes/<slug>` is the canonical probe CLI entrypoint path
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

## Packaging Direction

Debian packaging should stay in this repository, not in a separate downstream-only packaging repository.

Current packaging goals:

- one upstream repository
- Debian-first packaging scaffold
- probe-specific binary packages
- minimal duplication between probe metadata and Debian manifests

Current Debian conventions:

- source package name: `habr-nagios-plugins`
- binary package name: `<vendor>-nagios-plugin-<slug>`
- installed plugin path: `/usr/lib/nagios/plugins/check_<vendor>_<slug>`
- local developer binary path: `build/check_<slug>`
- packaging builds should emit the final installed binary name directly, e.g. `build/check_habr_sitemap`, instead of relying on a later filesystem rename step

Packaging helpers should derive probe-specific names from probe metadata instead of restating them manually in multiple Debian files.

Current implementation direction:

- static shared Debian files live in `debian/`
- `debian/control` is committed and edited as an ordinary Debian manifest
- `debian/changelog` is committed and should normally be updated manually
- generated Debian files are limited to probe-specific `*.install` and `*.docs`
- probe discovery for packaging lives in `internal/packaging/catalog`
- Debian rendering logic lives in `internal/packaging/debianmeta`

Current Makefile flow:

- `make package-prepare` refreshes probe-specific install/docs files from current probe metadata and those files are expected to be committed when they change
- `make package-changelog` can generate a snapshot changelog entry for local or CI builds, but is not part of the default package flow
- `make package-deb` builds binary packages with `dpkg-buildpackage` and assumes `debian/changelog` is already appropriate for the target distribution/version
- `make package-deb-source` builds source packages under the same assumption
- `make package-clean` removes Debian build staging artifacts without touching committed manifests
- generic Go build knobs `GO_BUILDMODE` and `GO_EXTRA_LDFLAGS` exist so packaging can request Linux hardening flags without changing ordinary local builds
- packaging builds can override `BIN_VENDOR` so the built artifact name matches the final installed binary name

Maintainer identity rules for generated Debian metadata:

- `DEBFULLNAME` and `DEBEMAIL` should be preferred when set
- `git config user.name` and `git config user.email` are the next fallback
- if neither source is available, generated files should use `Local Builder <builder@example.org>`
- packaging helpers should not synthesize maintainer addresses from transient local hostnames such as `.localdomain`

Versioning rules for Debian packaging:

- release tags should become Debian upstream versions without a leading `v`
- unreleased builds should fall back to a deterministic snapshot version such as `0~gitYYYYMMDD.<commit>`
- Debian revision stays separate from upstream version and defaults to `1`

The packaging scaffold should stay conservative:

- no runtime plugin loader
- no probe-name duplication across helper, metadata, and Debian manifests
- no packaging-only renaming rules hidden inside probe code
- do not auto-regenerate `debian/control` during ordinary prepare/build steps
- do not auto-regenerate `*.install` and `*.docs` during ordinary build steps either; refresh them explicitly in prepare flows and review them in VCS
- keep `debian/changelog` human-readable and VCS-reviewable by default; treat snapshot changelog generation as an opt-in helper rather than mandatory build machinery

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
- modular validation for format extensions (e.g., sitemap hreflang/image/news/video)
- redirect-chain cases for discovery paths that depend on `net/http` behavior
- explicit text sitemap cases for UTF-8, escaping, and scope rules

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

Current sitemap probe conventions:

- default overall timeout is `60s`
- traversal guardrails such as `--max-files` and `--max-depth` are opt-in and default to `0` (disabled)
- local traversal limits are checker-side constraints, not sitemap protocol violations
- traversal-limit results should surface as incomplete checker outcomes rather than false protocol-invalid `CRITICAL` states
- cyclic sitemap references should be reported as soft failures (`WARNING`) unless the standard explicitly requires harder treatment
- fallback discovery should be confirmed by content validation, not only `HEAD 200`
- discovery traces should narrate redirects in order, so operators do not need to reconstruct them from the raw HTTP section
- cross-host URLs and child sitemaps may be accepted only after cross-submit verification via the foreign host's `robots.txt`, with one `robots.txt` fetch per host per run
- text sitemap payloads should warn on non-UTF-8 data and on URL lines that contain characters which should be percent-encoded
- well-known sitemap extensions should be validated by namespace URI, not by XML prefix names

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

Performance expectation:

- probes should expose enough metrics to reason about runtime cost in monitoring environments
- current sitemap output includes elapsed time, transferred bytes, uncompressed bytes, and peak Go heap counters
- external RSS and wall-clock measurements are still useful for validating behavior on real hosts
- concurrency is intentionally out of scope for this repository unless a future need clearly outweighs the added operational and memory complexity

## Documentation Split

Keep public and developer-facing documentation separate:

- `README.md`: repository purpose, current probes, basic build commands, release-facing overview
- `DEVELOPERS.md`: architecture, module boundaries, build model, testing expectations, future extension rules
- `external/`: mirrored external references and vendored upstream artifacts, organized by source namespace such as `ietf/`, `iana/`, `cabf/`, with a repository-wide registry

When adding a new probe, update both only where it changes repository-level understanding. Detailed probe behavior belongs near the probe code or in probe-specific docs later.

Current technical debt in this area:

- Go `//go:embed` cannot consume canonical files directly from `external/` when they live outside the embedding package tree.
- Some probes therefore keep package-local `embeddata/` copies as derived build shims.
- Treat those copies as disposable packaging artifacts, not as a second source-of-truth.
- The repository should eventually grow a small lifecycle manager or sync helper that refreshes derived `embeddata/` trees from canonical files under `external/`.
