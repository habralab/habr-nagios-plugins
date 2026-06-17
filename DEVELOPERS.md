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

Documentation style:

- describe module and probe state as a snapshot of the repository at hand
- prefer "scope includes", "output contains", "module provides", and similar present-tense phrasing
- avoid historical or conversational narration such as "now", "already", "still", "used to", or "no longer" unless a migration step is itself the subject of the note
- keep future work explicit as follow-up items or constraints rather than mixing it into the state description

Current probes:

- `sitemap`: discovery and validation of sitemap entrypoints, trees, and extension payloads
- `robots`: `robots.txt` availability, syntax, policy, extension-registry, and documented crawler-behavior checks with RFC-oriented, vendor-aware, and strict behavior modes
- `dnschain`: authoritative delegation and DNSSEC chain checker with a structured report model; scope includes secure delegation hops, parent-side missing-`DS` denial, `NSEC3PARAM` policy and consistency, and sampled final-zone `NSEC3` negative responses
- `dnsresolver`: embedded iterative DNS resolver with authoritative querying, per-session cache, DNSSEC validation where available, and shared HTTP transport hostname resolution through `httpx`
- `dnschain` uses `dnsresolver` for root trust bootstrap, enclosing-zone discovery, zone-chain construction, authoritative fanout, and owner-level authoritative resolution
- `dnschain`-local DNS-specific code stays narrow and presentation-aware:
  - denial-proof classification and evidence shaping for `dnschain` findings
  - sampled final-zone `NSEC3` runtime probes and their stage/check wording
  - checker-specific DNSSEC algorithm policy interpretation and alerting
- future resolver policy may expose an explicit short-circuit flag such as `--resolver-mode bundled|system`; `bundled` is the authoritative and validating path, while `system` delegates hostname resolution to the host OS resolver and only interprets DNSSEC state if the external resolver already returned it
- `dnsresolver` should aim for a DNS-like API shape rather than a probe-specific one: question in, message-like answer out, with answer/authority/additional sections and response flags close to what operators expect from `dig` or a normal resolver API; higher-level helpers may still exist for probes that want convenience lookups
- DNSSEC state produced or observed by `dnsresolver` is primarily an input to probe logic, not something that must automatically appear in end-user output; some probes may care deeply about authenticated data, while others may use the same resolver only for ordinary hostname resolution
- `dnsresolver` has three distinct layers:
  - `Lookup(...)`: the small DNS-like API for a single question and a single effective result
  - `Resolve(...)`: a richer execution API that accepts fanout and consistency policy and can return per-endpoint material plus an aggregated result
  - `ResolveAuthoritative(...)`: the execution API for callers that already know the authoritative server set and want the resolver to perform the fanout and consistency work instead of reimplementing it in the probe
- new resolver features should prefer explicit execution policy objects such as fanout mode, consistency mode, and glue-acceptance mode over ad-hoc booleans; the resolver is the execution engine, while probes remain the business interpreters of the returned picture
- when a probe needs a yes/no answer such as "did any authoritative server publish this RRset" or "are all authoritative answers identical", that decision should be expressible through resolver execution options or through neutral assessments returned by the resolver, rather than through duplicated per-probe loops
- `dnsresolver` caches are intentionally per-resolver and therefore per probe run; they must not survive across runs
- cache keys must stay specific enough to avoid poisoning neighboring checks: simple lookups key on question, while richer execution results must also key on the authoritative server set and the execution policy such as fanout and consistency mode
- `dnsresolver` also keeps per-resolver endpoint health memory such as observed success, timeout, and RTT trends; that state is execution-local, affects upstream ordering, and must not leak across probe runs
- default resolver execution policy should stay laboratory-friendly unless a probe explicitly requests stricter behavior: partial or out-of-bailiwick additional-address material may still be used as hints, while missing or suspect glue should trigger best-effort completion of the remaining `NS` targets instead of short-circuiting the delegation walk

Candidate probe directions:

- `oidc`: OIDC discovery and issuer metadata checker; likely scope includes `/.well-known/openid-configuration` reachability, issuer-self-consistency, endpoint presence, JWKS publication, and TLS or DNS-backed prerequisites where they materially affect identity bootstrap
- `dane`: DANE policy checker for HTTP- and SMTP-oriented targets; a separate probe would need a clear value boundary such as protocol-specific DANE policy, MX-target walking, or mail-routing semantics rather than duplicating generic TLSA matching logic that may later live inside a broader TLS or DNS policy family
- `tls` / `x509`: certificate and transport-security probe family; likely scope includes modern and deprecated handshake policy, certificate identity and expiry, trust-path validation, revocation signals, and multi-endpoint semantic comparison across resolved service addresses
- `rss` / `atom`: feed discovery and validity checker; likely scope includes feed discovery from HTML and autodiscovery links, format and XML well-formedness, declared metadata consistency, basic HTTP freshness semantics, and publisher-facing issues such as broken entry links or invalid timestamps

Direction rule:

- candidate probes should enter the repository only when they have a clear target contract, a stable operator use case, and a boundary that is not better expressed as an option bundle inside an existing thinner probe

Current resolver-surface refactor plan:

- current state:
- `dnsresolver` already exposes a small `Lookup(...)` layer plus richer execution layers such as `Resolve(...)` and `ResolveAuthoritative(...)`
- resolver caches, execution policy, and endpoint-health memory are already per resolver instance and therefore per probe run
- shared HTTP transport already prefers `dnsresolver` rather than silently depending on the host OS recursive resolver
- near-term follow-up:
- keep new resolver features expressed through explicit execution-policy objects such as fanout, consistency, and glue-acceptance mode rather than ad-hoc booleans
- continue shifting duplicated authoritative fanout and consistency loops out of probes and into neutral resolver assessments or execution options
- keep the resolver API DNS-shaped: question in, message-like answer out, with richer convenience helpers layered above that boundary
- add a shared DNS wire-level test harness under `internal/testkit`, so resolver and probe tests can exercise truncation, timeout, `SERVFAIL`, missing glue, non-authoritative replies, and DNSSEC-bogus scenarios against real UDP/TCP packet flow instead of relying only on function stubs
- deferred follow-up:
- add an explicit shared resolver short-circuit policy such as `--resolver-mode bundled|system` in the shared resolver or transport layer rather than as probe-local conditionals
- keep TSIG, SIG(0), and EDNS extensions out of the common path until a concrete protocol need justifies them

For `robots`, keep target and policy semantics explicit:

- `--robots-url` means "fetch exactly this `robots.txt` URL" and overrides derived discovery targets
- `-u/--url` means "use this base site URL for `robots.txt` discovery"
- `-H/--hostname` means "derive an `https` base URL from this hostname and fetch `/robots.txt`"
- default `behavior-profile` is `rfc`; `vendor-aware` and `strict` are opt-in overlays on top of the transport and syntax baseline
- `--strict` is separate from `--behavior-profile` and is used for stricter local policy interpretation of known non-standard directives
- `robots` keeps built-in registries for directives, crawler and AI tokens, and documented behavior claims; those registries should stay inspectable through dedicated list flags rather than being hidden inside verbose-only output

For DNS-oriented probes, keep target semantics explicit:

- `--zone` means "analyze this zone cut directly"
- `-H/--hostname` means "start from this owner name, derive its enclosing zone, validate the zone chain, and then validate owner-level RR presence appropriate for the probe"
- in `dnschain`, hostname mode checks owner-level `CNAME` / `A` / `AAAA` presence and consistency on the final zone authoritative servers, follows same-zone `CNAME` chains to terminal address data, and does not recurse through foreign-zone `CNAME` targets

For service-oriented probes, keep target semantics explicit:

- `-H/--hostname` means "the service identity and network target hostname"
- `-p/--port` means "the concrete service port"
- service-oriented input normalization should prefer a shared contract such as `probecli.ResolveServiceTargetInput(...)` so trimming, missing-input handling, and port-range validation do not drift between probes
- service-specific policy flags such as transport mode, STARTTLS profile, or OCSP behavior belong above the service-target contract rather than inside it

For multi-address service probes, keep transport fanout separate from semantic coverage:

- resolving both `A` and `AAAA` records is only the candidate-discovery step
- transport fallback across resolved endpoints is useful but is not equivalent to semantic validation across the whole address set
- if handshake-derived checks such as PKI, OCSP, CT, DANE, or negotiated-parameter policy are evaluated from only one successful endpoint, the probe should treat that as partial address coverage rather than as full service equivalence
- semantic comparison across the address set should be explicit about what must match, what may differ harmlessly, and what degrades to `WARNING` versus `CRITICAL`

For shared CLI/runtime modules, prefer domain slices over flat growth:

- `probecli` common/runtime pieces cover shared flags, early errors, and renderer-facing input labels
- `probecli` DNS pieces cover inputs such as `hostname|zone|owner|rrtype`
- `probecli` service pieces cover inputs such as `hostname|port` and related reusable validation
- `probecli` web pieces cover `url`, `robots-url`, `entrypoint`, and similar HTTP-oriented target forms
- when a flat file starts mixing multiple such slices, split by domain and keep the text-rendering merge at the boundary rather than duplicating labels or semantics in individual probes

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
- transport-related helpers
- output rendering

Probe-specific logic should stay out of shared modules until there is a real second consumer.

The current transport options are intended to converge in shared modules rather than being redefined per probe.

Current direction:

- shared build-time version formatting lives in `internal/core/buildinfo`
- shared help-option structures and option-list rendering live in `internal/core/clihelp`
- shared help-document rendering also lives in `internal/core/clihelp`; probe apps should describe help through a small document structure such as summary, usage lines, and options rather than hand-writing `fmt.Printf` templates
- shared suppressible-finding catalog plumbing lives in `internal/core/rulecatalog`
- shared finding primitives such as `Severity`, `Problem`, and severity-name formatting live in `internal/core/finding`
- shared user-facing message catalog plumbing for future i18n lives in `internal/core/msgcatalog`
- probe-local suppressible finding definitions and category inference live next to each probe when those catalogs are probe-specific, for example `internal/probe/robots/findings.go`, `internal/probe/sitemap/findings.go`, and `internal/probe/dnschain/findings.go`
- shared client construction lives in `internal/core/httpx`
- shared redirect policy helpers live next to that module in `internal/core/httpx/redirects.go`
- shared CLI helper text for repeated options such as `--ignore-errors` and `--list-error-slugs` lives in `internal/core/probecli`
- shared standard CLI flag registration and finalization for `--timeout`, `--output`, `--ignore-errors`, `-v/--verbose`, `-h/--help`, `-V/--version`, and `--list-error-slugs` lives in `internal/core/probecli`; probe apps should add probe-local flags around that shared layer rather than rebuilding the common contract by hand
- shared probe CLI helpers may also render final probe output from the common `summary/detail/json/exit-code` contract, so app entrypoints do not each reimplement the same post-run stdout path
- shared probe CLI helpers may also dispatch common toggles such as version, help, and error-slug listing through small ordered actions, so app entrypoints do not each reimplement the same pre-run control flow
- shared HTTP transport should resolve hostnames through `dnsresolver` rather than assuming the host OS recursive resolver is acceptable; per-probe overrides can still inject a custom `HTTPClient` when tests or diagnostics need it
- if a future CLI flag allows system-resolver short-circuiting, that override should be implemented in the shared resolver/transport layer rather than as probe-local conditionals; probes may choose to surface the implications, but the resolver itself should not force that into user-facing output
- shared probe identity and naming helpers live in `internal/core/probemeta`
- shared verbosity parsing and clamping live in `internal/core/verbosity`
- shared target URL normalization and base-site derivation live in `internal/core/targeturl`
- shared probe CLI helpers for program naming, timeout parsing, CSV parsing, ignored-slug validation, and suppressible-finding list rendering live in `internal/core/probecli`
- schema-driven probe input registration should prefer `probecli.Parser` plus typed `InputSpec` definitions, so probe apps stop hand-wiring common parsing and can keep validation in reusable `InputRef` terms
- probe config structs should carry standard toggle state such as help, version, and error-slug listing when that state survives parsing into the app-to-probe contract; app-local booleans for the same common toggles should be treated as transitional drift
- shared authoritative DNS and DNSSEC lookup helpers live in `internal/core/dnsresolver`
- shared report structures for staged checks and multi-renderer output live in `internal/core/checkreport`
- top-level Nagios summary formatting should prefer the shared `checkreport` summary helper so probes keep one headline shape even when they still carry probe-specific perfdata or verbose sections
- shared renderer-facing check presentation helpers also live in `internal/core/checkreport` when they operate only on the shared report model, for example verbosity-aware hiding of low-level checks and aggregation of repeated success checks
- shared verbose text rendering skeleton also lives in `internal/core/checkreport`; probes should assemble an ordered section plan from shared and probe-local section writers instead of hand-building the whole detailed output as one monolithic function
- shared section writers should cover common report families such as findings, suppressed findings, rule checks, report overview, meta, stages, and traces when their formatting already matches across multiple probes
- probe-local renderers should shrink toward section adapters: they may still format probe-specific sections such as parsed robots groups or sitemap document summaries, but they should avoid re-implementing shared section families
- probe apps should aggregate shared and probe-local flags into one help output
- the intended `internal/app/*` shape is narrow: parse flags, build a help document, dispatch standard toggles, invoke the probe, and hand the result to shared rendering helpers
- shared options should appear in a stable order in CLI help

Current CLI and report-surface refactor plan:

- current state:
- `probecli` already owns common flags, parser helpers, typed input specs, shared help rendering, and common toggle dispatch
- `checkreport` already owns the shared staged report model plus default Nagios summary, detail, JSON, and perfdata helpers
- mature probes already converge on the narrow app-layer shape of parse, toggle dispatch, run, and shared rendering
- near-term follow-up:
- keep migrating remaining probe-local app glue onto schema-driven `probecli` registration and shared runtime helpers
- keep shrinking probe-local renderers toward section adapters over the shared `checkreport` model rather than full custom detail builders
- keep common toggle state in probe configs only where it survives parsing into the app-to-probe contract; duplicate app-local booleans remain transitional drift and should be removed when touched
- deferred follow-up:
- extend shared report entities with stable message-key fields and message parameters so renderers and JSON consumers can use machine-readable text provenance
- continue normalizing shared section families, aggregation hints, and verbosity behavior before adding new probe-local output conventions
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
- shared renderer helpers may also cover trace filtering, stable report lookups, rule-check presentation/selection, and perfdata formatting when those operations already have multiple probe consumers and still operate only on the shared report model

Current message-catalog policy:

- this repository is preparing for future i18n, but the current phase is a Go-native prototype rather than YAML, JSON, or gettext catalogs
- machine-facing semantics such as finding slugs, severity, category, policy flags, and branching stay in code
- user-facing copy such as titles, summaries, details, and hints should move into a message-catalog layer when that copy already belongs to a shared contract
- the current shared message-catalog module is `internal/core/msgcatalog`
- the current message-catalog contract is intentionally small: stable message keys, fixed variants such as `summary` and `detail`, and flat parameter substitution
- the current default catalog is assembled from distributed component sources rather than one monolithic text blob; probe-local or component-local sources are merged in `internal/core/msgcatalog`
- shared renderer labels and shared help-text fragments also live on those rails when they are already stable across multiple probes; probes should consume them through tiny shared helpers rather than copying the same English strings
- message rendering must not contain business logic; probes and renderers compute semantics first and only then ask the catalog to format text
- the migration scope is deliberately narrow: only copy that is already on shared rails should move first, for example common finding copy or common renderer labels
- for shared finding copy, the finding slug itself is the current message key; probe-local finding registries keep semantics and defaults such as severity/category, while the default user-facing summary text is resolved through `internal/core/msgcatalog`
- canonical finding slugs are namespaced with a stable probe or component prefix such as `dnschain_`, `robots_`, or `sitemap_`; new bare slugs should not be introduced
- when a probe reuses another component's finding family, it should reuse that component prefix rather than minting a second spelling for the same family
- temporary legacy slug aliases may exist only as transition shims around probe boundaries; catalogs, emitted reports, and help output should prefer canonical namespaced slugs
- probe-specific narrative text, ad-hoc trace prose, and still-evolving verbose sections may remain local until that probe is otherwise being adapted
- raw user-facing prose should not be cemented into new semantic registries when a stable message key would better express intent
- external catalog formats are out of scope for now; if the Go-native prototype proves too restrictive later, the data source can change without changing the key and variant contract

Current message-layer refactor plan:

- current state:
- `internal/core/msgcatalog` is already the shared catalog layer for stable message keys and small variants such as `summary`, `detail`, `title`, and `hint`
- distributed component sources such as `common`, `dnschain`, `robots`, and `sitemap` are already merged into the default catalog
- findings already use those rails for default summary copy through stable namespaced slugs
- some shared help text and renderer labels already use those rails as well
- near-term scope:
- extend shared report entities such as findings and checks so they can carry `message_key` plus flat message parameters alongside rendered text
- migrate shared runtime and CLI wording first, especially early errors, input validation messages, repeated timeout or transport wording, and shared help fragments
- migrate shared DNS and HTTP wording next where a second consumer already exists, for example authoritative RR presence summaries, matcher summaries, and repeated lookup or transport diagnostics
- keep business semantics in code and keep the catalog focused on rendering; analyzers compute meaning first and only then select a message key plus parameters
- probe migration order:
- `dnschain` is the first probe-level consumer because it already sits closest to the shared staged-report contract
- `robots` and `sitemap` remain later consumers because their detail and verbose output still carry more probe-local semantics inherited from the pre-framework phase
- deferred follow-up:
- expose `message_key`, message parameters, and rendered text together in JSON once the shared report contract is ready for that expansion
- review which `robots` and `sitemap` verbose/detail sections can move onto shared section families and which should stay probe-local adapters with an explicit contract
- keep i18n and external catalog formats out of the immediate refactor; the current target is a stable Go-native message contract rather than a data-source migration

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

Current probe-identity and packaging-surface refactor plan:

- current state:
- probe identity already centers on a stable slug plus probe-local metadata
- local binary names, installed binary names, and Debian package names already follow one derived naming family rather than ad-hoc per-probe spellings
- packaging metadata refresh already flows through probe discovery and packaging catalog helpers
- near-term follow-up:
- keep CLI help, version output, package manifests, and install/docs generation reading from probe metadata rather than duplicating probe names in multiple surfaces
- keep packaging builds emitting final installed binary names directly instead of relying on hidden rename steps later in the pipeline
- deferred follow-up:
- keep packaging-specific customizations additive around the generic build and metadata path rather than introducing probe-local naming rules or packaging-only identity forks

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
- opt-in integration tests with a lightweight local HTTP server for redirects, headers, and parser behavior under real `net/http`
- separate opt-in live-network tests only for explicit external regression corpora whose flakiness and target stability are understood

Each new probe should reserve a place for:

- package-local unit tests
- `testdata/` fixtures when format-heavy parsing exists
- mockable transport or resolver interfaces where external I/O is involved
- modular validation for format extensions (e.g., sitemap hreflang/image/news/video)
- redirect-chain cases for discovery paths that depend on `net/http` behavior
- explicit text sitemap cases for UTF-8, escaping, and scope rules

The root `Makefile` may expose separate targets for opt-in local integration suites such as `test-integration` and external live-network suites such as `test-live`, when those tests are not appropriate for the default no-network path.

Minimal Go code-quality gates should stay pragmatic:

- `gofmt` is mandatory and stays separate from semantic linting
- `go vet` is the baseline repository-wide lint pass
- `staticcheck` is recommended when available because it catches real Go issues with low stylistic noise
- repository lint should not depend on a large style-policy bundle unless a concrete CI need justifies the extra churn

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

Current robots probe conventions:

- default overall timeout is `60s`
- `HTTP 404` means "robots.txt not present" and should not be treated as a transport failure by default
- `4xx` availability failures should remain distinct from `5xx` or fetch failures so operators can suppress policy noise without hiding server-side breakage
- `--behavior-profile` should keep `rfc` as the default baseline, with `vendor-aware` and `strict` as opt-in overlays
- `--strict` should remain independent from `--behavior-profile`, because local policy about extension directives is not the same as documented crawler behavior
- built-in directive, agent, and behavior registries should stay discoverable through list flags and should carry provenance in verbose or structured output

Concrete probe flags should be documented alongside each binary once they exist.

If a probe uses shared transport options, the shared flag descriptions should stay attached to the shared module and be rendered into the final help text rather than duplicated manually across probe apps.

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

Current refactor plans in this area:

- external-artifact embedding plan:
- Go `//go:embed` cannot consume canonical files directly from `external/` when they live outside the embedding package tree
- some probes therefore keep package-local `embeddata/` copies as derived build shims
- those copies are disposable build artifacts rather than a second source-of-truth
- near-term follow-up:
- keep probe-local `embeddata/` trees mechanically derived and reviewable
- avoid moving canonical source material out of `external/` merely to satisfy `//go:embed`
- deferred follow-up:
- add a small lifecycle manager or sync helper that refreshes derived `embeddata/` trees from canonical files under `external/`

- renderer-semantics normalization plan:
- `robots` and `sitemap` already share the top-level CLI/runtime and summary contract with the shared probe framework
- their remaining drift lives in probe-local detail-section semantics and stage-specific output shaping inherited from the pre-framework phase
- near-term follow-up:
- review which parts of `robots` and `sitemap` verbose and JSON semantics can move onto shared `checkreport` section families
- keep genuinely probe-specific parsed-content adapters local, but describe them through an explicit contract rather than letting them drift implicitly

- test-taxonomy and testkit plan:
- the repository now distinguishes ordinary unit tests, deterministic local integration tests, and explicit live-network regressions
- probe app tests already share a minimal stdout-capture helper
- near-term follow-up:
- keep naming and build-tag semantics aligned across probes so `integration` means deterministic local listener or httptest coverage and `live` means external-network regression
- add a reusable DNS authoritative test harness in `internal/testkit` so DNS transport, referral, and DNSSEC error cases can be covered through real wire exchanges and shared between `dnsresolver`, `dnschain`, and future DNS-backed probes
- deferred follow-up:
- grow broader shared testkit layers for HTTP, TLS, and DNS harness builders
- add shared corpus runners and stable golden-output orchestration where multiple probes would benefit
