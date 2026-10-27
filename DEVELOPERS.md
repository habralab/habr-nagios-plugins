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
- `dnsrr`: thin authoritative DNS RR presence checker with shared authoritative discovery and resolver-backed DNSSEC state for rollout and policy-oriented RR assertions
- `tls`: TLS transport, PKI, and DNS-backed trust checker; scope includes direct TCP TLS plus SMTP/IMAP STARTTLS, hostname and expiry validation, basic trust-path evaluation, negotiated-version and ALPN reporting, weak TLS 1.2 cipher probing, deprecated TLS 1.0/1.1 probes, SCT presence, stapled or active OCSP modes, and authoritative CAA/DANE lookups through the bundled resolver
- `dnsresolver` is the embedded iterative DNS resolver used by DNS- and HTTP-backed probes; it provides authoritative querying, per-session cache, DNSSEC validation where available, and shared HTTP transport hostname resolution through `httpx`
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
- additive batch helpers also exist beside those single-question surfaces:
  - `LookupBatch(...)`: ordered orchestration helper for multiple DNS questions within one resolver session
  - `ResolveAuthoritativeBatch(...)`: ordered orchestration helper for multiple authoritative fanout questions against one authoritative server set and one execution policy
- if a richer resolver-side session or batch API is introduced, it should live beside those existing surfaces rather than replacing them; the small DNS-shaped API remains the stable default for thin probes, while heavier DNS-backed probes may opt into the richer execution surface for shared session caches, grouped questions, and deeper diagnostics
- new resolver features should prefer explicit execution policy objects such as fanout mode, consistency mode, and glue-acceptance mode over ad-hoc booleans; the resolver is the execution engine, while probes remain the business interpreters of the returned picture
- when a probe needs a yes/no answer such as "did any authoritative server publish this RRset" or "are all authoritative answers identical", that decision should be expressible through resolver execution options or through neutral assessments returned by the resolver, rather than through duplicated per-probe loops
- `dnsresolver` in-process caches are intentionally per-resolver and therefore per probe run; optional external shared-cache backends are additive acceleration layers and must not change probe correctness
- cache keys must stay specific enough to avoid poisoning neighboring checks: simple lookups key on question, while richer execution results must also key on the authoritative server set and the execution policy such as fanout and consistency mode
- per-resolver caches should be paired with per-resolver inflight suppression for expensive repeated work such as identical lookups, authoritative fanout plans, and zone validation, so future probe-side parallelism does not multiply wire traffic inside a single run
- `dnsresolver` also keeps per-resolver endpoint health memory such as observed success, timeout, and RTT trends; that state is execution-local, affects upstream ordering, and must not leak across probe runs
- transport-facing probes and shared network helpers expose one common IP-family policy surface:
  - `auto`: detect locally usable IPv4/IPv6 transport and use only working families for endpoint transport
  - `ipv4`: force IPv4 transport only
  - `ipv6`: force IPv6 transport only
  - `dual`: attempt both families even if local auto-detection would suppress one of them
- `dnsresolver` applies that policy to iterative DNS and authoritative fanout only as transport execution policy; it does not rewrite DNS payload semantics such as signed `AAAA` data, DNSSEC proofs, or authoritative RR contents
- the current implementation is a capability filter, not a Happy-Eyeballs race between IPv4 and IPv6 transports
- local family detection is layered:
  - a fast local inspection classifies each family as `available`, `hard_unavailable`, or `unknown`
  - `hard_unavailable` is reserved for strong host-local facts such as no usable non-loopback address, only link-local IPv6, missing up non-loopback interfaces, or local transport errors such as `EAFNOSUPPORT`, `ENETUNREACH`, or `EADDRNOTAVAIL`
  - `unknown` means the host shape did not prove absence and an external probe is still needed before the family is treated as usable
  - external family probes are only attempted for `unknown` families
- transport-family assessment is cached in-process for a short TTL and reused across the current process lifetime as host-runtime fact; this cache is execution-local and distinct from resolver DNS-answer caching
- structured runtime output contains both the effective family selection and the assessment reasons so probe JSON or verbose output can explain why `auto` suppressed one family on the local host
- default resolver execution policy should stay laboratory-friendly unless a probe explicitly requests stricter behavior: partial or out-of-bailiwick additional-address material may still be used as hints, while missing or suspect glue should trigger best-effort completion of the remaining `NS` targets instead of short-circuiting the delegation walk

Candidate probe directions:

- `oidc`: OIDC discovery and issuer metadata checker; likely scope includes `/.well-known/openid-configuration` reachability, issuer-self-consistency, endpoint presence, JWKS publication, and TLS or DNS-backed prerequisites where they materially affect identity bootstrap
- `dane`: DANE policy checker for HTTP- and SMTP-oriented targets; a separate probe would need a clear value boundary such as protocol-specific DANE policy, MX-target walking, or mail-routing semantics rather than duplicating generic TLSA matching logic that may later live inside a broader TLS or DNS policy family
- `rss` / `atom`: feed discovery and validity checker; likely scope includes feed discovery from HTML and autodiscovery links, format and XML well-formedness, declared metadata consistency, basic HTTP freshness semantics, and publisher-facing issues such as broken entry links or invalid timestamps

Direction rule:

- candidate probes should enter the repository only when they have a clear target contract, a stable operator use case, and a boundary that is not better expressed as an option bundle inside an existing thinner probe

Current resolver-surface refactor plan:

- current state:
- `dnsresolver` exposes a small `Lookup(...)` layer plus richer execution layers such as `Resolve(...)` and `ResolveAuthoritative(...)`
- resolver in-process caches, execution policy, and endpoint-health memory are per resolver instance and therefore per probe run
- shared HTTP transport prefers `dnsresolver` rather than silently depending on the host OS recursive resolver
- phased execution plan:
- phase 1: deepen internal per-run execution caches without changing probe-facing contracts
  - cache enclosing-zone and final-authority scaffolding per owner name so repeated `A` + `AAAA` + `CAA` + `TLSA` work can reuse one authority-discovery path
  - cache reusable zone-chain and authoritative-server material below the final lookup result so repeated DNSSEC-backed lookups do not cold-start every delegation walk
  - keep the simple `Lookup(...)`, `Resolve(...)`, and `LookupEffectiveCAA(...)` surfaces unchanged while they benefit from the deeper internal caches
  - extend deterministic resolver tests so repeated related lookups prove that intermediate discovery work is actually reused
  - compare cache structure, cache scope, and reuse policies against the three locally mirrored reference resolver codebases before freezing the internal cache model; where their behavior is clearly better suited to our execution style, prefer borrowing the structure or policy rather than inventing needless divergence
- phase 2: extend richer additive resolver-side execution surfaces
  - keep the existing batch helpers beside the classic DNS-shaped APIs and add a deeper optional session API only where grouped execution or trace sharing materially benefits heavier probes
  - let heavier probes request grouped questions and shared execution traces while thin probes remain on the simple contract
  - keep the richer surface business-neutral around cross-zone or child-zone referrals rather than baking probe assumptions into the resolver
- phase 3: optional external shared cache backend
  - keep Redis or any future networked cache transport in shared internal modules rather than embedding backend-specific transport code inside `dnsresolver`; other internal consumers may reuse the same client, dial, timeout, or backend-lifecycle layer later
  - keep per-run memory caches authoritative for one execution and make the external backend purely additive and opt-in
  - CLI and config should speak in terms of a generic cache-backend DSN rather than a Redis-specific flag; backend selection belongs to the shared cache layer, not to `dnsresolver` or individual probes
  - start with positive-result and scaffolding cache artifacts only; negative and transport-failure caching remains disabled until there is a stronger policy model
  - initial TTL policy may follow the authoritative DNS TTL of the cached artifact when an operator explicitly enables the backend
  - intended first backend is Redis, but backend failure or unavailability must degrade to cache miss rather than to probe failure
  - namespace Redis keyspace by module family and artifact kind so resolver-owned entries do not collide with future consumers and can evolve independently
  - before adding live Redis smoke coverage, assess local execution options such as an unprivileged local instance or Unix-socket mode and only run those tests when the capability is present
- Redis cache contract for the first external-cache phase:
  - the Redis backend is a local or near-local acceleration layer for components under our control, not a shared multi-tenant cache; key naming therefore does not need a repository-wide vanity prefix, but it must still be namespaced by internal module family and artifact kind
  - preferred key shape is module-oriented and versioned, for example:
    - `dnsresolver:v1:authority:<owner>`
    - `dnsresolver:v1:delegation:<zone>`
    - `dnsresolver:v1:lookup:<qname>:<qtype>`
    - `dnsresolver:v1:resolve:<resolve-key>`
    - `dnsresolver:v1:validation:<zone>`
    - future consumers should use their own module prefix rather than appending unrelated artifact kinds under `dnsresolver`
  - resolver-side cache artifacts should stay explicit and versioned rather than storing opaque ad-hoc blobs
  - the cache model should stay close to resolver-native DNS semantics first, with a small derived layer only where the laboratory resolver needs reusable execution state:
    - canonical DNS-like layer:
      - `lookup`: effective `Lookup(...)` result for one question, including answer RR material, signatures when present, DNSSEC state, and authenticated no-data fact when present
      - `resolve`: effective `ResolveAuthoritative(...)` result for one question plus one normalized authoritative-server set and execution policy, including per-endpoint answer material and consistency assessment
      - future refactors may split this toward a more explicit `message` and `rrset` internal model, but the stored artifact should still represent DNS answer material rather than probe-specific verdicts
    - derived execution layer:
    - `authority`: reusable closest-apex or enclosing-zone authority material for a name, including the final authoritative server set; shared-storage payloads should stay compact and must not duplicate full delegation-path material that already lives in `delegation`
    - `delegation`: reusable parent-to-child delegation-path prefixes keyed by zone apex so sibling names or sibling zones can reuse intermediate authority such as `.com`; each hop records who delegated to whom plus the parent and child server material used to advance the walk
    - `validation`: reusable DNSSEC chain-validation state for a zone apex, including validated DNSKEY material, verdict, and TTL
  - the derived layer exists because this repository uses a laboratory recursive resolver, not only a packet cache; the cache must preserve reusable execution knowledge such as delegated authority and validated trust-chain state, but it should not grow probe-shaped business payloads
  - where both a canonical DNS-like artifact and a derived artifact can express the same thing, prefer the canonical form and keep the derived artifact minimal
  - values should be self-describing and versioned so readers can reject stale schema assumptions safely; payloads should carry at least:
    - artifact kind
    - schema version
    - authoritative TTL used for expiry
    - store timestamp
    - serialized payload
  - shared-cache payload shape should stay compact and boring:
    - the top-level envelope carries the artifact TTL; payloads should not duplicate that top-level TTL unless a nested structure genuinely needs its own TTL semantics
    - endpoint payloads use `name`, `address`, and optional `port`; default DNS port `53` is implicit and should be omitted from the payload
    - compact `authority` payloads should omit empty `hops`; when shared authority needs delegation detail, that detail should be loaded from the sibling `delegation` artifact rather than duplicated
    - per-hop delegation TTL remains part of the `delegation` payload because one Redis key TTL is not enough to preserve the TTL semantics of individual delegation hops inside a reusable path prefix
  - TTL derivation should come from authoritative DNS material rather than from backend-local heuristics:
    - lookup artifacts use the minimum TTL across the returned RRset and its signatures, falling back to denial or authority material for authenticated no-data paths
    - resolve artifacts use the minimum TTL across the authoritative endpoint RRset material retained in the stored fanout result
    - zone-chain and authority artifacts use the minimum TTL observed in delegation `NS` plus glue material for the relevant hop set
    - validation artifacts use the minimum TTL across the validated `DS` and `DNSKEY` material accumulated along the secure chain
  - Redis reads are opportunistic:
    - missing key, decode failure, version mismatch, backend timeout, or backend unavailability all degrade to cache miss
    - probe correctness must not depend on Redis availability
  - Redis writes are also opportunistic:
    - first phase allows ordinary read-through `SET` or `SETEX` style writes without distributed locking
    - duplicate computation by concurrent probe processes is acceptable
    - last-write-wins is acceptable as long as the key identifies a single artifact kind precisely and the stored entry remains internally self-consistent
  - distributed locks, Redlock-style coordination, or Lua-based compare-and-set scripts are out of scope for the first phase; inter-process races may reduce cache efficiency but must not affect probe correctness
  - negative caching remains disabled in the first phase:
    - do not store `NXDOMAIN`, `NODATA`, `SERVFAIL`, timeout, bogus, or indeterminate execution results externally yet
    - once negative caching is revisited, it should have its own explicit TTL policy rather than inheriting positive-answer behavior
  - Redis transport behavior should stay conservative:
    - small dial, read, and write timeouts
    - backend connection failure must not materially extend probe runtime
    - the shared Redis transport or client layer should be reusable by future internal consumers outside `dnsresolver`
    - the first transport implementation may stay deliberately small:
      - `redis://host:port[/db]` for TCP
      - `redis+unix:///path/to/redis.sock?db=N` for local socket mode
      - `redis+sentinel://...` or sentinel-style multi-host discovery should be rejected early as unsupported, with structured runtime info that probes can surface in verbose or JSON output
      - minimal command surface such as `GET` and `SETEX` is enough for the initial additive cache layer
  - default or explicit no-external-cache modes should also be representable as backend DSNs at the shared-cache layer, for example `internal://` or `none://`, so probes can keep a stable generic flag while only the shared-cache whitelist evolves
- phase 4: extend shared wire-level and backend-aware regression coverage
  - extend the reusable DNS authoritative harness under `internal/testkit` for timeout, truncation, `SERVFAIL`, referral, missing-glue, and DNSSEC-bogus cases
  - extend resolver tests to cover cache hit or miss behavior, backend-disabled behavior, backend-failure fallback, and grouped lookup execution reuse
- near-term follow-up:
- keep new resolver features expressed through explicit execution-policy objects such as fanout, consistency, and glue-acceptance mode rather than ad-hoc booleans
- continue shifting duplicated authoritative fanout and consistency loops out of probes and into neutral resolver assessments or execution options
- keep the resolver API DNS-shaped: question in, message-like answer out, with richer convenience helpers layered above that boundary
- shared external-cache coverage now includes `authority`, `delegation`, `lookup`, `resolve`, and `validation`; after that, the main remaining DNS-layer work is no longer "basic cacheability" but higher-order execution surfaces and test harnessing
- per-resolver and probe-side grouped DNS work can use the additive batch helpers for ordered `A` + `AAAA` and authoritative multi-RR fanout slices without changing the single-question contract; `tls` and `dnschain` use that path where it removes duplicated probe-local loops
- extend per-resolver caching below the final lookup result where repeated probe flows benefit from shared execution state: repeated walks across the same zone should be able to reuse enclosing-zone discovery, delegation-chain material, authoritative server sets, validated DNSKEY or DS state, and NS host-address completion rather than re-walking every branch for each RR type
- keep any new batch or session surface as an additive API beside `Lookup(...)`, `Resolve(...)`, and `ResolveAuthoritative(...)`:
  - thin probes should not be forced onto the richer contract
  - existing probe code should continue to benefit from deeper internal caches even when it stays on the simple API
  - heavier probes such as `tls` may opt into the richer surface later when they need grouped questions, explicit shared execution traces, or batch-oriented diagnostics
- shared DNS wire-level test helpers now start in `internal/testkit/dnstest` with a minimal local authoritative UDP/TCP server harness; extend that harness toward truncation, timeout, `SERVFAIL`, referral, missing-glue, and DNSSEC-bogus scenarios instead of duplicating transport stubs in resolver or probe tests
- when extending `internal/testkit/dnstest`, keep a clear mapping from wire behavior to probe-facing semantics:
  - transport-only failures such as timeout or refused socket should continue to surface through transport-aware checks or traces rather than masquerading as DNS content verdicts
  - protocol-level negative or broken answers such as `SERVFAIL`, malformed referral chains, missing glue, or bogus DNSSEC proofs should remain available as DNS-layer facts that probes may interpret differently depending on their policy
  - the harness should therefore grow reusable packet scenarios first, while probe-local tests stay responsible for asserting how those scenarios map into `OK` or `WARNING` or `CRITICAL` or `UNKNOWN`
- deferred follow-up:
- add an explicit shared resolver short-circuit policy such as `--resolver-mode bundled|system` in the shared resolver or transport layer rather than as probe-local conditionals
- keep future retry behavior as an explicit policy discussion rather than an implicit transport habit:
  - clarify whether retries belong in low-level exchange, per-endpoint fanout, authoritative server selection, or only in specific probes
  - distinguish idempotent retry for transport noise from semantic re-query that could hide consistency problems or inflate traffic
  - decide how retry attempts should appear in resolver trace or stats so operators can tell "first-shot success" from "eventual success after retries"
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
- `-H/--hostname` means "start from this owner name, derive its enclosing zone, validate the delegation path, and then validate owner-level RR presence appropriate for the probe"
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

Current TLS follow-up plan:

- current state:
- `tls` shares the probe CLI/runtime contract, the staged `checkreport` output model, and the message-catalog-backed finding catalog used by the newer probes
- `tls` exercises real TCP TLS and SMTP `STARTTLS` execution paths, bundled-resolver-backed CAA and DANE lookups, SCT presence detection from certificate or OCSP sources, stapled and active OCSP handling, and local integration coverage for handshake, hostname, DANE, cipher, and revocation paths
- `tls` intentionally treats missing OCSP staples as informational by default; warning or critical status comes from invalid, revoked, or policy-requested active responder failures
- `tls` reports address-set transport coverage separately from endpoint-semantic comparison:
  - `coverage.addresses` captures which resolved `A` or `AAAA` endpoints completed the handshake, which genuinely failed transport, and which were skipped because the current `auto` IP-family policy classified that family as locally unavailable
  - `coverage.endpoint_semantics` compares transport, PKI, OCSP, CT, DANE, and SNI slices across successful endpoints
  - `endpoint_semantics.profiles` exposes structured per-endpoint semantic profiles in JSON through evidence items so external renderers do not need to parse the aggregated human-readable profile strings
  - `pki.graph` exposes a structured certificate graph for the primary detailed endpoint in JSON through graph evidence items; it includes certificate nodes, presented-chain edges, verified-path edges, graph-scope attributes, and explicit node classifications such as `presented_and_verified`, `presented_only`, and `verified_only`, plus rollover-tail hints suitable for external graph rendering
  - modern web no-SNI divergence is informational unless a stricter future policy mode asks for alerting
- `tls`, `httpx`, and `dnsresolver` share the same common transport-family flags and policy semantics rather than carrying probe-local spellings:
  - `--ip-family auto|ipv4|ipv6|dual`
  - `--use-ipv4` and `--use-ipv6` are sugar aliases for the corresponding forced modes
- live smoke artifacts are kept under `build/tls-live-matrix-YYYY-MM-DD/` as repository-local comparison points rather than as normative fixtures
- current live smoke set on 2026-06-19:
  - `www.cloudflare.com`: secure negative `TLSA` answer under delegated `www.cloudflare.com.`; useful regression target for authority reuse, SOA-owner final-zone refinement, and DNSSEC-authenticated no-data; with the current `auto` family policy the local unavailable `AAAA` endpoints are recorded as skipped rather than as failures, so the current result is `WARNING` only because Cloudflare still accepts a weak TLS 1.2 CBC suite, while CAA and DANE both validate
  - `google.com`: useful policy-discussion target because it currently accepts TLS 1.0, TLS 1.1, and a weak TLS 1.2 CBC suite on 2026-06-19; this is treated as a real finding set rather than a probe bug
  - `github.com`: useful weak-CBC discussion target without deprecated TLS 1.0 or 1.1 acceptance in current runs
  - `habr.com`: project-local target that currently accepts a weak TLS 1.2 CBC suite in live runs
  - `www.debian.org`: multi-address target with valid DANE-negative behavior and local IPv6 degradation visibility; with the current `auto` family policy the local unavailable `AAAA` endpoints are recorded as skipped and the host presently reports `OK`
  - `www.wikipedia.org`: compact dual-stack target that highlights local IPv6 transport degradation with a simpler address set than Debian; with the current `auto` family policy the local unavailable `AAAA` endpoint is recorded as skipped and the host presently reports `OK`
- current default policy for deprecated protocol acceptance is intentionally strict:
  - successful negotiation of `TLS 1.0` or `TLS 1.1` is `CRITICAL` by default, because the probe is positioned as a preventive security and compliance checker rather than as a pure reachability scanner
  - weak but modern-path-adjacent findings such as accepted TLS 1.2 CBC suites remain `WARNING` by default because the service still stays on a modern protocol line even though its policy breadth is too permissive
  - if legacy compatibility ever needs softer handling, add an explicit probe policy mode for deprecated protocol severity instead of silently downgrading the default
- near-term follow-up:
- make the current prototype boundary explicit and keep the public CLI surface honest: real `tcp` and `STARTTLS smtp|imap` paths stay in scope, while unimplemented transports or grading-style extensions stay outside the accepted user-facing contract until they have working analyzers behind them
- make multi-address service semantics explicit in the result model and policy surface: transport fallback may stay opportunistic, but PKI, OCSP, CT, DANE, and negotiated-parameter conclusions should distinguish single-endpoint success from full `A` + `AAAA` coverage
- report address-set coverage as a first-class result concept: the report should expose discovered addresses, attempted addresses, successful addresses, and semantic divergence per address so `OK` means more than "one endpoint happened to work"
- finish the per-address aggregation policy for the checks that materially define service identity and trust:
  - certificate identity and expiry
  - negotiated protocol and ALPN
  - trust-path result and chosen path
  - OCSP and SCT facts
  - DANE result where applicable
- finish the current PKI graph phase rather than leaving it implicit in chain-validation text:
  - distinguish presented chain completeness from built trust-path success
  - keep degraded or expired alternative tails visible without automatically collapsing the whole service when policy allows a healthy active path
  - make dual-stack or alternative-branch policy decisions come from path facts rather than narrative heuristics
  - keep the JSON graph contract semantically explicit for external renderers:
    - graph payload should distinguish node kinds, edge kinds, presented versus unpresented trust anchors, verified path membership, and path ordering without requiring text parsing
    - the current structured graph covers the primary detailed endpoint only; if multi-endpoint PKI graph rendering becomes important, add an endpoint-keyed graph slice rather than overloading the single primary graph block
    - current graph semantics already expose explicit `presented_only` and `verified_only` nodes plus presented-tail hints, but they still do not model richer path-level facts such as named alternative chains, cross-sign lineage labels, or policy-classified rollover branches
- finish the current revocation and CT phase as a coherent operator-facing model:
  - stapled OCSP, active responder OCSP, and strict comparison should produce explicit source-aware facts in verbose and JSON
  - CT should distinguish SCT presence by certificate, stapled OCSP, or TLS extension source and only degrade status when the active policy actually requires CT
- finish the current cipher and protocol phase at the policy level that matches the implemented probes:
  - deprecated protocol acceptance stays explicit
  - weak TLS 1.2 suite acceptance stays explicit
  - negotiated modern cipher, forward-secrecy characteristics, and ALPN expectations should be surfaced consistently per address
- treat ALPN as both an observed fact and an optional policy boundary:
  - negotiated ALPN should remain visible in structured output even when the user did not ask for a specific expected value
  - explicit expectations such as `h2` should stay probe policy, not an implicit default for every TLS service
  - ALPN facts may inform later transport expansion, but QUIC or HTTP/3 probing remains a separate future transport slice rather than something inferred from a TCP TLS handshake alone
- add an explicit SNI or no-SNI execution slice for TCP TLS so the probe can surface virtual-host surprises or default-certificate divergence instead of leaving that class of issue to external tools:
  - for contemporary web TLS this slice is informational by default; many legitimate HTTPS deployments do not promise a meaningful no-SNI fallback profile
  - if no-SNI behavior later needs to become alertable, it should do so through an explicit policy mode rather than as the baseline web expectation
- keep ECH work separate from ordinary SNI checks:
  - TLS 1.3 still uses the ordinary `server_name` extension as part of the visible ClientHello path in the non-ECH case, and servers may require it; no-SNI and SNI-selected profile comparison therefore remains useful even if ECH later enters scope
  - ECH readiness depends on external bootstrap material rather than on the TCP TLS handshake alone; for HTTPS-style targets that bootstrap is tied to SVCB or HTTPS RR semantics and associated ECH configuration delivery
  - an eventual ECH probe should therefore begin as an explicit readiness or bootstrap slice, not by overloading the existing SNI or no-SNI comparison checks
  - if active ECH handshakes are added later, they should be reported as a distinct execution slice beside plain SNI and no-SNI TCP TLS, with outcome comparison across those modes rather than silent substitution
- keep resolver-backed DNS work efficient inside one probe run:
  - repeated `A` + `AAAA` + `CAA` + `TLSA` work should reuse one resolver instance and eventually one richer zone-session execution path rather than behaving like isolated cold-start walks
  - resolver output used by TLS should stay explanation-friendly in verbose and JSON when DNS becomes the reason handshake evaluation cannot proceed
- move any remaining transport- or service-level policy catalogs toward the same shared rule/message rails already used by the newer DNS probe surfaces
- keep the current timeout split visible and testable: overall `-t/--timeout` budget, DNS sub-deadlines, handshake sub-deadlines, and any future parallel address fanout must compose without hiding time-budget exhaustion
- freeze the prototype output contract before merge:
  - `nagios` and `json` outputs should carry the same top-level semantics
  - structured output should expose addresses, paths, revocation facts, CT facts, DANE or CAA facts, and suppressed findings without probe-local ambiguity
- keep a minimal live regression corpus and saved JSON artifacts for representative happy-path and degraded-path targets so output drift is caught before deeper refactors
- keep family-gated transport interpretation explicit in live matrix notes:
  - current resolver behavior filters unreachable DNS IP families up front for iterative DNS and authoritative fanout
  - service endpoint transport coverage in `auto` mode records locally unavailable families as skipped rather than as failed, so a host-local `IPv6` outage does not by itself trigger `tls_endpoint_failed`
  - forced modes such as `ipv6` or `dual` remain intentionally strict and may still surface those same endpoints as transport failures
  - if a future transport layer adopts real Happy Eyeballs for service handshakes, that should be reported as a transport execution strategy change rather than silently changing the meaning of coverage findings
- deferred follow-up:
- add QUIC / HTTP/3 transport coverage behind the existing transport contract instead of probe-local option drift
- deepen certificate-path graph handling for alternative chains, cross-signatures, and configurable treatment of expired rollover tails or degraded dual-stack branches
- broaden revocation and cipher policy beyond the current OCSP and weak-suite focus when there is a stable shared policy representation for those rule families

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
- temporary branch-split workflow:
  - the repository is still in a transitional phase where one probe branch may contain both general library refactors and still-unfinished probe-specific work
  - when that happens, it is acceptable to split the tree manually: stash unfinished probe-specific slices such as `tls` or `dnsrr`, switch to `chore/refactor`, and commit only the shared library, runtime, renderer, parser, or documentation layer
  - this is temporary workflow debt rather than a desired steady-state release process
  - use it only to avoid mixing unfinished probe semantics into otherwise commit-ready shared refactors
  - when in doubt, prefer leaving suspicious probe-driven API expansion out of the refactor commit and keep the refactor branch biased toward obviously reusable components

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
