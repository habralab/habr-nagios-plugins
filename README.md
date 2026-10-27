# habr-nagios-plugins

Small self-contained monitoring plugins for Nagios, Icinga, LibreNMS, and similar systems.

Repository: `https://github.com/habralab/habr-nagios-plugins`

## Current Probes

Release candidate probes:

- `check_sitemap`
- `check_robots`
- `check_dnschain`
- `check_tls`
- `check_dnsrr`

All five probes are included in the Debian release candidate packages. Each
probe's documented coverage limits still apply; in particular, `check_tls`
supports TCP and SMTP/IMAP STARTTLS, not QUIC, while `check_dnschain` does not
recursively validate CNAME targets in other zones.

`check_sitemap` validates sitemap discovery and sitemap tree integrity in a way that is useful for monitoring:

- `OK`, `WARNING`, `CRITICAL`, and `UNKNOWN` exit codes
- short Nagios-style summary output by default
- deeper diagnostics through `-v`, `-vv`, and `-vvv`
- support for `robots.txt`, sitemap indexes, XML/text sitemaps, and `.gz`
- redirect-aware discovery traces for `robots.txt` and common fallback paths
- cross-submit verification through delegated `robots.txt` discovery on foreign hosts
- UTF-8 and URL-escaping checks for text sitemap payloads
- validation of sitemap extensions: `xhtml:hreflang`, `image:image`, `news:news`, and `video:video`
- `json` output for the same structured waterfall report used by the probe internally
- HTTP fetching resolves target hosts through the bundled iterative DNS resolver instead of relying on the host OS recursive resolver
- Debian packaging as `habr-nagios-plugin-sitemap`

`check_robots` validates `robots.txt` availability, syntax, policy shape, and documented crawler behavior:

- `OK`, `WARNING`, `CRITICAL`, and `UNKNOWN` exit codes
- short Nagios-style summary output by default
- deeper diagnostics through `-v`, `-vv`, and `-vvv`
- hostname-derived, base-URL, or explicit `robots.txt` targeting
- RFC-oriented default semantics with optional `vendor-aware` and `strict` behavior profiles
- checks for syntax, invalid or duplicate `Sitemap:` directives, invalid path patterns, empty payloads, redirect loops, and near-limit payload sizes
- built-in registries for directives, crawler and AI agent tokens, and documented behavior claims, all with provenance metadata
- optional policy assertions such as required `Sitemap`, required `User-agent`, required `Disallow`, and forbidden `Disallow`
- discoverable suppressible findings through `--list-error-slugs`
- `json` output for the same structured waterfall report used by the probe internally
- HTTP fetching resolves target hosts through the bundled iterative DNS resolver instead of relying on the host OS recursive resolver
- Debian packaging as `habr-nagios-plugin-robots`

`check_dnschain` is an authoritative DNS integrity checker:

- direct iterative discovery from bundled root hints instead of relying on the local recursive resolver
- short Nagios-style output by default
- `json` output for the same structured waterfall report
- checks cover delegation walk, child authoritative reachability, parent/child `NS` alignment, root trust-anchor bootstrapping, parent `DS` RRset signature validation, child `DNSKEY` RRset signature validation along secure hops, and per-endpoint `SOA` / `NS` / `DNSKEY` consistency checks across advertised authoritative addresses
- in hostname mode, the checker also verifies owner-level `CNAME` / `A` / `AAAA` presence and consistency on the final zone authoritative servers, following same-zone `CNAME` chains to terminal address data while treating foreign-zone `CNAME` targets as out of scope for recursive validation
- DNSSEC coverage includes secure-hop validation, parent-side authenticated denial for missing `DS` via exact `NSEC` / `NSEC3` proofs and `NSEC3` closest-encloser opt-out proofs, apex `NSEC3PARAM` policy and consistency checks, and sampled final-zone `NSEC3` `NXDOMAIN` / `NODATA` proof validation; full generic `NSEC` / `NSEC3` validation for every possible negative response pattern is out of scope for this phase
- authoritative transport probing attempts both IPv4 and IPv6 endpoints when available, and endpoint health is tracked per advertised address rather than only per nameserver name
- transport and DNSSEC semantics are reported separately: query timeouts and endpoint reachability issues surface as transport findings, while non-authoritative answers, bad signatures, and invalid proofs stay in delegation or DNSSEC findings

`check_tls` is a TLS transport and PKI integrity checker:

- short Nagios-style output by default
- `json` output for the same structured waterfall report
- scope includes direct TCP TLS plus SMTP/IMAP STARTTLS handshakes, negotiated version and ALPN reporting, certificate hostname and validity checks, basic trust-path validation against system or custom trust roots, weak key detection, negotiated-cipher inspection, weak TLS 1.2 cipher probing, and active downgrade probes for TLS 1.0 and TLS 1.1
- stapled OCSP responses are validated, optional active responder checks are available through `--ocsp-mode`, SCT presence is surfaced, and the probe performs authoritative CAA and DANE/TLSA lookups through bundled root hints with DNSSEC chain validation when the delegation is signed
- QUIC, broader cipher preference policy, and deeper certificate-path graph refinement stay outside the current phase

`check_dnsrr` is a thin authoritative DNS RR presence checker:

- short Nagios-style output by default
- `json` output for the same structured authoritative RR evaluation report
- authoritative zone discovery through bundled root hints instead of relying on the local recursive resolver
- checks whether a requested RR type is present on `any`, `all`, `master`, or `none` of the relevant authoritative endpoints
- optional DNSSEC interpretation modes for the queried RRset: `ignore`, `prefer`, or `require`
- useful for validating operational rollout of records such as `A`, `AAAA`, `TXT`, `MX`, `CAA`, `_dmarc`, `_acme-challenge`, or similar owner-specific data

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

Default local output for the dnschain probe:

```bash
build/check_dnschain
```

Default local output for the TLS probe:

```bash
build/check_tls
```

Default local output for the DNS RR probe:

```bash
build/check_dnsrr
```

If you need a debug-friendlier local build with symbols intact:

```bash
make build-debug
```

## Test

```bash
make vet
make lint
make test
make test-integration
make test-live
```

- `vet`: run `go vet ./...`
- `lint`: run `go vet` and `staticcheck` when `staticcheck` is installed
- `test`: default no-network unit and package tests
- `test-integration`: opt-in deterministic integration suites using local listeners or `httptest`
- `test-live`: opt-in external live-network regression suites

## Usage

```bash
./build/check_sitemap -H example.com
./build/check_sitemap -H example.com -vv
./build/check_sitemap -H example.com --output json
./build/check_sitemap --entrypoint https://example.com/sitemap.xml
./build/check_robots -H example.com
./build/check_robots --robots-url https://example.com/robots.txt --require-sitemap
./build/check_robots -H example.com --behavior-profile vendor-aware -vv
./build/check_robots -H example.com --output json
./build/check_robots --list-known-directives
./build/check_robots --list-known-agents
./build/check_dnschain -H www.example.com
./build/check_dnschain --zone example.com --output json
./build/check_dnschain -H habr.com -t 60s --query-timeout 3s -vv
./build/check_dnschain --zone habr.com --query-timeout 3s -vv
./build/check_dnschain --zone com --ignore-errors dnschain_child_soa_inconsistent -v
./build/check_tls -H www.example.com --output json
./build/check_tls -H smtp.example.com -p 587 --starttls smtp -vv
./build/check_dnsrr -H www.example.com --rrtype A --mode any
./build/check_dnsrr --zone example.com --owner _dmarc.example.com --rrtype TXT --mode all --dnssec-mode prefer
```

Installed Debian package payloads:

```bash
/usr/lib/nagios/plugins/check_habr_sitemap
/usr/lib/nagios/plugins/check_habr_robots
/usr/lib/nagios/plugins/check_habr_dnschain
/usr/lib/nagios/plugins/check_habr_dnsrr
/usr/lib/nagios/plugins/check_habr_tls
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

Build a Debian source package from a committed release tree:

```bash
make package-deb-source
```

This creates an upstream tarball from the committed source, excluding `debian/`,
then builds the Debian source package. Uncommitted source or packaging changes
are rejected so the tarball and Debian diff describe the same revision.

For a target-specific local snapshot build, prepend a changelog entry first:

```bash
make package-changelog DEB_DISTRIBUTION=noble VERSION=v1.1.0
make package-deb
```

`package-changelog` uses `SOURCE_DATE_EPOCH` when set, so snapshot versions and
changelog timestamps can be reproduced. It preserves earlier entries and
refuses to duplicate the current version. Edit the committed changelog entry
manually for a final release. Release packages include all five
probes listed above. The GitLab pipeline runs formatting, vet, unit and integration
tests, all probe builds, and Debian binary packaging before release.

## Versioning

Built binaries report version metadata via `-V`:

- tagged build: release tag plus commit hash
- untagged build on a branch: branch name plus commit hash
- detached `HEAD` or no git metadata: `dev` plus commit hash when available
- dirty worktree: `-dirty` suffix on the commit hash

## License

MIT. See [LICENSE](LICENSE).
