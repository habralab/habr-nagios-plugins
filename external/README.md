# External Source Mirror

This directory is the repository-local mirror of external reference material and
vendored upstream artifacts used during development and, in some cases, at
runtime through `go:embed`.

Design goals:

- keep repeatedly used upstream material close to the code
- reduce repeated web searches and context churn during implementation work
- preserve provenance for both human-readable references and machine-consumed artifacts
- keep the tree organized by upstream source first, then by topic and artifact type

Top-level layout:

- `<source>/`: upstream source namespace such as `ietf`, `iana`, `cabf`, `google`, `openai`
- `registry.json`: repository-wide index of mirrored materials

Within a source namespace:

- `docs/`: human-readable mirrored documentation
- `artifacts/`: files intended to be consumed by code or tooling
- `indexes/`: optional source-local registries when a subtree grows

Current examples:

- `ietf/rfc/`: mirrored RFC text files
- `iana/dns/artifacts/`: root hints and root trust anchor artifacts used by `dnschain`

Rules:

- prefer stable upstream text or otherwise durable source artifacts
- do not hand-edit mirrored source documents unless there is a local wrapper explaining why
- record each mirrored source in `registry.json`
- keep runtime-consumed files and human-readable docs adjacent when they come from the same upstream source
- when Go code needs to embed a canonical artifact from `external/`, a package-local `embeddata/` copy may exist as a build shim because `//go:embed` cannot reference parent paths

Known technical debt:

- some runtime-consumed artifacts currently exist twice: once here as the canonical mirror, and once under package-local `embeddata/` directories used by `go:embed`
- this duplication is intentional for now, but it needs a small lifecycle manager or sync helper so derived embed copies are refreshed from `external/` mechanically rather than by hand
