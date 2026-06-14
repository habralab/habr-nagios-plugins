# dnschain embeddata

This directory contains local copies of canonical upstream artifacts mirrored
under `external/`.

Why it exists:

- Go `//go:embed` patterns cannot reach files outside the current package tree.
- The canonical source-of-truth for mirrored upstream material lives under `external/`.
- `embeddata/` is therefore a packaging shim used only so the probe can embed those artifacts into the binary.

Current mapping:

- `embeddata/root.hints` <- `external/iana/dns/artifacts/root.hints`
- `embeddata/root-anchors.xml` <- `external/iana/dns/artifacts/root-anchors.xml`
- `embeddata/root-anchors.p7s` <- `external/iana/dns/artifacts/root-anchors.p7s`
- `embeddata/icannbundle.pem` <- `external/iana/dns/artifacts/icannbundle.pem`

When refreshing the canonical files under `external/`, update these local copies
before building.

Technical debt:

- this directory is a derived build shim, not a second source-of-truth
- refresh is still manual today; the repository should grow a small lifecycle manager or sync helper that copies canonical artifacts from `external/` into `embeddata/` and can validate that they match
