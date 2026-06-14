# dnschain live corpus

This file tracks real Internet zones used as an opt-in live regression corpus
for `check_dnschain`.

Current cases:

- `example.com`
  - expected class: secure signed delegation
  - expected outcome: `OK`
  - useful for: root trust anchor bootstrap, secure hop validation, parent `DS`
    signature validation, child `DNSKEY` signature validation

- `neverssl.com`
  - expected class: insecure delegation without `DS`
  - expected outcome: `OK`
  - useful for: authenticated denial of `DS` through parent-side `NSEC3`
    closest-encloser opt-out proof

- `dnssec-failed.org`
  - expected class: intentionally broken DNSSEC
  - expected outcome: `CRITICAL`
  - useful for: parent `DS` to child `DNSKEY` mismatch detection

- `sk.`
  - expected class: signed delegation with live authoritative drift
  - expected outcome: `WARNING`
  - useful for: multi-`DS` delegation and live `SOA` inconsistency detection

- `ua.`
  - expected class: signed delegation with multiple `DS` digests
  - expected outcome: `OK`
  - useful for: one `DNSKEY` matching multiple parent `DS` digest variants

- `arpa.`
  - expected class: signed infrastructure zone apex
  - expected outcome: `OK`
  - useful for: answer-style apex delegation discovery and root-to-child secure hop
  - note: useful as an exploratory live case, but too operationally noisy for
    the strict `test-live` suite because authoritative `SOA` consistency can
    drift in the wild

- `e164.arpa.`
  - expected class: signed child under an intermediate signed parent
  - expected outcome: `OK`
  - useful for: canonical zone-chain discovery through `arpa.` and secure-hop
    validation across intermediate signed parents
  - note: useful as an exploratory live case, but too operationally noisy for
    the strict `test-live` suite because individual authoritative endpoints may
    time out intermittently

- `in-addr.arpa.`, `ip6.arpa.`
  - expected class: signed children under an intermediate signed parent with
    extra rollover-tail `DS` records of the same algorithm
  - expected outcome: `OK`
  - useful for: canonical zone-chain discovery through `arpa.` without
    false warnings when multiple parent `DS` records still collapse to the same
    covered DNSSEC algorithm

Notes:

- These checks are intentionally opt-in under the `live` build tag because they
  depend on external network reachability and third-party zones remaining
  stable.
- When replacing or adding a corpus entry, prefer domains whose failure mode is
  simple, well-understood, and likely to remain stable over time.
