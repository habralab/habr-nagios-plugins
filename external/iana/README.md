# IANA mirror notes

## DNS artifacts

Paths:

- `dns/artifacts/root.hints`
- `dns/artifacts/root-anchors.xml`
- `dns/artifacts/root-anchors.p7s`
- `dns/artifacts/icannbundle.pem`

Refresh commands:

```bash
curl -sS -L https://www.internic.net/domain/named.root -o external/iana/dns/artifacts/root.hints
curl -sS -L https://data.iana.org/root-anchors/root-anchors.xml -o external/iana/dns/artifacts/root-anchors.xml
curl -sS -L https://data.iana.org/root-anchors/root-anchors.p7s -o external/iana/dns/artifacts/root-anchors.p7s
curl -sS -L https://data.iana.org/root-anchors/icannbundle.pem -o external/iana/dns/artifacts/icannbundle.pem
```

Notes:

- `root.hints` is consumed by `dnschain` as embedded runtime data.
- `root-anchors.xml` is currently the working trust-anchor source.
- `root-anchors.p7s` and `icannbundle.pem` are mirrored now so that supply-chain verification can be implemented without changing layout later.
