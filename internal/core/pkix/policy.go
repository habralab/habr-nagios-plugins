package pkix

import "fmt"

type UntrustedRootPolicy string

const (
	UntrustedRootCritical UntrustedRootPolicy = "critical"
	UntrustedRootWarning  UntrustedRootPolicy = "warning"
	UntrustedRootOK       UntrustedRootPolicy = "ok"
)

type DualStackPolicy string
type OCSPMode string

const (
	DualStackStrict   DualStackPolicy = "strict"
	DualStackDegraded DualStackPolicy = "degraded"
)

const (
	OCSPOff     OCSPMode = "off"
	OCSPStapled OCSPMode = "stapled"
	OCSPActive  OCSPMode = "active"
	OCSPStrict  OCSPMode = "strict"
)

func ParseUntrustedRootPolicy(raw string) (UntrustedRootPolicy, error) {
	switch UntrustedRootPolicy(raw) {
	case "", UntrustedRootCritical:
		return UntrustedRootCritical, nil
	case UntrustedRootWarning, UntrustedRootOK:
		return UntrustedRootPolicy(raw), nil
	default:
		return "", fmt.Errorf("invalid --policy-untrusted-root %q, expected critical, warning, or ok", raw)
	}
}

func ParseDualStackPolicy(raw string) (DualStackPolicy, error) {
	switch DualStackPolicy(raw) {
	case "", DualStackDegraded:
		return DualStackDegraded, nil
	case DualStackStrict:
		return DualStackStrict, nil
	default:
		return "", fmt.Errorf("invalid --policy-dual-stack %q, expected strict or degraded", raw)
	}
}

func ParseOCSPMode(raw string) (OCSPMode, error) {
	switch OCSPMode(raw) {
	case "", OCSPStapled:
		return OCSPStapled, nil
	case OCSPOff, OCSPActive, OCSPStrict:
		return OCSPMode(raw), nil
	default:
		return "", fmt.Errorf("invalid --ocsp-mode %q, expected off, stapled, active, or strict", raw)
	}
}
