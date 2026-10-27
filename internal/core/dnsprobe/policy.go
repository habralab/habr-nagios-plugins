package dnsprobe

import "fmt"

type PresenceMode string

const (
	PresenceAny    PresenceMode = "any"
	PresenceMaster PresenceMode = "master"
	PresenceAll    PresenceMode = "all"
	PresenceNone   PresenceMode = "none"
)

type DNSSECMode string

const (
	DNSSECIgnore  DNSSECMode = "ignore"
	DNSSECPrefer  DNSSECMode = "prefer"
	DNSSECRequire DNSSECMode = "require"
)

func IsValidPresenceMode(mode PresenceMode) bool {
	switch mode {
	case PresenceAny, PresenceMaster, PresenceAll, PresenceNone:
		return true
	default:
		return false
	}
}

func IsValidDNSSECMode(mode DNSSECMode) bool {
	switch mode {
	case DNSSECIgnore, DNSSECPrefer, DNSSECRequire:
		return true
	default:
		return false
	}
}

func PresenceModeAllowed() []string {
	return []string{
		string(PresenceAny),
		string(PresenceMaster),
		string(PresenceAll),
		string(PresenceNone),
	}
}

func DNSSECModeAllowed() []string {
	return []string{
		string(DNSSECIgnore),
		string(DNSSECPrefer),
		string(DNSSECRequire),
	}
}

func EvaluatePresenceMode(mode PresenceMode, rrtype, scope string, authoritative, present, failed int, matcher *RRValueMatcher) (string, bool, string, string) {
	subject := matcherSubject(rrtype, matcher)
	switch mode {
	case PresenceAny:
		if present > 0 {
			return fmt.Sprintf("%s was observed on at least one authoritative endpoint within %s", subject, scope), true, "", ""
		}
		if failed > 0 {
			return fmt.Sprintf("%s could not be confirmed on any authoritative endpoint within %s", subject, scope), false, "dnsrr_inconclusive", fmt.Sprintf("%s may be present on an unreachable authoritative endpoint within %s", subject, scope)
		}
		return fmt.Sprintf("%s was not observed on any authoritative endpoint within %s", subject, scope), false, "dnsrr_not_found", fmt.Sprintf("%s was not present on any authoritative endpoint within %s", subject, scope)
	case PresenceMaster:
		if present > 0 {
			return fmt.Sprintf("%s was observed on the formal master %s", subject, scope), true, "", ""
		}
		if failed > 0 {
			return fmt.Sprintf("%s could not be confirmed on the formal master %s", subject, scope), false, "dnsrr_inconclusive", fmt.Sprintf("the formal master %s did not return a usable answer for %s", scope, subject)
		}
		return fmt.Sprintf("%s was not observed on the formal master %s", subject, scope), false, "dnsrr_not_found", fmt.Sprintf("%s was not present on the formal master %s", subject, scope)
	case PresenceAll:
		if authoritative > 0 && present == authoritative && failed == 0 {
			return fmt.Sprintf("%s was observed on all authoritative endpoints within %s", subject, scope), true, "", ""
		}
		if present == authoritative && failed > 0 {
			return fmt.Sprintf("%s could not be confirmed on all authoritative endpoints within %s", subject, scope), false, "dnsrr_inconclusive", fmt.Sprintf("some authoritative endpoints did not return a usable answer for %s within %s", subject, scope)
		}
		return fmt.Sprintf("%s was not confirmed on all authoritative endpoints within %s", subject, scope), false, "dnsrr_not_found", fmt.Sprintf("%s was not present on every authoritative endpoint within %s", subject, scope)
	case PresenceNone:
		if authoritative > 0 && present == 0 && failed == 0 {
			return fmt.Sprintf("%s is absent on all authoritative endpoints within %s", subject, scope), true, "", ""
		}
		if present == 0 && failed > 0 {
			return fmt.Sprintf("%s absence could not be confirmed on all authoritative endpoints within %s", subject, scope), false, "dnsrr_inconclusive", fmt.Sprintf("some authoritative endpoints did not return a usable answer for %s within %s", subject, scope)
		}
		return fmt.Sprintf("%s was observed where absence was expected within %s", subject, scope), false, "dnsrr_unexpected_presence", fmt.Sprintf("%s was present on at least one authoritative endpoint within %s", subject, scope)
	default:
		return fmt.Sprintf("%s evaluation mode %q is not implemented", subject, mode), false, "dnsrr_not_found", fmt.Sprintf("presence mode %q is not implemented", mode)
	}
}
