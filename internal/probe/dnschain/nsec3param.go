package dnschain

import (
	"fmt"
	"sort"
	"strings"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/miekg/dns"
)

type nsec3ParamAssessment struct {
	State    checkreport.CheckState
	Message  string
	Evidence []checkreport.Evidence
}

func splitNSEC3PARAMAnswer(rrs []dns.RR, owner string) []*dns.NSEC3PARAM {
	var params []*dns.NSEC3PARAM
	for _, rr := range rrs {
		if v, ok := rr.(*dns.NSEC3PARAM); ok && dns.Fqdn(v.Header().Name) == dns.Fqdn(owner) {
			params = append(params, v)
		}
	}
	return params
}

func nsec3ParamSetFingerprint(params []*dns.NSEC3PARAM) string {
	if len(params) == 0 {
		return ""
	}
	parts := make([]string, 0, len(params))
	for _, param := range params {
		salt := "-"
		if param.SaltLength > 0 {
			salt = strings.ToUpper(param.Salt)
		}
		parts = append(parts, fmt.Sprintf("%d|%d|%d|%s", param.Hash, param.Flags, param.Iterations, salt))
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}

func assessNSEC3ParamPolicy(params []*dns.NSEC3PARAM) nsec3ParamAssessment {
	if len(params) == 0 {
		return nsec3ParamAssessment{}
	}

	var unsupportedHash []string
	var nonZeroFlags []string
	var nonZeroIterations []string
	var salted []string
	for _, param := range params {
		desc := fmt.Sprintf("hash=%d flags=%d iter=%d salt=%s", param.Hash, param.Flags, param.Iterations, nsec3SaltValue(param))
		if param.Hash != dns.SHA1 {
			unsupportedHash = append(unsupportedHash, desc)
		}
		if param.Flags != 0 {
			nonZeroFlags = append(nonZeroFlags, desc)
		}
		if param.Iterations != 0 {
			nonZeroIterations = append(nonZeroIterations, desc)
		}
		if param.SaltLength > 0 {
			salted = append(salted, desc)
		}
	}

	evidence := checkreport.Evidence{
		Kind:    "dnssec.nsec3param_policy",
		Summary: "NSEC3PARAM policy assessment for the zone apex",
		Attributes: []checkreport.KV{
			{Key: "records", Value: fmt.Sprintf("%d", len(params))},
			{Key: "fingerprint", Value: nsec3ParamSetFingerprint(params)},
		},
	}
	for _, param := range params {
		evidence.Attributes = append(evidence.Attributes, checkreport.KV{
			Key:   "record",
			Value: fmt.Sprintf("hash=%d flags=%d iter=%d salt=%s", param.Hash, param.Flags, param.Iterations, nsec3SaltValue(param)),
		})
	}

	var issues []string
	if len(unsupportedHash) > 0 {
		evidence.Attributes = append(evidence.Attributes, checkreport.KV{
			Key:   "unsupported_hash",
			Value: strings.Join(unsupportedHash, "; "),
		})
		issues = append(issues, "unsupported NSEC3 hash algorithm")
	}
	if len(nonZeroFlags) > 0 {
		evidence.Attributes = append(evidence.Attributes, checkreport.KV{
			Key:   "non_zero_flags",
			Value: strings.Join(nonZeroFlags, "; "),
		})
		issues = append(issues, "non-zero NSEC3PARAM flags")
	}
	if len(nonZeroIterations) > 0 {
		evidence.Attributes = append(evidence.Attributes, checkreport.KV{
			Key:   "non_zero_iterations",
			Value: strings.Join(nonZeroIterations, "; "),
		})
		issues = append(issues, "iterations > 0")
	}
	if len(salted) > 0 {
		evidence.Attributes = append(evidence.Attributes, checkreport.KV{
			Key:   "non_empty_salt",
			Value: strings.Join(salted, "; "),
		})
		issues = append(issues, "non-empty salt")
	}

	if len(issues) == 0 {
		return nsec3ParamAssessment{
			State:   checkreport.CheckPass,
			Message: "NSEC3PARAM used RFC 9276-recommended settings",
			Evidence: []checkreport.Evidence{
				evidence,
			},
		}
	}

	return nsec3ParamAssessment{
		State:   checkreport.CheckWarning,
		Message: fmt.Sprintf("NSEC3PARAM departed from RFC 9276 recommendations: %s", strings.Join(issues, ", ")),
		Evidence: []checkreport.Evidence{
			evidence,
		},
	}
}

func nsec3SaltValue(param *dns.NSEC3PARAM) string {
	if param == nil || param.SaltLength == 0 {
		return "-"
	}
	return strings.ToUpper(param.Salt)
}
