package probecli

import (
	"context"
	"strings"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/core/ipfamily"
)

func DecorateReportWithTransportFamilyRuntime(ctx context.Context, policy ipfamily.Policy, timeout time.Duration, report *checkreport.Report) {
	if report == nil {
		return
	}
	policy = normalizedTransportFamilyPolicy(policy)
	inspectTimeout := 500 * time.Millisecond
	if timeout > 0 && timeout < inspectTimeout {
		inspectTimeout = timeout
	}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining > 0 && remaining < inspectTimeout {
			inspectTimeout = remaining
		}
	}
	inspectCtx, cancel := context.WithTimeout(context.Background(), inspectTimeout)
	defer cancel()

	assessment := ipfamily.DetectAssessment(inspectCtx, inspectTimeout)
	detected := assessment.Capabilities()
	effective := policy.EffectiveCapabilities(detected)
	report.Stages = append(report.Stages, transportFamilyRuntimeStage(policy, assessment, effective))
}

func transportFamilyRuntimeStage(policy ipfamily.Policy, assessment ipfamily.Assessment, effective ipfamily.Capabilities) checkreport.Stage {
	detected := assessment.Capabilities()
	check := checkreport.Check{
		ID:      "runtime.transport_family.inspect",
		State:   transportFamilyRuntimeState(policy, detected, effective),
		Subject: string(policy),
		Message: transportFamilyRuntimeMessage(policy, assessment, effective),
		Meta: []checkreport.KV{
			{Key: "policy", Value: string(policy)},
			{Key: "detected_ipv4", Value: boolString(detected.IPv4)},
			{Key: "detected_ipv6", Value: boolString(detected.IPv6)},
			{Key: "detected_ipv4_state", Value: string(assessment.IPv4.Availability)},
			{Key: "detected_ipv6_state", Value: string(assessment.IPv6.Availability)},
			{Key: "detected_ipv4_reason", Value: assessment.IPv4.Reason},
			{Key: "detected_ipv6_reason", Value: assessment.IPv6.Reason},
			{Key: "effective_ipv4", Value: boolString(effective.IPv4)},
			{Key: "effective_ipv6", Value: boolString(effective.IPv6)},
			{Key: "cached", Value: boolString(assessment.Cached)},
		},
	}
	return checkreport.Stage{
		ID:     "runtime.transport_family",
		Title:  "Runtime Transport Family",
		Status: checkreport.StatusOK,
		Checks: []checkreport.Check{check},
	}
}

func transportFamilyRuntimeState(policy ipfamily.Policy, detected, effective ipfamily.Capabilities) checkreport.CheckState {
	switch policy {
	case ipfamily.PolicyAuto:
		if detected.IPv4 != detected.IPv6 {
			return checkreport.CheckNote
		}
	case ipfamily.PolicyIPv4:
		if !detected.IPv4 {
			return checkreport.CheckNote
		}
	case ipfamily.PolicyIPv6:
		if !detected.IPv6 {
			return checkreport.CheckNote
		}
	case ipfamily.PolicyDual:
		if !detected.IPv4 || !detected.IPv6 {
			return checkreport.CheckNote
		}
	}
	_ = effective
	return checkreport.CheckPass
}

func transportFamilyRuntimeMessage(policy ipfamily.Policy, assessment ipfamily.Assessment, effective ipfamily.Capabilities) string {
	detected := assessment.Capabilities()
	detectedLabel := "detected=" + capabilitiesLabel(detected)
	effectiveLabel := "effective=" + capabilitiesLabel(effective)
	reasonsLabel := "reasons=ipv4:" + assessment.IPv4.Reason + ",ipv6:" + assessment.IPv6.Reason
	switch policy {
	case ipfamily.PolicyAuto:
		return "auto family policy selected transport families from local capability detection: " + detectedLabel + ", " + effectiveLabel + ", " + reasonsLabel
	case ipfamily.PolicyIPv4, ipfamily.PolicyIPv6, ipfamily.PolicyDual:
		return "explicit family policy overrides local auto-selection: policy=" + string(policy) + ", " + detectedLabel + ", " + effectiveLabel + ", " + reasonsLabel
	default:
		return "transport family runtime state: policy=" + string(policy) + ", " + detectedLabel + ", " + effectiveLabel + ", " + reasonsLabel
	}
}

func capabilitiesLabel(caps ipfamily.Capabilities) string {
	switch {
	case caps.IPv4 && caps.IPv6:
		return "ipv4+ipv6"
	case caps.IPv4:
		return "ipv4"
	case caps.IPv6:
		return "ipv6"
	default:
		return "none"
	}
}

func normalizedTransportFamilyPolicy(policy ipfamily.Policy) ipfamily.Policy {
	if strings.TrimSpace(string(policy)) == "" {
		return ipfamily.PolicyAuto
	}
	return policy
}
