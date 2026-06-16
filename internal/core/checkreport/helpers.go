package checkreport

import (
	"fmt"
	"sort"
	"strings"

	"github.com/habralab/habr-nagios-plugins/internal/core/msgcatalog"
)

func StageByID(report *Report, id string) *Stage {
	for i := range report.Stages {
		if report.Stages[i].ID == id {
			return &report.Stages[i]
		}
	}
	return nil
}

func TargetValue(report *Report, role, fallback string) string {
	for _, target := range report.Targets {
		if target.Role == role {
			return target.Value
		}
	}
	return fallback
}

func MetaValue(meta []KV, key, fallback string) string {
	for _, item := range meta {
		if item.Key == key {
			return item.Value
		}
	}
	return fallback
}

func MetricValue(report *Report, name, fallback string) string {
	for _, metric := range report.Metrics {
		if metric.Name == name {
			return metric.DisplayValue()
		}
	}
	return fallback
}

func CheckDisplayState(check Check) string {
	if value := MetaValue(check.Meta, "display_state", ""); value != "" {
		return value
	}
	switch check.State {
	case CheckCritical:
		return "FAIL"
	case CheckWarning:
		return "WARN"
	case CheckPass:
		return "PASS"
	case CheckIgnore:
		return "IGNORE"
	default:
		return "NOTE"
	}
}

func ChecksByMeta(stages []Stage, key, value string) []Check {
	var checks []Check
	for _, stage := range stages {
		for _, check := range stage.Checks {
			for _, item := range check.Meta {
				if item.Key == key && item.Value == value {
					checks = append(checks, check)
					break
				}
			}
		}
	}
	sort.SliceStable(checks, func(i, j int) bool {
		return MetaValue(checks[i].Meta, "order", "") < MetaValue(checks[j].Meta, "order", "")
	})
	return checks
}

func NewRuleCheck(order int, stateLabel, id, subject, message string) Check {
	return Check{
		ID:      id,
		State:   RuleState(stateLabel),
		Subject: subject,
		Message: message,
		Meta: []KV{
			{Key: "kind", Value: "rule"},
			{Key: "order", Value: fmt.Sprintf("%06d", order)},
			{Key: "display_state", Value: strings.ToUpper(strings.TrimSpace(stateLabel))},
		},
	}
}

func RuleState(status string) CheckState {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case "FAIL":
		return CheckCritical
	case "WARN":
		return CheckWarning
	case "PASS":
		return CheckPass
	case "IGNORE":
		return CheckIgnore
	case "UNKNOWN":
		return CheckUnknown
	default:
		return CheckNote
	}
}

func Perfdata(report *Report, includeDuration bool) string {
	if report == nil {
		return ""
	}
	parts := make([]string, 0, len(report.Metrics)+1)
	for _, metric := range report.Metrics {
		parts = append(parts, fmt.Sprintf("%s=%s", metric.Name, metric.DisplayValue()))
	}
	if includeDuration {
		parts = append(parts, fmt.Sprintf("elapsed_ms=%d", report.DurationMS))
	}
	return strings.Join(parts, " ")
}

func CountMetric(name string, value int) Metric {
	v := float64(value)
	return Metric{
		Name:   name,
		Type:   "count",
		Value:  fmt.Sprintf("%d", value),
		Number: &v,
	}
}

func UintMetric(name string, value uint64) Metric {
	v := float64(value)
	return Metric{
		Name:   name,
		Type:   "count",
		Value:  fmt.Sprintf("%d", value),
		Number: &v,
	}
}

func EmptyAsDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func SectionTitle(key string) string {
	return msgcatalog.DefaultSummaryOrKey("common_section_" + strings.TrimSpace(key))
}
