package checkreport

import (
	"fmt"
	"sort"
	"strings"
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

func LegacyRuleStatus(check Check) string {
	if value := MetaValue(check.Meta, "status", ""); value != "" {
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

func LegacyRuleChecks(stages []Stage) []Check {
	var checks []Check
	for _, stage := range stages {
		for _, check := range stage.Checks {
			for _, item := range check.Meta {
				if item.Key == "legacy_rule" && item.Value == "true" {
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
