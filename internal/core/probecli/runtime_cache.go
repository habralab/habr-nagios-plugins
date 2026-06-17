package probecli

import (
	"context"
	"strings"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/core/sharedcache"
)

func DecorateReportWithCacheBackendInspection(ctx context.Context, cacheBackend string, active bool, report *checkreport.Report) {
	if report == nil {
		return
	}
	timeout := 500 * time.Millisecond
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining > 0 && remaining < timeout {
			timeout = remaining
		}
	}
	inspectCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	inspection := sharedcache.InspectBackendFromDSN(inspectCtx, cacheBackend, timeout)
	stage := checkreport.Stage{
		ID:     "runtime.cache_backend",
		Title:  "Runtime Cache Backend",
		Status: checkreport.StatusOK,
		Checks: []checkreport.Check{cacheBackendInspectionCheck(inspection, cacheBackendUsageState(inspection, active))},
	}
	if note := strings.TrimSpace(inspection.Message); note != "" {
		stage.Notes = append(stage.Notes, note)
	}
	report.Stages = append(report.Stages, stage)
}

func cacheBackendInspectionCheck(inspection sharedcache.BackendInspection, usageState string) checkreport.Check {
	state := checkreport.CheckNote
	if inspection.Code == "backend_ok" || (!inspection.Descriptor.External && inspection.Descriptor.Supported) {
		state = checkreport.CheckPass
	}
	message := strings.TrimSpace(inspection.Message)
	if message == "" {
		message = strings.TrimSpace(inspection.Descriptor.Description)
	}
	check := checkreport.Check{
		ID:      "runtime.cache_backend.inspect",
		State:   state,
		Subject: cacheBackendSubject(inspection),
		Message: message,
		Meta: []checkreport.KV{
			{Key: "code", Value: inspection.Code},
			{Key: "kind", Value: inspection.Descriptor.Kind},
			{Key: "transport", Value: inspection.Descriptor.Transport},
			{Key: "external", Value: boolString(inspection.Descriptor.External)},
			{Key: "supported", Value: boolString(inspection.Descriptor.Supported)},
			{Key: "usage_state", Value: usageState},
		},
	}
	if inspection.Descriptor.UnsupportedMode != "" {
		check.Meta = append(check.Meta, checkreport.KV{Key: "unsupported_mode", Value: inspection.Descriptor.UnsupportedMode})
	}
	if inspection.ServerRole != "" {
		check.Meta = append(check.Meta, checkreport.KV{Key: "server_role", Value: inspection.ServerRole})
	}
	if inspection.Endpoint != "" {
		check.Meta = append(check.Meta, checkreport.KV{Key: "endpoint", Value: inspection.Endpoint})
	}
	if len(inspection.Descriptor.Warnings) > 0 {
		check.Evidence = append(check.Evidence, checkreport.Evidence{
			Kind:       "runtime",
			Summary:    "shared cache backend warnings",
			Attributes: kvsFromStrings("warning", inspection.Descriptor.Warnings),
		})
	}
	return check
}

func cacheBackendUsageState(inspection sharedcache.BackendInspection, active bool) string {
	if !inspection.Descriptor.External {
		return "internal_only"
	}
	if active {
		return "active"
	}
	return "configured_but_unused"
}

func cacheBackendSubject(inspection sharedcache.BackendInspection) string {
	if strings.TrimSpace(inspection.Descriptor.RawDSN) != "" {
		return inspection.Descriptor.RawDSN
	}
	if inspection.Descriptor.Kind != "" {
		return inspection.Descriptor.Kind
	}
	return "cache-backend"
}

func kvsFromStrings(key string, values []string) []checkreport.KV {
	out := make([]checkreport.KV, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		out = append(out, checkreport.KV{Key: key, Value: value})
	}
	return out
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
