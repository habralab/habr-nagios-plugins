package sitemap

import (
	"fmt"
	"strings"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
)

func (r *Result) reportView() *checkreport.Report {
	if r.Report.Probe != "" {
		return &r.Report
	}
	report := checkreport.Report{
		Probe:         Meta.Slug,
		Target:        r.reportPrimaryTarget(),
		PrimaryTarget: r.reportPrimaryTarget(),
		Status:        r.reportStatus(),
		Summary:       r.summaryMessage(),
		Partial:       !r.hasReliableStats(),
		DurationMS:    r.Perf.Elapsed.Milliseconds(),
		Targets: []checkreport.Target{
			{Role: "source", Value: r.TargetSource},
			{Role: "effective_base", Value: emptyAsDash(r.EffectiveBaseURL)},
			{Role: "hostname", Value: emptyAsDash(r.Config.Hostname)},
			{Role: "url", Value: emptyAsDash(r.Config.URL)},
			{Role: "entrypoint", Value: emptyAsDash(r.Config.Entrypoint)},
		},
		Meta: []checkreport.KV{
			{Key: "discovered_via", Value: emptyAsDash(r.DiscoveredVia)},
			{Key: "strict", Value: fmt.Sprintf("%t", r.Config.Strict)},
			{Key: "allow_cross_host", Value: fmt.Sprintf("%t", r.Config.AllowCrossHost)},
			{Key: "fallback_probe", Value: fmt.Sprintf("%t", r.Config.FallbackProbe)},
			{Key: "fallback_status", Value: r.Config.FallbackStatus},
			{Key: "max_depth", Value: fmt.Sprintf("%d", r.Config.MaxDepth)},
			{Key: "max_files", Value: fmt.Sprintf("%d", r.Config.MaxFiles)},
			{Key: "max_urls", Value: fmt.Sprintf("%d", r.Config.MaxURLs)},
		},
		Metrics: []checkreport.Metric{
			countMetric("sitemap_files", len(r.Documents)),
			countMetric("urls", r.TotalURLs),
			countMetric("depth", r.MaxObservedDepth),
			countMetric("warnings", r.countProblems(SeverityWarning)),
			countMetric("criticals", r.countProblems(SeverityCritical)),
			countMetric("ignored", len(r.IgnoredProblems)),
			countMetric("bytes_net", r.Perf.TotalNetBytes),
			countMetric("bytes_raw", r.Perf.TotalRawBytes),
			uintMetric("heap_alloc_peak", r.Perf.PeakHeapAlloc),
			uintMetric("heap_sys_peak", r.Perf.PeakHeapSys),
		},
		Findings:           makeReportFindings(r.Problems),
		SuppressedFindings: makeReportFindings(r.IgnoredProblems),
		Traces:             makeHTTPTraces(r.HTTPTrace),
	}
	if report.Partial {
		report.CoverageNote = "summary stats are partial because traversal ended in a timeout, fetch failure, HTTP error, or local traversal limit"
	}
	report.Stages = []checkreport.Stage{
		r.makeTargetStage(),
		r.makeDiscoveryStage(),
		r.makeValidationStage(),
		r.makeDocumentsStage(),
		r.makePerformanceStage(),
	}
	r.Report = report
	return &r.Report
}

func (r *Result) reportPrimaryTarget() string {
	switch {
	case len(r.Entrypoints) > 0:
		return r.Entrypoints[0]
	case r.Config.Entrypoint != "":
		return r.Config.Entrypoint
	case r.EffectiveBaseURL != "":
		return r.EffectiveBaseURL
	case r.Config.URL != "":
		return r.Config.URL
	default:
		return r.Config.Hostname
	}
}

func (r *Result) reportStatus() checkreport.Status {
	if r.hasTraversalLimitProblem() {
		return checkreport.StatusUnknown
	}
	switch r.maxSeverity() {
	case SeverityCritical:
		return checkreport.StatusCritical
	case SeverityWarning:
		return checkreport.StatusWarning
	default:
		return checkreport.StatusOK
	}
}

func (r *Result) summaryMessage() string {
	if len(r.Problems) > 0 {
		return r.primaryProblem().Message
	}
	if r.Config.Verbosity > 0 {
		return fmt.Sprintf("discovery=%s entrypoints=%d sitemap_files=%d urls=%d depth=%d bytes_net=%d bytes_raw=%d",
			r.DiscoveredVia,
			len(r.Entrypoints),
			len(r.Documents),
			r.TotalURLs,
			r.MaxObservedDepth,
			r.Perf.TotalNetBytes,
			r.Perf.TotalRawBytes,
		)
	}
	return fmt.Sprintf("%d sitemap files, %d URLs, depth %d, net %d B, raw %d B",
		len(r.Documents),
		r.TotalURLs,
		r.MaxObservedDepth,
		r.Perf.TotalNetBytes,
		r.Perf.TotalRawBytes,
	)
}

func (r *Result) makeTargetStage() checkreport.Stage {
	return checkreport.Stage{
		ID:     "target",
		Title:  "Target",
		Status: checkreport.StatusOK,
		Target: r.reportPrimaryTarget(),
		Checks: []checkreport.Check{
			{
				ID:      "target.selection",
				State:   checkreport.CheckPass,
				Subject: r.reportPrimaryTarget(),
				Message: fmt.Sprintf("source=%s effective_base=%s hostname=%q url=%q entrypoint=%q", r.TargetSource, emptyAsDash(r.EffectiveBaseURL), r.Config.Hostname, r.Config.URL, r.Config.Entrypoint),
			},
		},
	}
}

func (r *Result) makeDiscoveryStage() checkreport.Stage {
	checks := make([]checkreport.Check, 0, len(r.DiscoveryTrace)+1)
	checks = append(checks, checkreport.Check{
		ID:      "discovery.summary",
		State:   checkreport.CheckPass,
		Subject: r.reportPrimaryTarget(),
		Message: fmt.Sprintf("method=%s entrypoints=%d", r.DiscoveredVia, len(r.Entrypoints)),
	})
	for _, line := range r.DiscoveryTrace {
		checks = append(checks, checkreport.Check{
			ID:      "discovery.trace",
			State:   checkreport.CheckNote,
			Subject: r.reportPrimaryTarget(),
			Message: line,
		})
	}
	return checkreport.Stage{
		ID:     "discovery",
		Title:  "Discovery",
		Status: stageStatusFromChecks(checks, r.FindingsForCategory("discovery")),
		Target: r.reportPrimaryTarget(),
		Checks: checks,
	}
}

func (r *Result) makeValidationStage() checkreport.Stage {
	checks := make([]checkreport.Check, 0, len(r.Rules)+len(r.Entrypoints))
	for i, rule := range r.Rules {
		checks = append(checks, ruleToCheck(i, rule))
	}
	for _, ep := range r.Entrypoints {
		checks = append(checks, checkreport.Check{
			ID:      "entrypoint",
			State:   checkreport.CheckPass,
			Subject: ep,
			Message: ep,
		})
	}
	return checkreport.Stage{
		ID:     "validation",
		Title:  "Validation",
		Status: stageStatusFromChecks(checks, makeReportFindings(r.Problems)),
		Target: r.reportPrimaryTarget(),
		Checks: checks,
	}
}

func (r *Result) makeDocumentsStage() checkreport.Stage {
	checks := make([]checkreport.Check, 0, len(r.Documents))
	for _, doc := range r.Documents {
		checks = append(checks, checkreport.Check{
			ID:      "document",
			State:   checkreport.CheckPass,
			Subject: doc.URL,
			Message: fmt.Sprintf("depth=%d kind=%s status=%d entries=%d children=%d encoding=%s gzip=%t url=%s", doc.Depth, doc.Kind, doc.StatusCode, doc.Entries, doc.Children, doc.Encoding, doc.Compressed, doc.URL),
		})
	}
	return checkreport.Stage{
		ID:     "documents",
		Title:  "Documents",
		Status: checkreport.StatusOK,
		Target: r.reportPrimaryTarget(),
		Checks: checks,
	}
}

func (r *Result) makePerformanceStage() checkreport.Stage {
	return checkreport.Stage{
		ID:     "performance",
		Title:  "Performance",
		Status: checkreport.StatusOK,
		Target: r.reportPrimaryTarget(),
		Checks: []checkreport.Check{
			{
				ID:      "performance.summary",
				State:   checkreport.CheckNote,
				Subject: r.reportPrimaryTarget(),
				Message: fmt.Sprintf("elapsed=%s net_bytes=%d raw_bytes=%d heap_alloc_peak=%d heap_sys_peak=%d", r.Perf.Elapsed, r.Perf.TotalNetBytes, r.Perf.TotalRawBytes, r.Perf.PeakHeapAlloc, r.Perf.PeakHeapSys),
			},
		},
	}
}

func makeReportFindings(problems []Problem) []checkreport.Finding {
	if len(problems) == 0 {
		return nil
	}
	out := make([]checkreport.Finding, 0, len(problems))
	for _, p := range problems {
		out = append(out, checkreport.Finding{
			Code:     p.Code,
			Severity: reportStatusFromSeverity(p.Severity),
			Target:   p.URL,
			Message:  p.Message,
		})
	}
	return out
}

func makeHTTPTraces(calls []HTTPCall) []checkreport.TraceEvent {
	if len(calls) == 0 {
		return nil
	}
	out := make([]checkreport.TraceEvent, 0, len(calls))
	for _, call := range calls {
		attrs := []checkreport.KV{
			{Key: "method", Value: call.Method},
			{Key: "status", Value: fmt.Sprintf("%d", call.StatusCode)},
			{Key: "headers", Value: call.HeadersTime.String()},
			{Key: "read", Value: call.ReadTime.String()},
			{Key: "parse", Value: call.ParseTime.String()},
			{Key: "total", Value: call.TotalTime.String()},
			{Key: "net_bytes", Value: fmt.Sprintf("%d", call.Payload.NetBytes)},
			{Key: "raw_bytes", Value: fmt.Sprintf("%d", call.Payload.RawBytes)},
			{Key: "gzip", Value: fmt.Sprintf("%t", call.Payload.Compressed)},
			{Key: "final_url", Value: emptyAsDash(call.FinalURL)},
		}
		if call.Note != "" {
			attrs = append(attrs, checkreport.KV{Key: "note", Value: call.Note})
		}
		out = append(out, checkreport.TraceEvent{
			Kind:       "http",
			StageID:    "validation",
			State:      httpTraceState(call),
			Target:     call.URL,
			Message:    httpTraceMessage(call),
			Attributes: attrs,
		})
	}
	return out
}

func httpTraceMessage(call HTTPCall) string {
	target := call.URL
	if call.FinalURL != "" && call.FinalURL != call.URL {
		target = fmt.Sprintf("%s -> %s", call.URL, call.FinalURL)
	}
	if call.Note != "" {
		return fmt.Sprintf("%s %d headers=%s read=%s parse=%s total=%s net_bytes=%d raw_bytes=%d gzip=%t %s (%s)",
			call.Method, call.StatusCode, call.HeadersTime, call.ReadTime, call.ParseTime, call.TotalTime, call.Payload.NetBytes, call.Payload.RawBytes, call.Payload.Compressed, target, call.Note)
	}
	return fmt.Sprintf("%s %d headers=%s read=%s parse=%s total=%s net_bytes=%d raw_bytes=%d gzip=%t %s",
		call.Method, call.StatusCode, call.HeadersTime, call.ReadTime, call.ParseTime, call.TotalTime, call.Payload.NetBytes, call.Payload.RawBytes, call.Payload.Compressed, target)
}

func httpTraceState(call HTTPCall) checkreport.CheckState {
	if strings.Contains(strings.ToLower(call.Note), "error") || strings.Contains(strings.ToLower(call.Note), "timeout") {
		return checkreport.CheckWarning
	}
	if call.Note != "" {
		return checkreport.CheckNote
	}
	return checkreport.CheckPass
}

func ruleToCheck(order int, rule RuleCheck) checkreport.Check {
	return checkreport.Check{
		ID:      rule.Name,
		State:   ruleState(rule.Status),
		Subject: rule.Target,
		Message: rule.Detail,
		Meta: []checkreport.KV{
			{Key: "order", Value: fmt.Sprintf("%06d", order)},
			{Key: "legacy_rule", Value: "true"},
			{Key: "status", Value: rule.Status},
			{Key: "name", Value: rule.Name},
		},
	}
}

func ruleState(status string) checkreport.CheckState {
	switch strings.ToUpper(status) {
	case "FAIL":
		return checkreport.CheckCritical
	case "WARN":
		return checkreport.CheckWarning
	case "PASS":
		return checkreport.CheckPass
	case "IGNORE":
		return checkreport.CheckIgnore
	default:
		return checkreport.CheckNote
	}
}

func reportStatusFromSeverity(sev Severity) checkreport.Status {
	switch sev {
	case SeverityCritical:
		return checkreport.StatusCritical
	case SeverityWarning:
		return checkreport.StatusWarning
	default:
		return checkreport.StatusOK
	}
}

func stageStatusFromChecks(checks []checkreport.Check, findings []checkreport.Finding) checkreport.Status {
	if len(findings) > 0 {
		for _, finding := range findings {
			if finding.Severity == checkreport.StatusCritical {
				return checkreport.StatusCritical
			}
		}
		return checkreport.StatusWarning
	}
	status := checkreport.StatusOK
	for _, check := range checks {
		switch check.State {
		case checkreport.CheckCritical:
			return checkreport.StatusCritical
		case checkreport.CheckWarning:
			status = checkreport.StatusWarning
		case checkreport.CheckUnknown:
			if status == checkreport.StatusOK {
				status = checkreport.StatusUnknown
			}
		}
	}
	return status
}

func countMetric(name string, value int) checkreport.Metric {
	v := float64(value)
	return checkreport.Metric{Name: name, Type: "count", Value: fmt.Sprintf("%d", value), Number: &v}
}

func uintMetric(name string, value uint64) checkreport.Metric {
	v := float64(value)
	return checkreport.Metric{Name: name, Type: "count", Value: fmt.Sprintf("%d", value), Number: &v}
}

func (r *Result) FindingsForCategory(categories ...string) []checkreport.Finding {
	if len(categories) == 0 {
		return nil
	}
	allowed := make(map[string]bool, len(categories))
	for _, category := range categories {
		allowed[category] = true
	}
	findings := make([]checkreport.Finding, 0)
	for _, p := range r.Problems {
		for _, descriptor := range CatalogEntries() {
			if descriptor.Slug == p.Code && allowed[descriptor.Category] {
				findings = append(findings, checkreport.Finding{
					Code:     p.Code,
					Severity: reportStatusFromSeverity(p.Severity),
					Target:   p.URL,
					Message:  p.Message,
				})
				break
			}
		}
	}
	return findings
}
