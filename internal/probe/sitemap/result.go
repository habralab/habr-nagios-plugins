package sitemap

import (
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
)

func (r *Result) ExitCode() int {
	return r.reportView().ExitCode()
}

func (r *Result) Summary() string {
	report := r.reportView()
	return checkreport.ResultSummaryWithPerfdata(report, r.summaryPerfdata(report.Partial))
}

func (r *Result) Detail() string {
	report := r.reportView()
	verbosity := r.Config.Verbosity
	ruleChecks := checkreport.ChecksForVerbosity(checkreport.ChecksByMeta(report.Stages, "kind", "rule"), verbosity)
	return checkreport.RenderDetail(r.Summary(), verbosity,
		checkreport.DetailSection{MinVerbosity: 1, Render: func(b *strings.Builder) { writeTargetSection(b, report, verbosity) }},
		checkreport.DetailSection{MinVerbosity: 1, Render: func(b *strings.Builder) { writeDiscoverySection(b, report, verbosity) }},
		checkreport.DetailSection{Render: func(b *strings.Builder) { checkreport.WriteRuleChecksSection(b, "rules", ruleChecks) }},
		checkreport.DetailSection{Render: func(b *strings.Builder) { writeEntrypointsSection(b, report, verbosity) }},
		checkreport.DetailSection{MinVerbosity: 1, Render: func(b *strings.Builder) { writeDocumentsSection(b, report, verbosity) }},
		checkreport.DetailSection{Render: func(b *strings.Builder) { writeHTTPSection(b, report, verbosity) }},
		checkreport.DetailSection{MinVerbosity: 1, Render: func(b *strings.Builder) { writePerformanceSection(b, report, verbosity) }},
		checkreport.DetailSection{Render: func(b *strings.Builder) { checkreport.WriteFindingsSection(b, "problems", report.Findings, false) }},
		checkreport.DetailSection{Render: func(b *strings.Builder) {
			checkreport.WriteFindingsSection(b, "ignored_problems", report.SuppressedFindings, true)
		}},
	)
}

func (r *Result) JSON() ([]byte, error) {
	return r.reportView().JSON()
}

func (r *Result) summaryPerfdata(partial bool) string {
	report := r.reportView()
	base := fmt.Sprintf("sitemap_files=%s urls=%s depth=%s warnings=%s criticals=%s ignored=%s bytes_net=%s bytes_raw=%s elapsed_ms=%d heap_alloc_peak=%s heap_sys_peak=%s",
		checkreport.MetricValue(report, "sitemap_files", "0"),
		checkreport.MetricValue(report, "urls", "0"),
		checkreport.MetricValue(report, "depth", "0"),
		checkreport.MetricValue(report, "warnings", "0"),
		checkreport.MetricValue(report, "criticals", "0"),
		checkreport.MetricValue(report, "ignored", "0"),
		checkreport.MetricValue(report, "bytes_net", "0"),
		checkreport.MetricValue(report, "bytes_raw", "0"),
		report.DurationMS,
		checkreport.MetricValue(report, "heap_alloc_peak", "0"),
		checkreport.MetricValue(report, "heap_sys_peak", "0"),
	)
	if !partial {
		return base
	}
	return fmt.Sprintf("warnings=%s criticals=%s ignored=%s partial=1 bytes_net=%s bytes_raw=%s elapsed_ms=%d heap_alloc_peak=%s heap_sys_peak=%s",
		checkreport.MetricValue(report, "warnings", "0"),
		checkreport.MetricValue(report, "criticals", "0"),
		checkreport.MetricValue(report, "ignored", "0"),
		checkreport.MetricValue(report, "bytes_net", "0"),
		checkreport.MetricValue(report, "bytes_raw", "0"),
		report.DurationMS,
		checkreport.MetricValue(report, "heap_alloc_peak", "0"),
		checkreport.MetricValue(report, "heap_sys_peak", "0"),
	)
}

func writeTargetSection(b *strings.Builder, report *checkreport.Report, verbosity int) {
	if len(checkreport.StageChecksForVerbosity(report, "target", verbosity)) == 0 {
		return
	}
	checkreport.WriteFieldsSection(b, "target", []checkreport.SectionField{
		{Key: "source", Value: checkreport.TargetValue(report, "source", "-")},
		{Key: "effective_base", Value: checkreport.TargetValue(report, "effective_base", "-")},
		{Key: "hostname", Value: fmt.Sprintf("%q", checkreport.TargetValue(report, "hostname", "-"))},
		{Key: "url", Value: fmt.Sprintf("%q", checkreport.TargetValue(report, "url", "-"))},
		{Key: "entrypoint", Value: fmt.Sprintf("%q", checkreport.TargetValue(report, "entrypoint", "-"))},
	})
}

func writeDiscoverySection(b *strings.Builder, report *checkreport.Report, verbosity int) {
	checkreport.WriteStageMessagesSection(b, report, "discovery", "discovery", verbosity, "discovery.summary", "discovery.trace")
}

func writeEntrypointsSection(b *strings.Builder, report *checkreport.Report, verbosity int) {
	checkreport.WriteCheckSubjectsSection(b, report, "entrypoints", "validation", verbosity, "entrypoint")
}

func writeDocumentsSection(b *strings.Builder, report *checkreport.Report, verbosity int) {
	checkreport.WriteStageMessagesSection(b, report, "documents", "documents", verbosity)
}

func writeHTTPSection(b *strings.Builder, report *checkreport.Report, verbosity int) {
	if verbosity < 2 {
		return
	}
	checkreport.WriteTraceMessageSection(b, "http", report.Traces, verbosity, "http")
}

func writePerformanceSection(b *strings.Builder, report *checkreport.Report, verbosity int) {
	checkreport.WriteStageMessagesSection(b, report, "performance", "performance", verbosity)
}

func (r *Result) addTrace(format string, args ...any) {
	r.DiscoveryTrace = append(r.DiscoveryTrace, fmt.Sprintf(format, args...))
	r.Report = checkreport.Report{}
}

func (r *Result) addRule(status, name, target, detail string) {
	r.RuleChecks = append(r.RuleChecks, checkreport.NewRuleCheck(len(r.RuleChecks), status, name, target, detail))
	r.Report = checkreport.Report{}
}

func (r *Result) addProblem(p Problem) {
	if p.Ignored {
		r.IgnoredProblems = append(r.IgnoredProblems, p)
		r.Report = checkreport.Report{}
		return
	}
	r.Problems = append(r.Problems, p)
	r.Report = checkreport.Report{}
}

func (r *Result) addProblems(problems ...Problem) {
	for _, p := range problems {
		r.addProblem(p)
	}
}

func (r *Result) attachDocumentTiming(rawURL string, headersTime, readTime, parseTime, totalTime time.Duration, payload PayloadStats) {
	for i := len(r.HTTPTrace) - 1; i >= 0; i-- {
		call := &r.HTTPTrace[i]
		if call.Method != http.MethodGet || call.URL != rawURL {
			continue
		}
		call.ReadTime = readTime
		call.ParseTime = parseTime
		call.TotalTime = totalTime
		call.Payload = payload
		return
	}
}

func (r *Result) attachHTTPRead(rawURL, method string, readTime time.Duration, netBytes, rawBytes int, compressed bool) {
	for i := len(r.HTTPTrace) - 1; i >= 0; i-- {
		call := &r.HTTPTrace[i]
		if call.Method != method || call.URL != rawURL {
			continue
		}
		call.ReadTime = readTime
		call.TotalTime = call.HeadersTime + readTime
		call.Payload = PayloadStats{
			Compressed: compressed,
			NetBytes:   netBytes,
			RawBytes:   rawBytes,
		}
		return
	}
}

func (r *Result) attachHTTPError(rawURL, method, note string, readTime time.Duration, netBytes, rawBytes int) {
	for i := len(r.HTTPTrace) - 1; i >= 0; i-- {
		call := &r.HTTPTrace[i]
		if call.Method != method || call.URL != rawURL {
			continue
		}
		call.Note = note
		call.ReadTime = readTime
		call.Payload = PayloadStats{
			Compressed: call.Payload.Compressed,
			NetBytes:   netBytes,
			RawBytes:   rawBytes,
		}
		call.TotalTime = call.HeadersTime + readTime
		return
	}
}

func (r *Result) updateRuntimeStats() {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	if ms.HeapAlloc > r.Perf.PeakHeapAlloc {
		r.Perf.PeakHeapAlloc = ms.HeapAlloc
	}
	if ms.HeapSys > r.Perf.PeakHeapSys {
		r.Perf.PeakHeapSys = ms.HeapSys
	}
}

func (r *Result) maxSeverity() Severity {
	max := SeverityOK
	for _, p := range r.Problems {
		if p.Severity > max {
			max = p.Severity
		}
	}
	return max
}

func (r *Result) primaryProblem() Problem {
	primary := r.Problems[0]
	for _, p := range r.Problems[1:] {
		if p.Severity > primary.Severity || (p.Severity == primary.Severity && problemPriority(p) > problemPriority(primary)) {
			primary = p
		}
	}
	return primary
}

func problemPriority(p Problem) int {
	switch p.Code {
	case "sitemap_check_timeout":
		return 100
	case "sitemap_entrypoint_not_found":
		return 90
	case "sitemap_fetch_timeout":
		return 80
	case "sitemap_fetch_failed", "sitemap_bad_status":
		return 70
	case "sitemap_max_files_exceeded", "sitemap_max_depth_exceeded", "sitemap_max_urls_exceeded":
		return 60
	default:
		return 10
	}
}

func (r *Result) countProblems(sev Severity) int {
	count := 0
	for _, p := range r.Problems {
		if p.Severity == sev {
			count++
		}
	}
	return count
}

func (r *Result) hasReliableStats() bool {
	for _, p := range r.Problems {
		switch p.Code {
		case "sitemap_check_timeout",
			"sitemap_fetch_timeout",
			"sitemap_fetch_failed",
			"sitemap_bad_status",
			"sitemap_max_files_exceeded",
			"sitemap_max_depth_exceeded",
			"sitemap_max_urls_exceeded":
			return false
		}
	}
	return true
}

func (r *Result) hasTraversalLimitProblem() bool {
	for _, p := range r.Problems {
		switch p.Code {
		case "sitemap_max_files_exceeded", "sitemap_max_depth_exceeded", "sitemap_max_urls_exceeded":
			return true
		}
	}
	return false
}

func hasProblemCode(problems []Problem, code string) bool {
	for _, p := range problems {
		if p.Code == code {
			return true
		}
	}
	return false
}

func ruleStatusFromSeverity(sev Severity) string {
	switch sev {
	case SeverityCritical:
		return "FAIL"
	case SeverityWarning:
		return "WARN"
	default:
		return "PASS"
	}
}

func lastHTTPCallHeadersTime(result *Result, rawURL, method string) time.Duration {
	if result == nil {
		return 0
	}
	for i := len(result.HTTPTrace) - 1; i >= 0; i-- {
		call := result.HTTPTrace[i]
		if call.Method == method && call.URL == rawURL {
			return call.HeadersTime
		}
	}
	return 0
}
