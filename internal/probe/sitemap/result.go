package sitemap

import (
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/finding"
)

func (r *Result) ExitCode() int {
	if r.hasTraversalLimitProblem() {
		return ExitUnknown
	}
	switch r.maxSeverity() {
	case SeverityCritical:
		return ExitCritical
	case SeverityWarning:
		return ExitWarning
	default:
		return ExitOK
	}
}

func (r *Result) Summary() string {
	label := statusLabel(r.ExitCode())

	if len(r.Problems) > 0 {
		primary := r.primaryProblem()
		if r.hasReliableStats() {
			return fmt.Sprintf("%s - %s (%s) | sitemap_files=%d urls=%d depth=%d warnings=%d criticals=%d ignored=%d bytes_net=%d bytes_raw=%d elapsed_ms=%d heap_alloc_peak=%d heap_sys_peak=%d",
				label,
				primary.Message,
				primary.URL,
				len(r.Documents),
				r.TotalURLs,
				r.MaxObservedDepth,
				r.countProblems(SeverityWarning),
				r.countProblems(SeverityCritical),
				len(r.IgnoredProblems),
				r.Perf.TotalNetBytes,
				r.Perf.TotalRawBytes,
				r.Perf.Elapsed.Milliseconds(),
				r.Perf.PeakHeapAlloc,
				r.Perf.PeakHeapSys,
			)
		}
		return fmt.Sprintf("%s - %s (%s) | warnings=%d criticals=%d ignored=%d partial=1 bytes_net=%d bytes_raw=%d elapsed_ms=%d heap_alloc_peak=%d heap_sys_peak=%d",
			label,
			primary.Message,
			primary.URL,
			r.countProblems(SeverityWarning),
			r.countProblems(SeverityCritical),
			len(r.IgnoredProblems),
			r.Perf.TotalNetBytes,
			r.Perf.TotalRawBytes,
			r.Perf.Elapsed.Milliseconds(),
			r.Perf.PeakHeapAlloc,
			r.Perf.PeakHeapSys,
		)
	}

	if r.Config.Verbosity > 0 {
		return fmt.Sprintf("%s - discovery=%s entrypoints=%d sitemap_files=%d urls=%d depth=%d bytes_net=%d bytes_raw=%d | %s",
			label,
			r.DiscoveredVia,
			len(r.Entrypoints),
			len(r.Documents),
			r.TotalURLs,
			r.MaxObservedDepth,
			r.Perf.TotalNetBytes,
			r.Perf.TotalRawBytes,
			r.summaryPerfdata(false),
		)
	}

	return fmt.Sprintf("%s - %d sitemap files, %d URLs, depth %d, net %d B, raw %d B | %s",
		label,
		len(r.Documents),
		r.TotalURLs,
		r.MaxObservedDepth,
		r.Perf.TotalNetBytes,
		r.Perf.TotalRawBytes,
		r.summaryPerfdata(false),
	)
}

func (r *Result) Detail() string {
	var b strings.Builder
	b.WriteString(r.Summary())
	b.WriteByte('\n')
	if r.Config.Verbosity > 0 {
		r.writeTargetSection(&b)
		r.writeDiscoverySection(&b)
	}
	if len(r.Rules) > 0 {
		r.writeRulesSection(&b)
	}
	if len(r.Entrypoints) > 0 {
		r.writeEntrypointsSection(&b)
	}
	if len(r.Documents) > 0 && r.Config.Verbosity > 0 {
		r.writeDocumentsSection(&b)
	}
	if len(r.HTTPTrace) > 0 && r.Config.Verbosity > 1 {
		r.writeHTTPSection(&b)
	}
	if r.Config.Verbosity > 0 {
		r.writePerformanceSection(&b)
	}
	if len(r.Problems) > 0 {
		r.writeProblemsSection(&b)
	}
	if len(r.IgnoredProblems) > 0 {
		r.writeIgnoredProblemsSection(&b)
	}
	return b.String()
}

func (r *Result) summaryPerfdata(partial bool) string {
	base := fmt.Sprintf("sitemap_files=%d urls=%d depth=%d warnings=%d criticals=%d ignored=%d bytes_net=%d bytes_raw=%d elapsed_ms=%d heap_alloc_peak=%d heap_sys_peak=%d",
		len(r.Documents),
		r.TotalURLs,
		r.MaxObservedDepth,
		r.countProblems(SeverityWarning),
		r.countProblems(SeverityCritical),
		len(r.IgnoredProblems),
		r.Perf.TotalNetBytes,
		r.Perf.TotalRawBytes,
		r.Perf.Elapsed.Milliseconds(),
		r.Perf.PeakHeapAlloc,
		r.Perf.PeakHeapSys,
	)
	if !partial {
		return base
	}
	return fmt.Sprintf("warnings=%d criticals=%d ignored=%d partial=1 bytes_net=%d bytes_raw=%d elapsed_ms=%d heap_alloc_peak=%d heap_sys_peak=%d",
		r.countProblems(SeverityWarning),
		r.countProblems(SeverityCritical),
		len(r.IgnoredProblems),
		r.Perf.TotalNetBytes,
		r.Perf.TotalRawBytes,
		r.Perf.Elapsed.Milliseconds(),
		r.Perf.PeakHeapAlloc,
		r.Perf.PeakHeapSys,
	)
}

func (r *Result) writeTargetSection(b *strings.Builder) {
	b.WriteString("Target:\n")
	fmt.Fprintf(b, "  - source=%s effective_base=%s hostname=%q url=%q entrypoint=%q\n", r.TargetSource, emptyAsDash(r.EffectiveBaseURL), r.Config.Hostname, r.Config.URL, r.Config.Entrypoint)
}

func (r *Result) writeDiscoverySection(b *strings.Builder) {
	b.WriteString("Discovery:\n")
	fmt.Fprintf(b, "  - method=%s entrypoints=%d\n", r.DiscoveredVia, len(r.Entrypoints))
	for _, line := range r.DiscoveryTrace {
		b.WriteString("  - ")
		b.WriteString(line)
		b.WriteByte('\n')
	}
}

func (r *Result) writeRulesSection(b *strings.Builder) {
	b.WriteString("Rules:\n")
	for _, rule := range r.Rules {
		fmt.Fprintf(b, "  - %s %s: %s [%s]\n", rule.Status, rule.Name, rule.Detail, rule.Target)
	}
}

func (r *Result) writeEntrypointsSection(b *strings.Builder) {
	b.WriteString("Entrypoints:\n")
	for _, ep := range r.Entrypoints {
		b.WriteString("  - ")
		b.WriteString(ep)
		b.WriteByte('\n')
	}
}

func (r *Result) writeDocumentsSection(b *strings.Builder) {
	b.WriteString("Documents:\n")
	for _, doc := range r.Documents {
		fmt.Fprintf(b, "  - depth=%d kind=%s status=%d entries=%d children=%d gzip=%t url=%s\n",
			doc.Depth, doc.Kind, doc.StatusCode, doc.Entries, doc.Children, doc.Compressed, doc.URL)
	}
}

func (r *Result) writeHTTPSection(b *strings.Builder) {
	b.WriteString("HTTP:\n")
	for _, call := range r.HTTPTrace {
		target := call.URL
		if call.FinalURL != "" && call.FinalURL != call.URL {
			target = fmt.Sprintf("%s -> %s", call.URL, call.FinalURL)
		}
		if call.Note != "" {
			fmt.Fprintf(b, "  - %s %d headers=%s read=%s parse=%s total=%s net_bytes=%d raw_bytes=%d gzip=%t %s (%s)\n",
				call.Method, call.StatusCode, call.HeadersTime, call.ReadTime, call.ParseTime, call.TotalTime, call.Payload.NetBytes, call.Payload.RawBytes, call.Payload.Compressed, target, call.Note)
			continue
		}
		fmt.Fprintf(b, "  - %s %d headers=%s read=%s parse=%s total=%s net_bytes=%d raw_bytes=%d gzip=%t %s\n",
			call.Method, call.StatusCode, call.HeadersTime, call.ReadTime, call.ParseTime, call.TotalTime, call.Payload.NetBytes, call.Payload.RawBytes, call.Payload.Compressed, target)
	}
}

func (r *Result) writePerformanceSection(b *strings.Builder) {
	b.WriteString("Performance:\n")
	fmt.Fprintf(b, "  - elapsed=%s net_bytes=%d raw_bytes=%d heap_alloc_peak=%d heap_sys_peak=%d\n",
		r.Perf.Elapsed, r.Perf.TotalNetBytes, r.Perf.TotalRawBytes, r.Perf.PeakHeapAlloc, r.Perf.PeakHeapSys)
}

func (r *Result) writeProblemsSection(b *strings.Builder) {
	b.WriteString("Problems:\n")
	for _, p := range r.Problems {
		fmt.Fprintf(b, "  - %s %s: %s [%s]\n", severityName(p.Severity), p.Code, p.Message, p.URL)
	}
}

func (r *Result) writeIgnoredProblemsSection(b *strings.Builder) {
	b.WriteString("Ignored Problems:\n")
	for _, p := range r.IgnoredProblems {
		fmt.Fprintf(b, "  - IGNORED %s original=%s: %s [%s]\n", p.Code, severityName(p.Severity), p.Message, p.URL)
	}
}

func (r *Result) addTrace(format string, args ...any) {
	r.DiscoveryTrace = append(r.DiscoveryTrace, fmt.Sprintf(format, args...))
}

func (r *Result) addRule(status, name, target, detail string) {
	r.Rules = append(r.Rules, RuleCheck{
		Status: status,
		Name:   name,
		Target: target,
		Detail: detail,
	})
}

func (r *Result) addProblem(p Problem) {
	if p.Ignored {
		r.IgnoredProblems = append(r.IgnoredProblems, p)
		if r.Config.Verbosity > 0 {
			r.addRule("IGNORE", "problem."+p.Code, p.URL, p.Message)
		}
		return
	}
	r.Problems = append(r.Problems, p)
}

func (r *Result) addProblems(problems ...Problem) {
	for _, p := range problems {
		r.addProblem(p)
	}
}

func makeProblem(cfg Config, slug, url, message string, severityOverride ...Severity) Problem {
	return finding.Make(cfg.IgnoreErrorSet, slug, url, message, severityOverride...)
}

func CatalogHasSlug(slug string) bool {
	return finding.CatalogHasSlug(slug)
}

func CatalogSlugs() []string {
	return finding.CatalogSlugs()
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

func statusLabel(exitCode int) string {
	switch exitCode {
	case ExitWarning:
		return "WARNING"
	case ExitCritical:
		return "CRITICAL"
	case ExitUnknown:
		return "UNKNOWN"
	default:
		return "OK"
	}
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
	case "check_timeout":
		return 100
	case "entrypoint_not_found":
		return 90
	case "fetch_timeout":
		return 80
	case "fetch_failed", "bad_status":
		return 70
	case "max_files_exceeded", "max_depth_exceeded", "max_urls_exceeded":
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
		case "check_timeout",
			"fetch_timeout",
			"fetch_failed",
			"bad_status",
			"max_files_exceeded",
			"max_depth_exceeded",
			"max_urls_exceeded":
			return false
		}
	}
	return true
}

func (r *Result) hasTraversalLimitProblem() bool {
	for _, p := range r.Problems {
		switch p.Code {
		case "max_files_exceeded", "max_depth_exceeded", "max_urls_exceeded":
			return true
		}
	}
	return false
}

func severityName(sev Severity) string { return finding.SeverityName(sev) }

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
