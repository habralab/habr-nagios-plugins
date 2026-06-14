package sitemap

import (
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/core/finding"
	"github.com/habralab/habr-nagios-plugins/internal/core/probecli"
)

func (r *Result) ExitCode() int {
	return r.reportView().ExitCode()
}

func (r *Result) Summary() string {
	report := r.reportView()
	return fmt.Sprintf("%s - %s | %s",
		report.NagiosLabel(),
		report.Summary,
		r.summaryPerfdata(report.Partial),
	)
}

func (r *Result) Detail() string {
	report := r.reportView()
	verbosity := r.Config.Verbosity
	var b strings.Builder
	b.WriteString(r.Summary())
	b.WriteByte('\n')
	if verbosity > 0 {
		writeTargetSection(&b, report, verbosity)
		writeDiscoverySection(&b, report, verbosity)
	}
	ruleChecks := checkreport.ChecksForVerbosity(checkreport.LegacyRuleChecks(report.Stages), verbosity)
	if len(ruleChecks) > 0 {
		writeRulesSection(&b, ruleChecks)
	}
	writeEntrypointsSection(&b, report, verbosity)
	if verbosity > 0 {
		writeDocumentsSection(&b, report, verbosity)
	}
	if len(report.Traces) > 0 {
		writeHTTPSection(&b, report, verbosity)
	}
	if verbosity > 0 {
		writePerformanceSection(&b, report, verbosity)
	}
	if len(report.Findings) > 0 {
		writeFindingsSection(&b, "Problems", report.Findings)
	}
	if len(report.SuppressedFindings) > 0 {
		writeFindingsSection(&b, "Ignored Problems", report.SuppressedFindings)
	}
	return b.String()
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
	stage := checkreport.StageByID(report, "target")
	if stage == nil || len(checkreport.ChecksForVerbosity(stage.Checks, verbosity)) == 0 {
		return
	}
	b.WriteString("Target:\n")
	fmt.Fprintf(b, "  - source=%s effective_base=%s hostname=%q url=%q entrypoint=%q\n",
		checkreport.TargetValue(report, "source", "-"),
		checkreport.TargetValue(report, "effective_base", "-"),
		checkreport.TargetValue(report, "hostname", "-"),
		checkreport.TargetValue(report, "url", "-"),
		checkreport.TargetValue(report, "entrypoint", "-"),
	)
}

func writeDiscoverySection(b *strings.Builder, report *checkreport.Report, verbosity int) {
	stage := checkreport.StageByID(report, "discovery")
	if stage == nil {
		return
	}
	checks := checkreport.ChecksForVerbosity(stage.Checks, verbosity)
	if len(checks) == 0 {
		return
	}
	b.WriteString("Discovery:\n")
	for _, check := range checks {
		switch check.ID {
		case "discovery.summary":
			fmt.Fprintf(b, "  - %s\n", check.Message)
		case "discovery.trace":
			fmt.Fprintf(b, "  - %s\n", check.Message)
		}
	}
}

func writeRulesSection(b *strings.Builder, checks []checkreport.Check) {
	if len(checks) == 0 {
		return
	}
	b.WriteString("Rules:\n")
	for _, check := range checks {
		fmt.Fprintf(b, "  - %s %s: %s [%s]\n",
			checkreport.LegacyRuleStatus(check),
			check.ID,
			check.Message,
			emptyAsDash(check.Subject),
		)
	}
}

func writeEntrypointsSection(b *strings.Builder, report *checkreport.Report, verbosity int) {
	stage := checkreport.StageByID(report, "validation")
	if stage == nil {
		return
	}
	var entrypointChecks []checkreport.Check
	for _, check := range checkreport.ChecksForVerbosity(stage.Checks, verbosity) {
		if check.ID == "entrypoint" {
			entrypointChecks = append(entrypointChecks, check)
		}
	}
	if len(entrypointChecks) == 0 {
		return
	}
	b.WriteString("Entrypoints:\n")
	for _, check := range entrypointChecks {
		fmt.Fprintf(b, "  - %s\n", check.Subject)
	}
}

func writeDocumentsSection(b *strings.Builder, report *checkreport.Report, verbosity int) {
	stage := checkreport.StageByID(report, "documents")
	if stage == nil {
		return
	}
	checks := checkreport.ChecksForVerbosity(stage.Checks, verbosity)
	if len(checks) == 0 {
		return
	}
	b.WriteString("Documents:\n")
	for _, check := range checks {
		fmt.Fprintf(b, "  - %s\n", check.Message)
	}
}

func writeHTTPSection(b *strings.Builder, report *checkreport.Report, verbosity int) {
	if verbosity < 2 {
		return
	}
	traces := checkreport.TracesForVerbosity(report.Traces, verbosity)
	if len(traces) == 0 {
		return
	}
	b.WriteString("HTTP:\n")
	for _, trace := range traces {
		if trace.Kind != "http" {
			continue
		}
		fmt.Fprintf(b, "  - %s\n", trace.Message)
	}
}

func writePerformanceSection(b *strings.Builder, report *checkreport.Report, verbosity int) {
	stage := checkreport.StageByID(report, "performance")
	if stage == nil {
		return
	}
	checks := checkreport.ChecksForVerbosity(stage.Checks, verbosity)
	if len(checks) == 0 {
		return
	}
	b.WriteString("Performance:\n")
	for _, check := range checks {
		fmt.Fprintf(b, "  - %s\n", check.Message)
	}
}

func writeFindingsSection(b *strings.Builder, title string, findings []checkreport.Finding) {
	b.WriteString(title)
	b.WriteString(":\n")
	for _, finding := range findings {
		if title == "Ignored Problems" {
			fmt.Fprintf(b, "  - IGNORED %s original=%s: %s [%s]\n",
				finding.Code,
				strings.ToUpper(string(finding.Severity)),
				finding.Message,
				emptyAsDash(finding.Target),
			)
			continue
		}
		fmt.Fprintf(b, "  - %s %s: %s [%s]\n",
			strings.ToUpper(string(finding.Severity)),
			finding.Code,
			finding.Message,
			emptyAsDash(finding.Target),
		)
	}
}

func (r *Result) addTrace(format string, args ...any) {
	r.DiscoveryTrace = append(r.DiscoveryTrace, fmt.Sprintf(format, args...))
	r.Report = checkreport.Report{}
}

func (r *Result) addRule(status, name, target, detail string) {
	r.Rules = append(r.Rules, RuleCheck{
		Status: status,
		Name:   name,
		Target: target,
		Detail: detail,
	})
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

func makeProblem(cfg Config, slug, url, message string, severityOverride ...Severity) Problem {
	return finding.Make(cfg.IgnoreErrorSet, slug, url, message, severityOverride...)
}

func CatalogHasSlug(slug string) bool {
	return finding.CatalogHasSlug(slug)
}

func CatalogSlugs() []string {
	return finding.CatalogSlugs()
}

func CatalogEntries() []probecli.ErrorSlugDescriptor {
	return finding.CatalogEntries()
}

func ParseOutputMode(raw string) (checkreport.OutputMode, error) {
	switch strings.TrimSpace(strings.ToLower(raw)) {
	case "", string(checkreport.OutputNagios):
		return checkreport.OutputNagios, nil
	case string(checkreport.OutputJSON):
		return checkreport.OutputJSON, nil
	default:
		return "", fmt.Errorf("invalid --output %q, expected nagios or json", raw)
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
