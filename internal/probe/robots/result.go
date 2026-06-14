package robots

import (
	"fmt"
	"strings"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/core/finding"
	"github.com/habralab/habr-nagios-plugins/internal/core/probecli"
)

func (r *Result) ExitCode() int {
	return r.reportView().ExitCode()
}

func (r *Result) Summary() string {
	report := r.reportView()
	var perfParts []string
	for _, metric := range report.Metrics {
		perfParts = append(perfParts, fmt.Sprintf("%s=%s", metric.Name, metric.DisplayValue()))
	}
	perfParts = append(perfParts, fmt.Sprintf("elapsed_ms=%d", report.DurationMS))

	return fmt.Sprintf("%s - %s (%s) | %s",
		report.NagiosLabel(),
		report.Summary,
		report.EffectiveTarget(),
		strings.Join(perfParts, " "),
	)
}

func (r *Result) Detail() string {
	report := r.reportView()
	var b strings.Builder

	b.WriteString(r.Summary())
	b.WriteByte('\n')
	writeTargetSection(&b, report)
	if len(report.Traces) > 0 {
		writeHTTPSection(&b, report)
	}
	writeParsedSection(&b, report)
	ruleChecks := legacyRuleChecks(report.Stages)
	if len(ruleChecks) > 0 {
		writeRulesSection(&b, ruleChecks)
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

func writeTargetSection(b *strings.Builder, report *checkreport.Report) {
	b.WriteString("Target:\n")
	fmt.Fprintf(b, "  - source=%s effective_base=%s requested=%s final=%s status=%s\n",
		reportTargetValue(report, "source"),
		reportTargetValue(report, "effective_base"),
		reportTargetValue(report, "requested"),
		reportTargetValue(report, "final"),
		reportMetaValue(report.Meta, "status_code"),
	)
}

func writeHTTPSection(b *strings.Builder, report *checkreport.Report) {
	b.WriteString("HTTP:\n")
	for _, trace := range report.Traces {
		if trace.Kind != "http" {
			continue
		}
		fmt.Fprintf(b, "  - %s\n", trace.Message)
	}
}

func writeParsedSection(b *strings.Builder, report *checkreport.Report) {
	stage := reportStage(report, "parse")
	if stage == nil {
		return
	}
	b.WriteString("Parsed:\n")
	for _, check := range stage.Checks {
		switch check.ID {
		case "parsed.absent":
			fmt.Fprintf(b, "  - %s\n", check.Message)
		case "parsed.summary":
			fmt.Fprintf(b, "  - %s\n", check.Message)
		case "parsed.group":
			fmt.Fprintf(b, "  - %s %s\n", strings.Replace(check.Subject, "group ", "group=", 1), check.Message)
			for _, ev := range check.Evidence {
				fmt.Fprintf(b, "    %s\n", ev.Summary)
			}
		case "parsed.sitemap":
			fmt.Fprintf(b, "  - %s\n", check.Message)
		case "parsed.extension":
			fmt.Fprintf(b, "  - %s\n", check.Message)
			for _, ev := range check.Evidence {
				fmt.Fprintf(b, "    %s\n", ev.Summary)
			}
		case "parsed.known_agent":
			fmt.Fprintf(b, "  - %s\n", check.Message)
			for _, ev := range check.Evidence {
				fmt.Fprintf(b, "    %s\n", ev.Summary)
			}
		}
	}
}

func writeRulesSection(b *strings.Builder, checks []checkreport.Check) {
	b.WriteString("Rules:\n")
	for _, check := range checks {
		fmt.Fprintf(b, "  - %s %s: %s [%s]\n",
			legacyRuleStatus(check),
			check.ID,
			check.Message,
			emptyAsDash(check.Subject),
		)
	}
}

func writeFindingsSection(b *strings.Builder, title string, findings []checkreport.Finding) {
	b.WriteString(title)
	b.WriteString(":\n")
	for _, finding := range findings {
		prefix := strings.ToUpper(string(finding.Severity))
		if title == "Ignored Problems" {
			prefix = "IGNORED " + finding.Code + " original=" + strings.ToUpper(string(finding.Severity))
			fmt.Fprintf(b, "  - %s: %s [%s]\n", prefix, finding.Message, emptyAsDash(finding.Target))
			continue
		}
		fmt.Fprintf(b, "  - %s %s: %s [%s]\n", prefix, finding.Code, finding.Message, emptyAsDash(finding.Target))
	}
}

func reportStage(report *checkreport.Report, id string) *checkreport.Stage {
	for i := range report.Stages {
		if report.Stages[i].ID == id {
			return &report.Stages[i]
		}
	}
	return nil
}

func reportTargetValue(report *checkreport.Report, role string) string {
	for _, target := range report.Targets {
		if target.Role == role {
			return target.Value
		}
	}
	return "-"
}

func reportMetaValue(meta []checkreport.KV, key string) string {
	for _, item := range meta {
		if item.Key == key {
			return item.Value
		}
	}
	return "-"
}

func legacyRuleStatus(check checkreport.Check) string {
	if value := metaValue(check.Meta, "status"); value != "" {
		return value
	}
	switch check.State {
	case checkreport.CheckCritical:
		return "FAIL"
	case checkreport.CheckWarning:
		return "WARN"
	case checkreport.CheckPass:
		return "PASS"
	default:
		return "NOTE"
	}
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

func (r *Result) countProblems(sev Severity) int {
	count := 0
	for _, p := range r.Problems {
		if p.Severity == sev {
			count++
		}
	}
	return count
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
	if len(r.Problems) == 0 {
		return Problem{}
	}
	best := r.Problems[0]
	for _, p := range r.Problems[1:] {
		if p.Severity > best.Severity {
			best = p
		}
	}
	return best
}

func (r *Result) ruleCount() int {
	count := len(r.Sitemaps) + len(r.Hosts)
	for _, group := range r.Groups {
		count += len(group.Allows) + len(group.Disallows) + len(group.Extensions)
	}
	return count
}

func (r *Result) finalTarget() string {
	if r.FinalURL != "" {
		return r.FinalURL
	}
	return r.EffectiveRobotsURL
}

func severityName(sev Severity) string {
	return finding.SeverityName(sev)
}
