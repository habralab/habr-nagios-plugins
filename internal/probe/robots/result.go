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
	return fmt.Sprintf("%s - %s (%s) | %s",
		report.NagiosLabel(),
		report.Summary,
		report.EffectiveTarget(),
		checkreport.Perfdata(report, true),
	)
}

func (r *Result) Detail() string {
	report := r.reportView()
	verbosity := r.Config.Verbosity
	if verbosity < 1 {
		verbosity = 1
	}
	var b strings.Builder

	b.WriteString(r.Summary())
	b.WriteByte('\n')
	if verbosity > 0 {
		writeTargetSection(&b, report, verbosity)
	}
	if len(report.Traces) > 0 {
		writeHTTPSection(&b, report, verbosity)
	}
	writeParsedSection(&b, report, verbosity)
	ruleChecks := checkreport.ChecksForVerbosity(checkreport.LegacyRuleChecks(report.Stages), verbosity)
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

func writeTargetSection(b *strings.Builder, report *checkreport.Report, verbosity int) {
	stage := checkreport.StageByID(report, "target")
	if stage == nil || len(checkreport.ChecksForVerbosity(stage.Checks, verbosity)) == 0 {
		return
	}
	b.WriteString("Target:\n")
	fmt.Fprintf(b, "  - source=%s effective_base=%s requested=%s final=%s status=%s\n",
		checkreport.TargetValue(report, "source", "-"),
		checkreport.TargetValue(report, "effective_base", "-"),
		checkreport.TargetValue(report, "requested", "-"),
		checkreport.TargetValue(report, "final", "-"),
		checkreport.MetaValue(report.Meta, "status_code", "-"),
	)
}

func writeHTTPSection(b *strings.Builder, report *checkreport.Report, verbosity int) {
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

func writeParsedSection(b *strings.Builder, report *checkreport.Report, verbosity int) {
	stage := checkreport.StageByID(report, "parse")
	if stage == nil {
		return
	}
	checks := checkreport.ChecksForVerbosity(stage.Checks, verbosity)
	if len(checks) == 0 {
		return
	}
	b.WriteString("Parsed:\n")
	for _, check := range checks {
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
			checkreport.LegacyRuleStatus(check),
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
