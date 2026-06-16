package robots

import (
	"fmt"
	"strings"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
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
	ruleChecks := checkreport.ChecksForVerbosity(checkreport.ChecksByMeta(report.Stages, "kind", "rule"), verbosity)
	return checkreport.RenderDetail(r.Summary(), verbosity,
		checkreport.DetailSection{Render: func(b *strings.Builder) { writeTargetSection(b, report, verbosity) }},
		checkreport.DetailSection{Render: func(b *strings.Builder) { writeHTTPSection(b, report, verbosity) }},
		checkreport.DetailSection{Render: func(b *strings.Builder) { writeParsedSection(b, report, verbosity) }},
		checkreport.DetailSection{Render: func(b *strings.Builder) { checkreport.WriteRuleChecksSection(b, "rules", ruleChecks) }},
		checkreport.DetailSection{Render: func(b *strings.Builder) { checkreport.WriteFindingsSection(b, "problems", report.Findings, false) }},
		checkreport.DetailSection{Render: func(b *strings.Builder) {
			checkreport.WriteFindingsSection(b, "ignored_problems", report.SuppressedFindings, true)
		}},
	)
}

func (r *Result) JSON() ([]byte, error) {
	return r.reportView().JSON()
}

func writeTargetSection(b *strings.Builder, report *checkreport.Report, verbosity int) {
	if len(checkreport.StageChecksForVerbosity(report, "target", verbosity)) == 0 {
		return
	}
	checkreport.WriteFieldsSection(b, "target", []checkreport.SectionField{
		{Key: "source", Value: checkreport.TargetValue(report, "source", "-")},
		{Key: "effective_base", Value: checkreport.TargetValue(report, "effective_base", "-")},
		{Key: "requested", Value: checkreport.TargetValue(report, "requested", "-")},
		{Key: "final", Value: checkreport.TargetValue(report, "final", "-")},
		{Key: "status", Value: checkreport.MetaValue(report.Meta, "status_code", "-")},
	})
}

func writeHTTPSection(b *strings.Builder, report *checkreport.Report, verbosity int) {
	checkreport.WriteTraceMessageSection(b, "http", report.Traces, verbosity, "http")
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
	b.WriteString(checkreport.SectionTitle("parsed"))
	b.WriteString(":\n")
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
