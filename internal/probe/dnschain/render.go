package dnschain

import (
	"fmt"
	"strings"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
)

func (r *Result) ExitCode() int {
	return r.Report.ExitCode()
}

func (r *Result) Summary() string {
	report := r.Report
	return fmt.Sprintf("%s - %s (%s) | %s",
		report.NagiosLabel(),
		report.Summary,
		report.EffectiveTarget(),
		checkreport.Perfdata(&report, true),
	)
}

func (r *Result) Detail() string {
	var b strings.Builder
	verbosity := r.Config.Verbosity
	b.WriteString(r.Summary())
	b.WriteByte('\n')
	b.WriteString("Target:\n")
	fmt.Fprintf(&b, "  - probe=%s target=%s status=%s partial=%t\n", r.Report.Probe, r.Report.EffectiveTarget(), r.Report.Status, r.Report.Partial)
	if r.Report.CoverageNote != "" {
		fmt.Fprintf(&b, "  - coverage=%s\n", r.Report.CoverageNote)
	}
	for _, target := range r.Report.Targets {
		fmt.Fprintf(&b, "  - role=%s value=%s\n", target.Role, target.Value)
	}
	if len(r.Report.Meta) > 0 {
		b.WriteString("Meta:\n")
		for _, item := range r.Report.Meta {
			fmt.Fprintf(&b, "  - %s=%s\n", item.Key, item.Value)
		}
	}
	if len(r.Report.Stages) > 0 {
		b.WriteString("Stages:\n")
		for _, stage := range r.Report.Stages {
			fmt.Fprintf(&b, "  - %s status=%s target=%s\n", stage.ID, stage.Status, emptyAsDash(stage.Target))
			for _, check := range checkreport.ChecksForVerbosity(stage.Checks, verbosity) {
				fmt.Fprintf(&b, "    check=%s state=%s subject=%s message=%s\n", check.ID, check.State, emptyAsDash(check.Subject), check.Message)
				for _, item := range check.Meta {
					fmt.Fprintf(&b, "      meta %s=%s\n", item.Key, item.Value)
				}
				for _, ev := range check.Evidence {
					fmt.Fprintf(&b, "      evidence kind=%s summary=%s\n", ev.Kind, ev.Summary)
					for _, attr := range ev.Attributes {
						fmt.Fprintf(&b, "        %s=%s\n", attr.Key, attr.Value)
					}
				}
			}
			for _, note := range stage.Notes {
				fmt.Fprintf(&b, "    note=%s\n", note)
			}
		}
	}
	if verbosity >= 2 {
		traces := checkreport.TracesForVerbosity(r.Report.Traces, verbosity)
		if len(traces) == 0 {
			goto findings
		}
		b.WriteString("Trace:\n")
		for _, trace := range traces {
			fmt.Fprintf(&b, "  - kind=%s stage=%s state=%s target=%s message=%s\n",
				trace.Kind,
				emptyAsDash(trace.StageID),
				emptyAsDash(string(trace.State)),
				emptyAsDash(trace.Target),
				trace.Message,
			)
			for _, attr := range trace.Attributes {
				fmt.Fprintf(&b, "    %s=%s\n", attr.Key, attr.Value)
			}
		}
	}
findings:
	if len(r.Report.Findings) > 0 {
		b.WriteString("Findings:\n")
		for _, finding := range r.Report.Findings {
			fmt.Fprintf(&b, "  - %s %s: %s [%s]\n",
				strings.ToUpper(string(finding.Severity)),
				finding.Code,
				finding.Message,
				emptyAsDash(finding.Target),
			)
		}
	}
	if len(r.Report.SuppressedFindings) > 0 {
		b.WriteString("Suppressed Findings:\n")
		for _, finding := range r.Report.SuppressedFindings {
			fmt.Fprintf(&b, "  - %s %s: %s [%s]\n",
				strings.ToUpper(string(finding.Severity)),
				finding.Code,
				finding.Message,
				emptyAsDash(finding.Target),
			)
		}
	}
	return b.String()
}

func (r *Result) JSON() ([]byte, error) {
	return r.Report.JSON()
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

func emptyAsDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
