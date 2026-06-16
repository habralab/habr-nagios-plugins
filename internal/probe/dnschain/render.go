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
	verbosity := r.Config.Verbosity
	return checkreport.RenderDetail(r.Summary(), verbosity,
		checkreport.DetailSection{Render: func(b *strings.Builder) { checkreport.WriteReportOverviewSection(b, &r.Report) }},
		checkreport.DetailSection{Render: func(b *strings.Builder) { checkreport.WriteReportMetaSection(b, &r.Report) }},
		checkreport.DetailSection{Render: func(b *strings.Builder) { checkreport.WriteReportStagesSection(b, &r.Report, verbosity) }},
		checkreport.DetailSection{MinVerbosity: 2, Render: func(b *strings.Builder) { checkreport.WriteReportTraceSection(b, &r.Report, verbosity) }},
		checkreport.DetailSection{Render: func(b *strings.Builder) { checkreport.WriteFindingsSection(b, "findings", r.Report.Findings, false) }},
		checkreport.DetailSection{Render: func(b *strings.Builder) {
			checkreport.WriteFindingsSection(b, "suppressed_findings", r.Report.SuppressedFindings, true)
		}},
	)
}

func (r *Result) JSON() ([]byte, error) {
	return r.Report.JSON()
}
