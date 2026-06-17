package checkreport

import (
	"fmt"
	"strings"
)

func DefaultResultSummary(report *Report) string {
	return ResultSummaryWithPerfdata(report, Perfdata(report, true))
}

func ResultSummaryWithPerfdata(report *Report, perfdata string) string {
	if report == nil {
		return "UNKNOWN - empty report"
	}
	return fmt.Sprintf("%s - %s (%s) | %s",
		report.NagiosLabel(),
		report.Summary,
		report.EffectiveTarget(),
		perfdata,
	)
}

func DefaultResultDetail(report *Report, verbosity int) string {
	return RenderDetail(DefaultResultSummary(report), verbosity,
		DetailSection{Render: func(b *strings.Builder) { WriteReportOverviewSection(b, report) }},
		DetailSection{Render: func(b *strings.Builder) { WriteReportMetaSection(b, report) }},
		DetailSection{Render: func(b *strings.Builder) { WriteReportStagesSection(b, report, verbosity) }},
		DetailSection{MinVerbosity: 2, Render: func(b *strings.Builder) { WriteReportTraceSection(b, report, verbosity) }},
		DetailSection{Render: func(b *strings.Builder) { WriteFindingsSection(b, "findings", report.Findings, false) }},
		DetailSection{Render: func(b *strings.Builder) {
			WriteFindingsSection(b, "suppressed_findings", report.SuppressedFindings, true)
		}},
	)
}

func DefaultResultJSON(report *Report) ([]byte, error) {
	if report == nil {
		return nil, fmt.Errorf("nil report")
	}
	return report.JSON()
}
