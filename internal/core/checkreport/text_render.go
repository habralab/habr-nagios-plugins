package checkreport

import (
	"fmt"
	"strings"
)

type DetailSection struct {
	MinVerbosity int
	Render       func(*strings.Builder)
}

type SectionField struct {
	Key   string
	Value string
}

func RenderDetail(summary string, verbosity int, sections ...DetailSection) string {
	var b strings.Builder
	b.WriteString(summary)
	b.WriteByte('\n')
	for _, section := range sections {
		if verbosity < section.MinVerbosity || section.Render == nil {
			continue
		}
		section.Render(&b)
	}
	return b.String()
}

func WriteSectionHeader(b *strings.Builder, key string) {
	b.WriteString(SectionTitle(key))
	b.WriteString(":\n")
}

func WriteFieldsSection(b *strings.Builder, key string, fields []SectionField) {
	if len(fields) == 0 {
		return
	}
	WriteSectionHeader(b, key)
	for _, field := range fields {
		fmt.Fprintf(b, "  - %s=%s\n", strings.TrimSpace(field.Key), EmptyAsDash(field.Value))
	}
}

func WriteMessageListSection(b *strings.Builder, key string, messages []string) {
	if len(messages) == 0 {
		return
	}
	WriteSectionHeader(b, key)
	for _, message := range messages {
		message = strings.TrimSpace(message)
		if message == "" {
			continue
		}
		fmt.Fprintf(b, "  - %s\n", message)
	}
}

func WriteRuleChecksSection(b *strings.Builder, key string, checks []Check) {
	if len(checks) == 0 {
		return
	}
	WriteSectionHeader(b, key)
	for _, check := range checks {
		fmt.Fprintf(b, "  - %s %s: %s [%s]\n",
			CheckDisplayState(check),
			check.ID,
			check.Message,
			EmptyAsDash(check.Subject),
		)
	}
}

func WriteFindingsSection(b *strings.Builder, key string, findings []Finding, suppressed bool) {
	if len(findings) == 0 {
		return
	}
	WriteSectionHeader(b, key)
	for _, finding := range findings {
		if suppressed {
			fmt.Fprintf(b, "  - IGNORED %s original=%s: %s [%s]\n",
				finding.Code,
				strings.ToUpper(string(finding.Severity)),
				finding.Message,
				EmptyAsDash(finding.Target),
			)
			continue
		}
		fmt.Fprintf(b, "  - %s %s: %s [%s]\n",
			strings.ToUpper(string(finding.Severity)),
			finding.Code,
			finding.Message,
			EmptyAsDash(finding.Target),
		)
	}
}

func WriteTraceMessageSection(b *strings.Builder, key string, traces []TraceEvent, verbosity int, kinds ...string) {
	filtered := TracesForVerbosity(traces, verbosity)
	if len(filtered) == 0 {
		return
	}
	allowedKinds := make(map[string]bool, len(kinds))
	for _, kind := range kinds {
		allowedKinds[strings.TrimSpace(kind)] = true
	}
	messages := make([]string, 0, len(filtered))
	for _, trace := range filtered {
		if len(allowedKinds) > 0 && !allowedKinds[trace.Kind] {
			continue
		}
		if strings.TrimSpace(trace.Message) == "" {
			continue
		}
		messages = append(messages, trace.Message)
	}
	WriteMessageListSection(b, key, messages)
}

func WriteReportOverviewSection(b *strings.Builder, report *Report) {
	if report == nil {
		return
	}
	WriteSectionHeader(b, "target")
	fmt.Fprintf(b, "  - probe=%s target=%s status=%s partial=%t\n", report.Probe, report.EffectiveTarget(), report.Status, report.Partial)
	if report.CoverageNote != "" {
		fmt.Fprintf(b, "  - coverage=%s\n", report.CoverageNote)
	}
	for _, target := range report.Targets {
		fmt.Fprintf(b, "  - role=%s value=%s\n", target.Role, target.Value)
	}
}

func StageChecksForVerbosity(report *Report, stageID string, verbosity int) []Check {
	stage := StageByID(report, stageID)
	if stage == nil {
		return nil
	}
	return ChecksForVerbosity(stage.Checks, verbosity)
}

func WriteStageMessagesSection(b *strings.Builder, report *Report, key, stageID string, verbosity int, checkIDs ...string) {
	checks := StageChecksForVerbosity(report, stageID, verbosity)
	if len(checks) == 0 {
		return
	}
	allowedIDs := make(map[string]bool, len(checkIDs))
	for _, id := range checkIDs {
		allowedIDs[strings.TrimSpace(id)] = true
	}
	messages := make([]string, 0, len(checks))
	for _, check := range checks {
		if len(allowedIDs) > 0 && !allowedIDs[check.ID] {
			continue
		}
		if strings.TrimSpace(check.Message) == "" {
			continue
		}
		messages = append(messages, check.Message)
	}
	WriteMessageListSection(b, key, messages)
}

func WriteCheckSubjectsSection(b *strings.Builder, report *Report, key, stageID string, verbosity int, checkIDs ...string) {
	checks := StageChecksForVerbosity(report, stageID, verbosity)
	if len(checks) == 0 {
		return
	}
	allowedIDs := make(map[string]bool, len(checkIDs))
	for _, id := range checkIDs {
		allowedIDs[strings.TrimSpace(id)] = true
	}
	values := make([]string, 0, len(checks))
	for _, check := range checks {
		if len(allowedIDs) > 0 && !allowedIDs[check.ID] {
			continue
		}
		if strings.TrimSpace(check.Subject) == "" {
			continue
		}
		values = append(values, check.Subject)
	}
	WriteMessageListSection(b, key, values)
}

func WriteReportMetaSection(b *strings.Builder, report *Report) {
	if report == nil || len(report.Meta) == 0 {
		return
	}
	WriteSectionHeader(b, "meta")
	for _, item := range report.Meta {
		fmt.Fprintf(b, "  - %s=%s\n", item.Key, item.Value)
	}
}

func WriteReportStagesSection(b *strings.Builder, report *Report, verbosity int) {
	if report == nil || len(report.Stages) == 0 {
		return
	}
	WriteSectionHeader(b, "stages")
	for _, stage := range report.Stages {
		fmt.Fprintf(b, "  - %s status=%s target=%s\n", stage.ID, stage.Status, EmptyAsDash(stage.Target))
		for _, check := range ChecksForVerbosity(stage.Checks, verbosity) {
			fmt.Fprintf(b, "    check=%s state=%s subject=%s message=%s\n", check.ID, check.State, EmptyAsDash(check.Subject), check.Message)
			for _, item := range check.Meta {
				fmt.Fprintf(b, "      meta %s=%s\n", item.Key, item.Value)
			}
			for _, ev := range check.Evidence {
				fmt.Fprintf(b, "      evidence kind=%s summary=%s\n", ev.Kind, ev.Summary)
				for _, attr := range ev.Attributes {
					fmt.Fprintf(b, "        %s=%s\n", attr.Key, attr.Value)
				}
				for _, item := range ev.Items {
					fmt.Fprintf(b, "        item id=%s subject=%s summary=%s\n", EmptyAsDash(item.ID), EmptyAsDash(item.Subject), EmptyAsDash(item.Summary))
					for _, attr := range item.Attributes {
						fmt.Fprintf(b, "          %s=%s\n", attr.Key, attr.Value)
					}
				}
			}
		}
		for _, note := range stage.Notes {
			fmt.Fprintf(b, "    note=%s\n", note)
		}
	}
}

func WriteReportTraceSection(b *strings.Builder, report *Report, verbosity int) {
	traces := TracesForVerbosity(report.Traces, verbosity)
	if len(traces) == 0 {
		return
	}
	WriteSectionHeader(b, "trace")
	for _, trace := range traces {
		fmt.Fprintf(b, "  - kind=%s stage=%s state=%s target=%s message=%s\n",
			trace.Kind,
			EmptyAsDash(trace.StageID),
			EmptyAsDash(string(trace.State)),
			EmptyAsDash(trace.Target),
			trace.Message,
		)
		for _, attr := range trace.Attributes {
			fmt.Fprintf(b, "    %s=%s\n", attr.Key, attr.Value)
		}
	}
}
