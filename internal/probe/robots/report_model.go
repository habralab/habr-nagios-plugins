package robots

import (
	"fmt"
	"strings"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
)

func (r *Result) reportView() *checkreport.Report {
	if r.Report.Probe != "" {
		return &r.Report
	}
	report := checkreport.Report{
		Probe:         Meta.Slug,
		Target:        r.finalTarget(),
		PrimaryTarget: r.finalTarget(),
		Status:        reportStatusFromSeverity(r.maxSeverity()),
		Summary:       r.summaryMessage(),
		StartedAt:     r.StartedAt,
		DurationMS:    r.Perf.Elapsed.Milliseconds(),
		Targets: []checkreport.Target{
			{Role: "source", Value: r.TargetSource},
			{Role: "effective_base", Value: emptyAsDash(r.EffectiveBaseURL)},
			{Role: "requested", Value: emptyAsDash(r.EffectiveRobotsURL)},
			{Role: "final", Value: emptyAsDash(r.FinalURL)},
		},
		Meta: []checkreport.KV{
			{Key: "status_code", Value: fmt.Sprintf("%d", r.StatusCode)},
			{Key: "absent", Value: fmt.Sprintf("%t", r.Absent)},
			{Key: "content_type", Value: emptyAsDash(r.ContentType)},
			{Key: "encoding", Value: emptyAsDash(r.Encoding)},
			{Key: "output_mode", Value: string(r.Config.OutputMode)},
			{Key: "behavior_profile", Value: string(r.Config.BehaviorProfile)},
			{Key: "strict", Value: fmt.Sprintf("%t", r.Config.Strict)},
		},
		Metrics: []checkreport.Metric{
			countMetric("groups", len(r.Groups)),
			countMetric("sitemaps", len(r.Sitemaps)),
			countMetric("rules", r.ruleCount()),
			countMetric("warnings", r.countProblems(SeverityWarning)),
			countMetric("criticals", r.countProblems(SeverityCritical)),
			countMetric("ignored", len(r.IgnoredProblems)),
			countMetric("bytes", r.Perf.Bytes),
		},
		Findings:           makeReportFindings(r.Problems),
		SuppressedFindings: makeReportFindings(r.IgnoredProblems),
		Traces:             makeHTTPTraces(r.HTTPTrace),
	}
	report.Stages = []checkreport.Stage{
		r.makeTargetStage(),
		r.makeFetchStage(),
		r.makeParseStage(),
		r.makePolicyStage(),
		r.makeBehaviorStage(),
	}
	r.Report = report
	return &r.Report
}

func (r *Result) summaryMessage() string {
	if r.Absent {
		return fmt.Sprintf("robots.txt not present (HTTP %d)", r.StatusCode)
	}
	if len(r.Problems) > 0 {
		return r.primaryProblem().Message
	}
	return fmt.Sprintf("%d groups, %d sitemaps, %d rules, %d B", len(r.Groups), len(r.Sitemaps), r.ruleCount(), r.Perf.Bytes)
}

func (r *Result) makeTargetStage() checkreport.Stage {
	stage := checkreport.Stage{
		ID:     "target",
		Title:  "Target",
		Status: checkreport.StatusOK,
		Target: r.finalTarget(),
		Checks: []checkreport.Check{
			{
				ID:      "target.selection",
				State:   checkreport.CheckPass,
				Subject: r.finalTarget(),
				Message: targetSelectionTrace(r.Config, r.EffectiveBaseURL, r.EffectiveRobotsURL),
				MinVerbosity: 1,
				Meta: []checkreport.KV{
					{Key: "source", Value: r.TargetSource},
				},
			},
		},
	}
	return stage
}

func (r *Result) makeFetchStage() checkreport.Stage {
	checks := make([]checkreport.Check, 0, len(r.Rules))
	for i, rule := range r.Rules {
		if !strings.HasPrefix(rule.Name, "robots.") {
			continue
		}
		if rule.Name == "robots.groups" || rule.Name == "robots.parse" {
			continue
		}
		checks = append(checks, ruleToCheck(i, rule))
	}
	status := stageStatusFromChecks(checks, r.FindingsForCategory("transport"))
	return checkreport.Stage{
		ID:     "fetch",
		Title:  "Fetch",
		Status: status,
		Target: r.finalTarget(),
		Checks: checks,
	}
}

func (r *Result) makeParseStage() checkreport.Stage {
	checks := make([]checkreport.Check, 0, len(r.Groups)+len(r.Sitemaps)+len(r.Extensions)+len(r.KnownAgents)+2)
	if r.Absent {
		checks = append(checks, checkreport.Check{
			ID:      "parsed.absent",
			State:   checkreport.CheckNote,
			Subject: r.finalTarget(),
			Message: "robots.txt not present, no directives parsed",
			MinVerbosity: 1,
		})
		return checkreport.Stage{
			ID:     "parse",
			Title:  "Parsed",
			Status: checkreport.StatusOK,
			Target: r.finalTarget(),
			Checks: checks,
		}
	}

	checks = append(checks, checkreport.Check{
		ID:      "parsed.summary",
		State:   checkreport.CheckPass,
		Subject: r.finalTarget(),
		Message: fmt.Sprintf("encoding=%s lines=%d groups=%d sitemaps=%d rules=%d", r.Encoding, r.RawLines, len(r.Groups), len(r.Sitemaps), r.ruleCount()),
		MinVerbosity: 1,
	})
	for i, group := range r.Groups {
		check := checkreport.Check{
			ID:      "parsed.group",
			State:   checkreport.CheckPass,
			Subject: fmt.Sprintf("group %d", i+1),
			Message: fmt.Sprintf("user_agents=%s allow=%d disallow=%d extensions=%d", strings.Join(group.UserAgents, ","), len(group.Allows), len(group.Disallows), len(group.Extensions)),
			MinVerbosity: 1,
		}
		for _, ext := range group.Extensions {
			check.Evidence = append(check.Evidence, directiveEvidence(ext))
		}
		checks = append(checks, check)
	}
	for _, sitemap := range r.Sitemaps {
		checks = append(checks, checkreport.Check{
			ID:      "parsed.sitemap",
			State:   checkreport.CheckPass,
			Subject: sitemap,
			Message: fmt.Sprintf("sitemap=%s", sitemap),
			MinVerbosity: 1,
		})
	}
	for _, ext := range r.Extensions {
		checks = append(checks, checkreport.Check{
			ID:       "parsed.extension",
			State:    checkreport.CheckPass,
			Subject:  ext.Name,
			Message:  fmt.Sprintf("extension=%s value=%q", ext.Name, ext.Value),
			MinVerbosity: 1,
			Evidence: []checkreport.Evidence{directiveEvidence(ext)},
		})
	}
	for _, agent := range r.KnownAgents {
		check := checkreport.Check{
			ID:      "parsed.known_agent",
			State:   checkreport.CheckPass,
			Subject: agent.Token,
			Message: fmt.Sprintf("known_agent=%s vendor=%s kind=%s provenance=%s groups=%s count=%d", agent.Token, agent.Spec.Vendor, agent.Spec.Kind, agent.Spec.Provenance, strings.Join(agent.GroupNames, ","), agent.Count),
			MinVerbosity: 1,
			Evidence: []checkreport.Evidence{
				{
					Kind:    "agent",
					Summary: fmt.Sprintf("reference=%s", agent.Spec.Reference),
					Attributes: []checkreport.KV{
						{Key: "ref", Value: agent.Spec.Reference},
						{Key: "ref_url", Value: emptyAsDash(agent.Spec.ReferenceURL)},
						{Key: "provenance", Value: string(agent.Spec.Provenance)},
					},
				},
			},
		}
		if behavior, ok := lookupAgentBehavior(agent.Token); ok {
			for _, claim := range behavior.Claims {
				check.Evidence = append(check.Evidence, checkreport.Evidence{
					Kind:    "behavior",
					Summary: fmt.Sprintf("behavior category=%s subject=%q disposition=%s value=%s ref=%s ref_url=%s", claim.Category, claim.Subject, claim.Disposition, emptyAsDash(claim.Value), claim.Reference, emptyAsDash(claim.ReferenceURL)),
					Attributes: []checkreport.KV{
						{Key: "category", Value: string(claim.Category)},
						{Key: "subject", Value: claim.Subject},
						{Key: "disposition", Value: string(claim.Disposition)},
						{Key: "value", Value: emptyAsDash(claim.Value)},
						{Key: "ref", Value: claim.Reference},
						{Key: "ref_url", Value: emptyAsDash(claim.ReferenceURL)},
					},
				})
			}
		}
		checks = append(checks, check)
	}
	for i, rule := range r.Rules {
		if rule.Name == "robots.groups" || rule.Name == "robots.parse" {
			checks = append(checks, ruleToCheck(i, rule))
		}
	}

	status := stageStatusFromChecks(checks, r.FindingsForCategory("syntax", "content", "policy", "robots"))
	return checkreport.Stage{
		ID:     "parse",
		Title:  "Parsed",
		Status: status,
		Target: r.finalTarget(),
		Checks: checks,
	}
}

func (r *Result) makePolicyStage() checkreport.Stage {
	checks := make([]checkreport.Check, 0, len(r.Rules))
	for i, rule := range r.Rules {
		if strings.HasPrefix(rule.Name, "policy.") {
			checks = append(checks, ruleToCheck(i, rule))
		}
	}
	return checkreport.Stage{
		ID:     "policy",
		Title:  "Policy",
		Status: stageStatusFromChecks(checks, r.FindingsForCategory("policy")),
		Target: r.finalTarget(),
		Checks: checks,
	}
}

func (r *Result) makeBehaviorStage() checkreport.Stage {
	checks := make([]checkreport.Check, 0, len(r.Rules))
	for i, rule := range r.Rules {
		if strings.HasPrefix(rule.Name, "behavior.") {
			checks = append(checks, ruleToCheck(i, rule))
		}
	}
	return checkreport.Stage{
		ID:     "behavior",
		Title:  "Behavior",
		Status: stageStatusFromChecks(checks, r.FindingsForCategory("behavior")),
		Target: r.finalTarget(),
		Checks: checks,
	}
}

func directiveEvidence(ext DirectiveObservation) checkreport.Evidence {
	return checkreport.Evidence{
		Kind:    "directive",
		Summary: fmt.Sprintf("extension=%s value=%q scope=%s provenance=%s ref=%s ref_url=%s", ext.Name, ext.Value, ext.Spec.Scope, ext.Spec.Provenance, ext.Spec.Reference, emptyAsDash(ext.Spec.ReferenceURL)),
		Attributes: []checkreport.KV{
			{Key: "extension", Value: ext.Name},
			{Key: "value", Value: ext.Value},
			{Key: "scope", Value: string(ext.Spec.Scope)},
			{Key: "provenance", Value: string(ext.Spec.Provenance)},
			{Key: "ref", Value: ext.Spec.Reference},
			{Key: "ref_url", Value: emptyAsDash(ext.Spec.ReferenceURL)},
		},
	}
}

func makeReportFindings(problems []Problem) []checkreport.Finding {
	if len(problems) == 0 {
		return nil
	}
	out := make([]checkreport.Finding, 0, len(problems))
	for _, p := range problems {
		out = append(out, checkreport.Finding{
			Code:     p.Code,
			Severity: reportStatusFromSeverity(p.Severity),
			Target:   p.URL,
			Message:  p.Message,
		})
	}
	return out
}

func makeHTTPTraces(calls []HTTPCall) []checkreport.TraceEvent {
	if len(calls) == 0 {
		return nil
	}
	out := make([]checkreport.TraceEvent, 0, len(calls))
	for _, call := range calls {
		attrs := []checkreport.KV{
			{Key: "method", Value: call.Method},
			{Key: "status", Value: fmt.Sprintf("%d", call.StatusCode)},
			{Key: "headers_ms", Value: call.HeadersTime.String()},
			{Key: "read_ms", Value: call.ReadTime.String()},
			{Key: "total_ms", Value: call.TotalTime.String()},
			{Key: "bytes", Value: fmt.Sprintf("%d", call.Bytes)},
			{Key: "final_url", Value: emptyAsDash(call.FinalURL)},
		}
		if call.Note != "" {
			attrs = append(attrs, checkreport.KV{Key: "note", Value: call.Note})
		}
		out = append(out, checkreport.TraceEvent{
			Kind:       "http",
			StageID:    "fetch",
			State:      httpTraceState(call),
			Target:     call.URL,
			Message:    httpTraceMessage(call),
			Attributes: attrs,
			MinVerbosity: 2,
		})
	}
	return out
}

func httpTraceMessage(call HTTPCall) string {
	target := call.URL
	if call.FinalURL != "" && call.FinalURL != call.URL {
		target = fmt.Sprintf("%s -> %s", call.URL, call.FinalURL)
	}
	if call.Note != "" {
		return fmt.Sprintf("%s %d headers=%s read=%s total=%s bytes=%d %s (%s)", call.Method, call.StatusCode, call.HeadersTime, call.ReadTime, call.TotalTime, call.Bytes, target, call.Note)
	}
	return fmt.Sprintf("%s %d headers=%s read=%s total=%s bytes=%d %s", call.Method, call.StatusCode, call.HeadersTime, call.ReadTime, call.TotalTime, call.Bytes, target)
}

func httpTraceState(call HTTPCall) checkreport.CheckState {
	if strings.Contains(strings.ToLower(call.Note), "error") {
		return checkreport.CheckWarning
	}
	if call.Note == "redirect" {
		return checkreport.CheckNote
	}
	return checkreport.CheckPass
}

func ruleToCheck(order int, rule RuleCheck) checkreport.Check {
	check := checkreport.Check{
		ID:      rule.Name,
		State:   ruleState(rule.Status),
		Subject: rule.Target,
		Message: rule.Detail,
		Meta: []checkreport.KV{
			{Key: "order", Value: fmt.Sprintf("%06d", order)},
			{Key: "legacy_rule", Value: "true"},
			{Key: "status", Value: rule.Status},
			{Key: "name", Value: rule.Name},
		},
	}
	return check
}

func ruleState(status string) checkreport.CheckState {
	switch strings.ToUpper(status) {
	case "FAIL":
		return checkreport.CheckCritical
	case "WARN":
		return checkreport.CheckWarning
	case "PASS":
		return checkreport.CheckPass
	default:
		return checkreport.CheckNote
	}
}

func reportStatusFromSeverity(sev Severity) checkreport.Status {
	switch sev {
	case SeverityCritical:
		return checkreport.StatusCritical
	case SeverityWarning:
		return checkreport.StatusWarning
	default:
		return checkreport.StatusOK
	}
}

func stageStatusFromChecks(checks []checkreport.Check, findings []checkreport.Finding) checkreport.Status {
	if len(findings) > 0 {
		for _, finding := range findings {
			if finding.Severity == checkreport.StatusCritical {
				return checkreport.StatusCritical
			}
		}
		return checkreport.StatusWarning
	}
	status := checkreport.StatusOK
	for _, check := range checks {
		switch check.State {
		case checkreport.CheckCritical:
			return checkreport.StatusCritical
		case checkreport.CheckWarning:
			status = checkreport.StatusWarning
		case checkreport.CheckUnknown:
			if status == checkreport.StatusOK {
				status = checkreport.StatusUnknown
			}
		}
	}
	return status
}

func countMetric(name string, value int) checkreport.Metric {
	v := float64(value)
	return checkreport.Metric{
		Name:   name,
		Type:   "count",
		Value:  fmt.Sprintf("%d", value),
		Number: &v,
	}
}

func (r *Result) FindingsForCategory(categories ...string) []checkreport.Finding {
	if len(categories) == 0 {
		return nil
	}
	allowed := make(map[string]bool, len(categories))
	for _, category := range categories {
		allowed[category] = true
	}
	findings := make([]checkreport.Finding, 0)
	for _, p := range r.Problems {
		if spec, ok := findingSpec(p.Code); ok && allowed[spec.Category] {
			findings = append(findings, checkreport.Finding{
				Code:     p.Code,
				Severity: reportStatusFromSeverity(p.Severity),
				Target:   p.URL,
				Message:  p.Message,
			})
			continue
		}
	}
	return findings
}

func findingSpec(slug string) (spec struct{ Category string }, ok bool) {
	entry, exists := findingCatalogEntry(slug)
	if !exists {
		return spec, false
	}
	spec.Category = entry.Category
	return spec, true
}

func findingCatalogEntry(slug string) (entry struct{ Category string }, ok bool) {
	for _, descriptor := range CatalogEntries() {
		if descriptor.Slug != slug {
			continue
		}
		entry.Category = descriptor.Category
		return entry, true
	}
	return entry, false
}
