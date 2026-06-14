package robots

import (
	"fmt"
	"strings"

	"github.com/habralab/habr-nagios-plugins/internal/core/finding"
)

func (r *Result) ExitCode() int {
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
	if r.Absent {
		return fmt.Sprintf("%s - robots.txt not present (HTTP %d) | groups=0 sitemaps=0 rules=0 warnings=%d criticals=%d ignored=%d bytes=%d elapsed_ms=%d",
			label,
			r.StatusCode,
			r.countProblems(SeverityWarning),
			r.countProblems(SeverityCritical),
			len(r.IgnoredProblems),
			r.Perf.Bytes,
			r.Perf.Elapsed.Milliseconds(),
		)
	}
	if len(r.Problems) > 0 {
		primary := r.primaryProblem()
		return fmt.Sprintf("%s - %s (%s) | groups=%d sitemaps=%d rules=%d warnings=%d criticals=%d ignored=%d bytes=%d elapsed_ms=%d",
			label,
			primary.Message,
			primary.URL,
			len(r.Groups),
			len(r.Sitemaps),
			r.ruleCount(),
			r.countProblems(SeverityWarning),
			r.countProblems(SeverityCritical),
			len(r.IgnoredProblems),
			r.Perf.Bytes,
			r.Perf.Elapsed.Milliseconds(),
		)
	}
	return fmt.Sprintf("%s - %d groups, %d sitemaps, %d rules, %d B | groups=%d sitemaps=%d rules=%d warnings=%d criticals=%d ignored=%d bytes=%d elapsed_ms=%d",
		label,
		len(r.Groups),
		len(r.Sitemaps),
		r.ruleCount(),
		r.Perf.Bytes,
		len(r.Groups),
		len(r.Sitemaps),
		r.ruleCount(),
		r.countProblems(SeverityWarning),
		r.countProblems(SeverityCritical),
		len(r.IgnoredProblems),
		r.Perf.Bytes,
		r.Perf.Elapsed.Milliseconds(),
	)
}

func (r *Result) Detail() string {
	var b strings.Builder
	b.WriteString(r.Summary())
	b.WriteByte('\n')
	r.writeTargetSection(&b)
	if len(r.HTTPTrace) > 0 {
		r.writeHTTPSection(&b)
	}
	r.writeParsedSection(&b)
	if len(r.Rules) > 0 {
		r.writeRulesSection(&b)
	}
	if len(r.Problems) > 0 {
		r.writeProblemsSection(&b)
	}
	if len(r.IgnoredProblems) > 0 {
		r.writeIgnoredProblemsSection(&b)
	}
	return b.String()
}

func (r *Result) writeTargetSection(b *strings.Builder) {
	b.WriteString("Target:\n")
	fmt.Fprintf(b, "  - source=%s effective_base=%s requested=%s final=%s status=%d\n",
		r.TargetSource,
		emptyAsDash(r.EffectiveBaseURL),
		emptyAsDash(r.EffectiveRobotsURL),
		emptyAsDash(r.FinalURL),
		r.StatusCode,
	)
}

func (r *Result) writeHTTPSection(b *strings.Builder) {
	b.WriteString("HTTP:\n")
	for _, call := range r.HTTPTrace {
		target := call.URL
		if call.FinalURL != "" && call.FinalURL != call.URL {
			target = fmt.Sprintf("%s -> %s", call.URL, call.FinalURL)
		}
		if call.Note != "" {
			fmt.Fprintf(b, "  - %s %d headers=%s read=%s total=%s bytes=%d %s (%s)\n",
				call.Method, call.StatusCode, call.HeadersTime, call.ReadTime, call.TotalTime, call.Bytes, target, call.Note)
			continue
		}
		fmt.Fprintf(b, "  - %s %d headers=%s read=%s total=%s bytes=%d %s\n",
			call.Method, call.StatusCode, call.HeadersTime, call.ReadTime, call.TotalTime, call.Bytes, target)
	}
}

func (r *Result) writeParsedSection(b *strings.Builder) {
	b.WriteString("Parsed:\n")
	if r.Absent {
		fmt.Fprintf(b, "  - robots.txt not present, no directives parsed\n")
		return
	}
	fmt.Fprintf(b, "  - encoding=%s lines=%d groups=%d sitemaps=%d rules=%d\n", r.Encoding, r.RawLines, len(r.Groups), len(r.Sitemaps), r.ruleCount())
	for i, group := range r.Groups {
		fmt.Fprintf(b, "  - group=%d user_agents=%s allow=%d disallow=%d extensions=%d\n", i+1, strings.Join(group.UserAgents, ","), len(group.Allows), len(group.Disallows), len(group.Extensions))
		for _, ext := range group.Extensions {
			fmt.Fprintf(b, "    extension=%s value=%q scope=%s provenance=%s ref=%s ref_url=%s\n", ext.Name, ext.Value, ext.Spec.Scope, ext.Spec.Provenance, ext.Spec.Reference, emptyAsDash(ext.Spec.ReferenceURL))
		}
	}
	for _, sitemap := range r.Sitemaps {
		fmt.Fprintf(b, "  - sitemap=%s\n", sitemap)
	}
	for _, ext := range r.Extensions {
		fmt.Fprintf(b, "  - extension=%s value=%q scope=%s provenance=%s ref=%s ref_url=%s\n", ext.Name, ext.Value, ext.Spec.Scope, ext.Spec.Provenance, ext.Spec.Reference, emptyAsDash(ext.Spec.ReferenceURL))
	}
	for _, agent := range r.KnownAgents {
		fmt.Fprintf(b, "  - known_agent=%s vendor=%s kind=%s provenance=%s groups=%s count=%d ref=%s ref_url=%s\n", agent.Token, agent.Spec.Vendor, agent.Spec.Kind, agent.Spec.Provenance, strings.Join(agent.GroupNames, ","), agent.Count, agent.Spec.Reference, emptyAsDash(agent.Spec.ReferenceURL))
		if behavior, ok := lookupAgentBehavior(agent.Token); ok {
			for _, claim := range behavior.Claims {
				fmt.Fprintf(b, "    behavior category=%s subject=%q disposition=%s value=%s ref=%s ref_url=%s\n",
					claim.Category,
					claim.Subject,
					claim.Disposition,
					emptyAsDash(claim.Value),
					claim.Reference,
					emptyAsDash(claim.ReferenceURL),
				)
			}
		}
	}
}

func (r *Result) writeRulesSection(b *strings.Builder) {
	b.WriteString("Rules:\n")
	for _, rule := range r.Rules {
		fmt.Fprintf(b, "  - %s %s: %s [%s]\n", rule.Status, rule.Name, rule.Detail, rule.Target)
	}
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

func statusLabel(exitCode int) string {
	switch exitCode {
	case ExitCritical:
		return "CRITICAL"
	case ExitWarning:
		return "WARNING"
	default:
		return "OK"
	}
}

func severityName(sev Severity) string {
	return finding.SeverityName(sev)
}
