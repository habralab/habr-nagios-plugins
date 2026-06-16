package robots

import (
	"sort"
	"strings"

	"github.com/habralab/habr-nagios-plugins/internal/core/finding"
	"github.com/habralab/habr-nagios-plugins/internal/core/msgcatalog"
	"github.com/habralab/habr-nagios-plugins/internal/core/probecli"
	"github.com/habralab/habr-nagios-plugins/internal/core/rulecatalog"
)

type Severity = finding.Severity
type Problem = finding.Problem

const (
	SeverityOK       = finding.SeverityOK
	SeverityWarning  = finding.SeverityWarning
	SeverityCritical = finding.SeverityCritical
)

type FindingSpec struct {
	Slug            string
	Category        string
	DefaultSeverity Severity
}

var FindingCatalog = map[string]FindingSpec{
	"robots_bad_status":              {Slug: "robots_bad_status", DefaultSeverity: SeverityCritical},
	"robots_unavailable_status":      {Slug: "robots_unavailable_status", DefaultSeverity: SeverityWarning},
	"robots_empty":                   {Slug: "robots_empty", DefaultSeverity: SeverityWarning},
	"robots_fetch_failed":            {Slug: "robots_fetch_failed", DefaultSeverity: SeverityCritical},
	"robots_fetch_timeout":           {Slug: "robots_fetch_timeout", DefaultSeverity: SeverityCritical},
	"robots_non_utf8":                {Slug: "robots_non_utf8", DefaultSeverity: SeverityWarning},
	"robots_invalid_line":            {Slug: "robots_invalid_line", DefaultSeverity: SeverityWarning},
	"robots_invalid_path":            {Slug: "robots_invalid_path", DefaultSeverity: SeverityWarning},
	"robots_invalid_directive_value": {Slug: "robots_invalid_directive_value", DefaultSeverity: SeverityWarning},
	"robots_invalid_sitemap":         {Slug: "robots_invalid_sitemap", DefaultSeverity: SeverityWarning},
	"robots_duplicate_sitemap":       {Slug: "robots_duplicate_sitemap", DefaultSeverity: SeverityWarning},
	"robots_extension_directive":     {Slug: "robots_extension_directive", DefaultSeverity: SeverityWarning},
	"robots_unknown_directive":       {Slug: "robots_unknown_directive", DefaultSeverity: SeverityWarning},
	"robots_no_groups":               {Slug: "robots_no_groups", DefaultSeverity: SeverityWarning},
	"robots_rule_missing":            {Slug: "robots_rule_missing", DefaultSeverity: SeverityCritical},
	"robots_rule_forbidden":          {Slug: "robots_rule_forbidden", DefaultSeverity: SeverityCritical},
	"robots_content_type_unexpected": {Slug: "robots_content_type_unexpected", DefaultSeverity: SeverityWarning},
	"robots_too_large":               {Slug: "robots_too_large", DefaultSeverity: SeverityCritical},
	"robots_size_near_limit":         {Slug: "robots_size_near_limit", DefaultSeverity: SeverityWarning},
	"robots_redirect_loop":           {Slug: "robots_redirect_loop", DefaultSeverity: SeverityWarning},
	"robots_redirect_limit_exceeded": {Slug: "robots_redirect_limit_exceeded", DefaultSeverity: SeverityWarning},
	"robots_agent_ignores_rules":     {Slug: "robots_agent_ignores_rules", DefaultSeverity: SeverityWarning},
	"robots_agent_ignores_directive": {Slug: "robots_agent_ignores_directive", DefaultSeverity: SeverityWarning},
	"robots_agent_directive_undocumented": {
		Slug:            "robots_agent_directive_undocumented",
		DefaultSeverity: SeverityWarning,
	},
}

var findingRegistry = rulecatalog.New(FindingCatalogToEntries(FindingCatalog), severityName)

func makeProblem(cfg Config, slug, url, message string, severityOverride ...Severity) Problem {
	spec, ok := FindingCatalog[slug]
	if !ok {
		spec = FindingSpec{
			Slug:            slug,
			DefaultSeverity: SeverityCritical,
		}
	}

	severity := spec.DefaultSeverity
	if len(severityOverride) > 0 {
		severity = severityOverride[0]
	}
	if message == "" {
		message = msgcatalog.DefaultSummaryOrKey(spec.Slug)
	}

	p := Problem{
		Severity: severity,
		Code:     spec.Slug,
		Message:  message,
		URL:      url,
	}
	if cfg.IgnoreErrorSet[spec.Slug] {
		p.Ignored = true
	}
	return p
}

func CatalogHasSlug(slug string) bool {
	return findingRegistry.HasSlug(slug)
}

func CatalogSlugs() []string {
	return findingRegistry.Slugs()
}

func CatalogEntries() []probecli.ErrorSlugDescriptor {
	return findingRegistry.Entries()
}

func CatalogCategory(slug string) (string, bool) {
	entry, ok := findingRegistry.Lookup(slug)
	if !ok {
		return "", false
	}
	return entry.Category, true
}

func severityName(sev Severity) string {
	return finding.SeverityName(sev)
}

func inferCategory(slug string) string {
	switch {
	case strings.Contains(slug, "fetch") || strings.Contains(slug, "redirect") || strings.Contains(slug, "status") || strings.Contains(slug, "too_large") || strings.Contains(slug, "size_near_limit"):
		return "transport"
	case strings.Contains(slug, "invalid_line") || strings.Contains(slug, "invalid_path") || strings.Contains(slug, "unknown_directive") || strings.Contains(slug, "extension_directive"):
		return "syntax"
	case strings.Contains(slug, "invalid_sitemap") || strings.Contains(slug, "duplicate_sitemap") || strings.Contains(slug, "rule_missing") || strings.Contains(slug, "rule_forbidden") || strings.Contains(slug, "no_groups"):
		return "policy"
	case strings.Contains(slug, "content_type") || strings.Contains(slug, "non_utf8") || strings.Contains(slug, "empty"):
		return "content"
	case strings.Contains(slug, "agent_"):
		return "behavior"
	default:
		return "robots"
	}
}

func FindingCatalogToEntries(catalog map[string]FindingSpec) map[string]rulecatalog.Entry[Severity] {
	out := make(map[string]rulecatalog.Entry[Severity], len(catalog))
	for slug, spec := range catalog {
		category := spec.Category
		if category == "" {
			category = inferCategory(slug)
		}
		out[slug] = rulecatalog.Entry[Severity]{
			Slug:     spec.Slug,
			Category: category,
			Severity: spec.DefaultSeverity,
			Message:  msgcatalog.DefaultSummaryOrKey(spec.Slug),
		}
	}
	return out
}

func sortedCatalogSlugs() []string {
	out := make([]string, 0, len(FindingCatalog))
	for slug := range FindingCatalog {
		out = append(out, slug)
	}
	sort.Strings(out)
	return out
}
