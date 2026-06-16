package sitemap

import (
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

var sitemapSlugAliases = map[string]string{
	"entrypoint_not_found":       "sitemap_entrypoint_not_found",
	"check_timeout":              "sitemap_check_timeout",
	"max_files_exceeded":         "sitemap_max_files_exceeded",
	"max_depth_exceeded":         "sitemap_max_depth_exceeded",
	"max_urls_exceeded":          "sitemap_max_urls_exceeded",
	"cycle_detected":             "sitemap_cycle_detected",
	"duplicate_child":            "sitemap_duplicate_child",
	"invalid_entrypoint":         "sitemap_invalid_entrypoint",
	"fallback_probe_failed":      "sitemap_fallback_probe_failed",
	"fallback_used":              "sitemap_fallback_used",
	"fetch_failed":               "sitemap_fetch_failed",
	"fetch_timeout":              "sitemap_fetch_timeout",
	"bad_status":                 "sitemap_bad_status",
	"content_type_unexpected":    "sitemap_content_type_unexpected",
	"child_scope_invalid":        "sitemap_child_scope_invalid",
	"unsupported_format":         "sitemap_unsupported_format",
	"empty_document":             "sitemap_empty_document",
	"entry_limit_exceeded":       "sitemap_entry_limit_exceeded",
	"missing_loc":                "sitemap_missing_loc",
	"invalid_loc":                "sitemap_invalid_loc",
	"invalid_url":                "sitemap_invalid_url",
	"url_not_escaped":            "sitemap_url_not_escaped",
	"url_scope_invalid":          "sitemap_url_scope_invalid",
	"extension_hreflang_invalid": "sitemap_extension_hreflang_invalid",
	"extension_image_invalid":    "sitemap_extension_image_invalid",
	"extension_news_invalid":     "sitemap_extension_news_invalid",
	"extension_video_invalid":    "sitemap_extension_video_invalid",
	"non_utf8_encoding":          "sitemap_non_utf8_encoding",
	"xml_parse_failed":           "sitemap_xml_parse_failed",
	"text_parse_failed":          "sitemap_text_parse_failed",
	"empty_urlset":               "sitemap_empty_urlset",
	"empty_text_sitemap":         "sitemap_empty_text_sitemap",
}

var FindingCatalog = map[string]FindingSpec{
	"sitemap_entrypoint_not_found":       {Slug: "sitemap_entrypoint_not_found", DefaultSeverity: SeverityCritical},
	"sitemap_check_timeout":              {Slug: "sitemap_check_timeout", DefaultSeverity: SeverityCritical},
	"sitemap_max_files_exceeded":         {Slug: "sitemap_max_files_exceeded", DefaultSeverity: SeverityWarning},
	"sitemap_max_depth_exceeded":         {Slug: "sitemap_max_depth_exceeded", DefaultSeverity: SeverityWarning},
	"sitemap_max_urls_exceeded":          {Slug: "sitemap_max_urls_exceeded", DefaultSeverity: SeverityWarning},
	"sitemap_cycle_detected":             {Slug: "sitemap_cycle_detected", DefaultSeverity: SeverityWarning},
	"sitemap_duplicate_child":            {Slug: "sitemap_duplicate_child", DefaultSeverity: SeverityWarning},
	"sitemap_invalid_entrypoint":         {Slug: "sitemap_invalid_entrypoint", DefaultSeverity: SeverityCritical},
	"robots_fetch_failed":                {Slug: "robots_fetch_failed", DefaultSeverity: SeverityCritical},
	"sitemap_fallback_probe_failed":      {Slug: "sitemap_fallback_probe_failed", DefaultSeverity: SeverityWarning},
	"sitemap_fallback_used":              {Slug: "sitemap_fallback_used", DefaultSeverity: SeverityWarning},
	"sitemap_fetch_failed":               {Slug: "sitemap_fetch_failed", DefaultSeverity: SeverityCritical},
	"sitemap_fetch_timeout":              {Slug: "sitemap_fetch_timeout", DefaultSeverity: SeverityCritical},
	"sitemap_bad_status":                 {Slug: "sitemap_bad_status", DefaultSeverity: SeverityCritical},
	"sitemap_content_type_unexpected":    {Slug: "sitemap_content_type_unexpected", DefaultSeverity: SeverityWarning},
	"sitemap_child_scope_invalid":        {Slug: "sitemap_child_scope_invalid", DefaultSeverity: SeverityWarning},
	"sitemap_unsupported_format":         {Slug: "sitemap_unsupported_format", DefaultSeverity: SeverityCritical},
	"sitemap_empty_document":             {Slug: "sitemap_empty_document", DefaultSeverity: SeverityCritical},
	"sitemap_entry_limit_exceeded":       {Slug: "sitemap_entry_limit_exceeded", DefaultSeverity: SeverityCritical},
	"sitemap_missing_loc":                {Slug: "sitemap_missing_loc", DefaultSeverity: SeverityCritical},
	"sitemap_invalid_loc":                {Slug: "sitemap_invalid_loc", DefaultSeverity: SeverityCritical},
	"sitemap_invalid_url":                {Slug: "sitemap_invalid_url", DefaultSeverity: SeverityCritical},
	"sitemap_url_not_escaped":            {Slug: "sitemap_url_not_escaped", DefaultSeverity: SeverityWarning},
	"sitemap_url_scope_invalid":          {Slug: "sitemap_url_scope_invalid", DefaultSeverity: SeverityWarning},
	"sitemap_extension_hreflang_invalid": {Slug: "sitemap_extension_hreflang_invalid", DefaultSeverity: SeverityWarning},
	"sitemap_extension_image_invalid":    {Slug: "sitemap_extension_image_invalid", DefaultSeverity: SeverityWarning},
	"sitemap_extension_news_invalid":     {Slug: "sitemap_extension_news_invalid", DefaultSeverity: SeverityWarning},
	"sitemap_extension_video_invalid":    {Slug: "sitemap_extension_video_invalid", DefaultSeverity: SeverityWarning},
	"sitemap_non_utf8_encoding":          {Slug: "sitemap_non_utf8_encoding", DefaultSeverity: SeverityWarning},
	"sitemap_xml_parse_failed":           {Slug: "sitemap_xml_parse_failed", DefaultSeverity: SeverityCritical},
	"sitemap_text_parse_failed":          {Slug: "sitemap_text_parse_failed", DefaultSeverity: SeverityCritical},
	"sitemap_empty_urlset":               {Slug: "sitemap_empty_urlset", DefaultSeverity: SeverityWarning},
	"sitemap_empty_text_sitemap":         {Slug: "sitemap_empty_text_sitemap", DefaultSeverity: SeverityWarning},
	"robots_bad_status":                  {Slug: "robots_bad_status", DefaultSeverity: SeverityCritical},
	"robots_unavailable_status":          {Slug: "robots_unavailable_status", DefaultSeverity: SeverityWarning},
	"robots_empty":                       {Slug: "robots_empty", DefaultSeverity: SeverityWarning},
	"robots_fetch_timeout":               {Slug: "robots_fetch_timeout", DefaultSeverity: SeverityCritical},
	"robots_non_utf8":                    {Slug: "robots_non_utf8", DefaultSeverity: SeverityWarning},
	"robots_invalid_line":                {Slug: "robots_invalid_line", DefaultSeverity: SeverityWarning},
	"robots_invalid_path":                {Slug: "robots_invalid_path", DefaultSeverity: SeverityWarning},
	"robots_invalid_directive_value":     {Slug: "robots_invalid_directive_value", DefaultSeverity: SeverityWarning},
	"robots_invalid_sitemap":             {Slug: "robots_invalid_sitemap", DefaultSeverity: SeverityWarning},
	"robots_duplicate_sitemap":           {Slug: "robots_duplicate_sitemap", DefaultSeverity: SeverityWarning},
	"robots_extension_directive":         {Slug: "robots_extension_directive", DefaultSeverity: SeverityWarning},
	"robots_unknown_directive":           {Slug: "robots_unknown_directive", DefaultSeverity: SeverityWarning},
	"robots_no_groups":                   {Slug: "robots_no_groups", DefaultSeverity: SeverityWarning},
	"robots_rule_missing":                {Slug: "robots_rule_missing", DefaultSeverity: SeverityCritical},
	"robots_rule_forbidden":              {Slug: "robots_rule_forbidden", DefaultSeverity: SeverityCritical},
	"robots_content_type_unexpected":     {Slug: "robots_content_type_unexpected", DefaultSeverity: SeverityWarning},
	"robots_too_large":                   {Slug: "robots_too_large", DefaultSeverity: SeverityCritical},
	"robots_size_near_limit":             {Slug: "robots_size_near_limit", DefaultSeverity: SeverityWarning},
	"robots_redirect_loop":               {Slug: "robots_redirect_loop", DefaultSeverity: SeverityWarning},
	"robots_redirect_limit_exceeded":     {Slug: "robots_redirect_limit_exceeded", DefaultSeverity: SeverityWarning},
	"robots_agent_ignores_rules":         {Slug: "robots_agent_ignores_rules", DefaultSeverity: SeverityWarning},
	"robots_agent_ignores_directive":     {Slug: "robots_agent_ignores_directive", DefaultSeverity: SeverityWarning},
	"robots_agent_directive_undocumented": {
		Slug:            "robots_agent_directive_undocumented",
		DefaultSeverity: SeverityWarning,
	},
}

var findingRegistry = rulecatalog.New(FindingCatalogToEntries(FindingCatalog), severityName)

func makeProblem(cfg Config, slug, url, message string, severityOverride ...Severity) Problem {
	originalSlug := slug
	slug = canonicalSitemapSlug(slug)
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
	if !p.Ignored && originalSlug != spec.Slug && cfg.IgnoreErrorSet[originalSlug] {
		p.Ignored = true
	}
	return p
}

func CatalogHasSlug(slug string) bool {
	return findingRegistry.HasSlug(canonicalSitemapSlug(slug))
}

func CatalogSlugs() []string {
	return findingRegistry.Slugs()
}

func CatalogEntries() []probecli.ErrorSlugDescriptor {
	return findingRegistry.Entries()
}

func CatalogCategory(slug string) (string, bool) {
	entry, ok := findingRegistry.Lookup(canonicalSitemapSlug(slug))
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
	case strings.HasPrefix(slug, "robots_"):
		return inferRobotsCategory(slug)
	case strings.HasPrefix(slug, "sitemap_extension_"):
		return "extension"
	case slug == "sitemap_entrypoint_not_found" || slug == "sitemap_invalid_entrypoint" || slug == "sitemap_fallback_probe_failed" || slug == "sitemap_fallback_used":
		return "discovery"
	case slug == "sitemap_check_timeout" || slug == "sitemap_fetch_timeout" || slug == "sitemap_fetch_failed" || slug == "sitemap_bad_status" || slug == "sitemap_content_type_unexpected":
		return "transport"
	case strings.Contains(slug, "scope") || slug == "sitemap_invalid_url" || slug == "sitemap_invalid_loc" || slug == "sitemap_missing_loc":
		return "scope"
	case strings.Contains(slug, "sitemap_max_") || strings.Contains(slug, "limit_exceeded"):
		return "limits"
	case strings.Contains(slug, "parse_failed") || slug == "sitemap_unsupported_format" || slug == "sitemap_empty_document" || slug == "sitemap_non_utf8_encoding":
		return "content"
	default:
		return "validation"
	}
}

func inferRobotsCategory(slug string) string {
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

func canonicalSitemapSlug(slug string) string {
	if mapped, ok := sitemapSlugAliases[slug]; ok {
		return mapped
	}
	return slug
}
