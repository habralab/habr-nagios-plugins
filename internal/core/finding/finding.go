package finding

import (
	"sort"
	"strings"

	"github.com/habralab/habr-nagios-plugins/internal/core/probecli"
)

type Severity int

const (
	SeverityOK Severity = iota
	SeverityWarning
	SeverityCritical
)

type Problem struct {
	Severity Severity
	Code     string
	Message  string
	URL      string
	Ignored  bool
}

type ProblemSpec struct {
	Slug            string
	Category        string
	DefaultSeverity Severity
	DefaultMessage  string
}

var Catalog = map[string]ProblemSpec{
	"entrypoint_not_found":           {Slug: "entrypoint_not_found", DefaultSeverity: SeverityCritical, DefaultMessage: "no sitemap entrypoint discovered"},
	"check_timeout":                  {Slug: "check_timeout", DefaultSeverity: SeverityCritical, DefaultMessage: "check timeout"},
	"max_files_exceeded":             {Slug: "max_files_exceeded", DefaultSeverity: SeverityWarning, DefaultMessage: "reached max sitemap files limit"},
	"max_depth_exceeded":             {Slug: "max_depth_exceeded", DefaultSeverity: SeverityWarning, DefaultMessage: "sitemap depth exceeds limit"},
	"max_urls_exceeded":              {Slug: "max_urls_exceeded", DefaultSeverity: SeverityWarning, DefaultMessage: "parsed URL count exceeds limit"},
	"cycle_detected":                 {Slug: "cycle_detected", DefaultSeverity: SeverityWarning, DefaultMessage: "cyclic sitemap reference detected"},
	"duplicate_child":                {Slug: "duplicate_child", DefaultSeverity: SeverityWarning, DefaultMessage: "duplicate child sitemap reference"},
	"invalid_entrypoint":             {Slug: "invalid_entrypoint", DefaultSeverity: SeverityCritical, DefaultMessage: "invalid sitemap entrypoint"},
	"robots_fetch_failed":            {Slug: "robots_fetch_failed", DefaultSeverity: SeverityCritical, DefaultMessage: "robots.txt fetch failed"},
	"fallback_probe_failed":          {Slug: "fallback_probe_failed", DefaultSeverity: SeverityWarning, DefaultMessage: "fallback probe failed"},
	"fallback_used":                  {Slug: "fallback_used", DefaultSeverity: SeverityWarning, DefaultMessage: "sitemap discovered via fallback probing, robots.txt has no Sitemap directive"},
	"fetch_failed":                   {Slug: "fetch_failed", DefaultSeverity: SeverityCritical, DefaultMessage: "document fetch failed"},
	"fetch_timeout":                  {Slug: "fetch_timeout", DefaultSeverity: SeverityCritical, DefaultMessage: "document fetch timeout"},
	"bad_status":                     {Slug: "bad_status", DefaultSeverity: SeverityCritical, DefaultMessage: "unexpected HTTP status"},
	"content_type_unexpected":        {Slug: "content_type_unexpected", DefaultSeverity: SeverityWarning, DefaultMessage: "unexpected content type"},
	"child_scope_invalid":            {Slug: "child_scope_invalid", DefaultSeverity: SeverityWarning, DefaultMessage: "child sitemap scope invalid"},
	"unsupported_format":             {Slug: "unsupported_format", DefaultSeverity: SeverityCritical, DefaultMessage: "unsupported sitemap document format"},
	"empty_document":                 {Slug: "empty_document", DefaultSeverity: SeverityCritical, DefaultMessage: "empty sitemap document"},
	"entry_limit_exceeded":           {Slug: "entry_limit_exceeded", DefaultSeverity: SeverityCritical, DefaultMessage: "sitemap entry limit exceeded"},
	"missing_loc":                    {Slug: "missing_loc", DefaultSeverity: SeverityCritical, DefaultMessage: "required loc value missing"},
	"invalid_loc":                    {Slug: "invalid_loc", DefaultSeverity: SeverityCritical, DefaultMessage: "invalid loc value"},
	"invalid_url":                    {Slug: "invalid_url", DefaultSeverity: SeverityCritical, DefaultMessage: "invalid URL value"},
	"url_not_escaped":                {Slug: "url_not_escaped", DefaultSeverity: SeverityWarning, DefaultMessage: "URL contains characters that should be escaped"},
	"url_scope_invalid":              {Slug: "url_scope_invalid", DefaultSeverity: SeverityWarning, DefaultMessage: "URL violates sitemap location scope"},
	"extension_hreflang_invalid":     {Slug: "extension_hreflang_invalid", DefaultSeverity: SeverityWarning, DefaultMessage: "hreflang sitemap extension is invalid"},
	"extension_image_invalid":        {Slug: "extension_image_invalid", DefaultSeverity: SeverityWarning, DefaultMessage: "image sitemap extension is invalid"},
	"extension_news_invalid":         {Slug: "extension_news_invalid", DefaultSeverity: SeverityWarning, DefaultMessage: "news sitemap extension is invalid"},
	"extension_video_invalid":        {Slug: "extension_video_invalid", DefaultSeverity: SeverityWarning, DefaultMessage: "video sitemap extension is invalid"},
	"non_utf8_encoding":              {Slug: "non_utf8_encoding", DefaultSeverity: SeverityWarning, DefaultMessage: "sitemap uses non-UTF-8 encoding"},
	"xml_parse_failed":               {Slug: "xml_parse_failed", DefaultSeverity: SeverityCritical, DefaultMessage: "XML sitemap parse failed"},
	"text_parse_failed":              {Slug: "text_parse_failed", DefaultSeverity: SeverityCritical, DefaultMessage: "text sitemap parse failed"},
	"empty_urlset":                   {Slug: "empty_urlset", DefaultSeverity: SeverityWarning, DefaultMessage: "urlset contains no URLs"},
	"empty_text_sitemap":             {Slug: "empty_text_sitemap", DefaultSeverity: SeverityWarning, DefaultMessage: "text sitemap contains no URLs"},
	"robots_bad_status":              {Slug: "robots_bad_status", DefaultSeverity: SeverityCritical, DefaultMessage: "unexpected robots.txt HTTP status"},
	"robots_unavailable_status":      {Slug: "robots_unavailable_status", DefaultSeverity: SeverityWarning, DefaultMessage: "robots.txt is unavailable to crawlers due to 4xx status"},
	"robots_empty":                   {Slug: "robots_empty", DefaultSeverity: SeverityWarning, DefaultMessage: "robots.txt is empty"},
	"robots_fetch_timeout":           {Slug: "robots_fetch_timeout", DefaultSeverity: SeverityCritical, DefaultMessage: "robots.txt fetch timeout"},
	"robots_non_utf8":                {Slug: "robots_non_utf8", DefaultSeverity: SeverityWarning, DefaultMessage: "robots.txt is not valid UTF-8"},
	"robots_invalid_line":            {Slug: "robots_invalid_line", DefaultSeverity: SeverityWarning, DefaultMessage: "robots.txt contains an invalid directive line"},
	"robots_invalid_path":            {Slug: "robots_invalid_path", DefaultSeverity: SeverityWarning, DefaultMessage: "robots.txt contains an invalid Allow/Disallow path"},
	"robots_invalid_directive_value": {Slug: "robots_invalid_directive_value", DefaultSeverity: SeverityWarning, DefaultMessage: "robots.txt contains an invalid extension directive value"},
	"robots_invalid_sitemap":         {Slug: "robots_invalid_sitemap", DefaultSeverity: SeverityWarning, DefaultMessage: "robots.txt contains an invalid Sitemap directive"},
	"robots_duplicate_sitemap":       {Slug: "robots_duplicate_sitemap", DefaultSeverity: SeverityWarning, DefaultMessage: "robots.txt contains a duplicate Sitemap directive"},
	"robots_extension_directive":     {Slug: "robots_extension_directive", DefaultSeverity: SeverityWarning, DefaultMessage: "robots.txt uses a non-standard extension directive"},
	"robots_unknown_directive":       {Slug: "robots_unknown_directive", DefaultSeverity: SeverityWarning, DefaultMessage: "robots.txt contains an unknown directive"},
	"robots_no_groups":               {Slug: "robots_no_groups", DefaultSeverity: SeverityWarning, DefaultMessage: "robots.txt contains no User-agent groups"},
	"robots_rule_missing":            {Slug: "robots_rule_missing", DefaultSeverity: SeverityCritical, DefaultMessage: "required robots.txt rule is missing"},
	"robots_rule_forbidden":          {Slug: "robots_rule_forbidden", DefaultSeverity: SeverityCritical, DefaultMessage: "forbidden robots.txt rule is present"},
	"robots_content_type_unexpected": {Slug: "robots_content_type_unexpected", DefaultSeverity: SeverityWarning, DefaultMessage: "unexpected robots.txt content type"},
	"robots_too_large":               {Slug: "robots_too_large", DefaultSeverity: SeverityCritical, DefaultMessage: "robots.txt exceeds the RFC parsing size limit"},
	"robots_size_near_limit":         {Slug: "robots_size_near_limit", DefaultSeverity: SeverityWarning, DefaultMessage: "robots.txt size is close to the RFC parsing limit"},
	"robots_redirect_loop":           {Slug: "robots_redirect_loop", DefaultSeverity: SeverityWarning, DefaultMessage: "robots.txt redirect loop detected"},
	"robots_redirect_limit_exceeded": {Slug: "robots_redirect_limit_exceeded", DefaultSeverity: SeverityWarning, DefaultMessage: "robots.txt redirect limit exceeded"},
	"robots_agent_ignores_rules":     {Slug: "robots_agent_ignores_rules", DefaultSeverity: SeverityWarning, DefaultMessage: "documented crawler behavior ignores the configured robots.txt rules"},
	"robots_agent_ignores_directive": {Slug: "robots_agent_ignores_directive", DefaultSeverity: SeverityWarning, DefaultMessage: "documented crawler behavior ignores a configured robots.txt directive"},
	"robots_agent_directive_undocumented": {
		Slug:            "robots_agent_directive_undocumented",
		DefaultSeverity: SeverityWarning,
		DefaultMessage:  "documented crawler support for a configured extension directive is unknown",
	},
}

func Make(ignoreSet map[string]bool, slug, url, message string, severityOverride ...Severity) Problem {
	spec, ok := Catalog[slug]
	if !ok {
		spec = ProblemSpec{
			Slug:            slug,
			DefaultSeverity: SeverityCritical,
			DefaultMessage:  slug,
		}
	}

	severity := spec.DefaultSeverity
	if len(severityOverride) > 0 {
		severity = severityOverride[0]
	}
	if message == "" {
		message = spec.DefaultMessage
	}

	p := Problem{
		Severity: severity,
		Code:     spec.Slug,
		Message:  message,
		URL:      url,
	}
	if ignoreSet[spec.Slug] {
		p.Ignored = true
	}
	return p
}

func CatalogHasSlug(slug string) bool {
	_, ok := Catalog[slug]
	return ok
}

func CatalogSlugs() []string {
	out := make([]string, 0, len(Catalog))
	for slug := range Catalog {
		out = append(out, slug)
	}
	sort.Strings(out)
	return out
}

func CatalogEntries() []probecli.ErrorSlugDescriptor {
	slugs := CatalogSlugs()
	out := make([]probecli.ErrorSlugDescriptor, 0, len(slugs))
	for _, slug := range slugs {
		spec := Catalog[slug]
		category := spec.Category
		if category == "" {
			category = inferCategory(slug)
		}
		out = append(out, probecli.ErrorSlugDescriptor{
			Slug:     spec.Slug,
			Category: category,
			Severity: SeverityName(spec.DefaultSeverity),
			Message:  spec.DefaultMessage,
		})
	}
	return out
}

func SeverityName(sev Severity) string {
	switch sev {
	case SeverityCritical:
		return "CRITICAL"
	case SeverityWarning:
		return "WARNING"
	default:
		return "OK"
	}
}

func inferCategory(slug string) string {
	switch {
	case strings.HasPrefix(slug, "robots_"):
		return inferRobotsCategory(slug)
	case strings.HasPrefix(slug, "extension_"):
		return "extension"
	case slug == "entrypoint_not_found" || slug == "invalid_entrypoint" || slug == "fallback_probe_failed" || slug == "fallback_used":
		return "discovery"
	case slug == "check_timeout" || slug == "fetch_timeout" || slug == "fetch_failed" || slug == "bad_status" || slug == "content_type_unexpected":
		return "transport"
	case strings.Contains(slug, "scope") || slug == "invalid_url" || slug == "invalid_loc" || slug == "missing_loc":
		return "scope"
	case strings.Contains(slug, "max_") || strings.Contains(slug, "limit_exceeded"):
		return "limits"
	case strings.Contains(slug, "parse_failed") || slug == "unsupported_format" || slug == "empty_document" || slug == "non_utf8_encoding":
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
