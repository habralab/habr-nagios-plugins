package finding

import "sort"

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
	DefaultSeverity Severity
	DefaultMessage  string
}

var Catalog = map[string]ProblemSpec{
	"entrypoint_not_found":    {Slug: "entrypoint_not_found", DefaultSeverity: SeverityCritical, DefaultMessage: "no sitemap entrypoint discovered"},
	"check_timeout":           {Slug: "check_timeout", DefaultSeverity: SeverityCritical, DefaultMessage: "check timeout"},
	"max_files_exceeded":      {Slug: "max_files_exceeded", DefaultSeverity: SeverityWarning, DefaultMessage: "reached max sitemap files limit"},
	"max_depth_exceeded":      {Slug: "max_depth_exceeded", DefaultSeverity: SeverityWarning, DefaultMessage: "sitemap depth exceeds limit"},
	"max_urls_exceeded":       {Slug: "max_urls_exceeded", DefaultSeverity: SeverityWarning, DefaultMessage: "parsed URL count exceeds limit"},
	"cycle_detected":          {Slug: "cycle_detected", DefaultSeverity: SeverityWarning, DefaultMessage: "cyclic sitemap reference detected"},
	"duplicate_child":         {Slug: "duplicate_child", DefaultSeverity: SeverityWarning, DefaultMessage: "duplicate child sitemap reference"},
	"invalid_entrypoint":      {Slug: "invalid_entrypoint", DefaultSeverity: SeverityCritical, DefaultMessage: "invalid sitemap entrypoint"},
	"robots_fetch_failed":     {Slug: "robots_fetch_failed", DefaultSeverity: SeverityWarning, DefaultMessage: "robots.txt fetch failed"},
	"fallback_probe_failed":   {Slug: "fallback_probe_failed", DefaultSeverity: SeverityWarning, DefaultMessage: "fallback probe failed"},
	"fallback_used":           {Slug: "fallback_used", DefaultSeverity: SeverityWarning, DefaultMessage: "sitemap discovered via fallback probing, robots.txt has no Sitemap directive"},
	"fetch_failed":            {Slug: "fetch_failed", DefaultSeverity: SeverityCritical, DefaultMessage: "document fetch failed"},
	"fetch_timeout":           {Slug: "fetch_timeout", DefaultSeverity: SeverityCritical, DefaultMessage: "document fetch timeout"},
	"bad_status":              {Slug: "bad_status", DefaultSeverity: SeverityCritical, DefaultMessage: "unexpected HTTP status"},
	"content_type_unexpected": {Slug: "content_type_unexpected", DefaultSeverity: SeverityWarning, DefaultMessage: "unexpected content type"},
	"child_scope_invalid":     {Slug: "child_scope_invalid", DefaultSeverity: SeverityWarning, DefaultMessage: "child sitemap scope invalid"},
	"unsupported_format":      {Slug: "unsupported_format", DefaultSeverity: SeverityCritical, DefaultMessage: "unsupported sitemap document format"},
	"empty_document":          {Slug: "empty_document", DefaultSeverity: SeverityCritical, DefaultMessage: "empty sitemap document"},
	"entry_limit_exceeded":    {Slug: "entry_limit_exceeded", DefaultSeverity: SeverityCritical, DefaultMessage: "sitemap entry limit exceeded"},
	"missing_loc":             {Slug: "missing_loc", DefaultSeverity: SeverityCritical, DefaultMessage: "required loc value missing"},
	"invalid_loc":             {Slug: "invalid_loc", DefaultSeverity: SeverityCritical, DefaultMessage: "invalid loc value"},
	"invalid_url":             {Slug: "invalid_url", DefaultSeverity: SeverityCritical, DefaultMessage: "invalid URL value"},
	"url_not_escaped":         {Slug: "url_not_escaped", DefaultSeverity: SeverityWarning, DefaultMessage: "URL contains characters that should be escaped"},
	"url_scope_invalid":       {Slug: "url_scope_invalid", DefaultSeverity: SeverityWarning, DefaultMessage: "URL violates sitemap location scope"},
	"extension_hreflang_invalid": {Slug: "extension_hreflang_invalid", DefaultSeverity: SeverityWarning, DefaultMessage: "hreflang sitemap extension is invalid"},
	"extension_image_invalid":    {Slug: "extension_image_invalid", DefaultSeverity: SeverityWarning, DefaultMessage: "image sitemap extension is invalid"},
	"extension_news_invalid":     {Slug: "extension_news_invalid", DefaultSeverity: SeverityWarning, DefaultMessage: "news sitemap extension is invalid"},
	"extension_video_invalid":    {Slug: "extension_video_invalid", DefaultSeverity: SeverityWarning, DefaultMessage: "video sitemap extension is invalid"},
	"non_utf8_encoding":       {Slug: "non_utf8_encoding", DefaultSeverity: SeverityWarning, DefaultMessage: "sitemap uses non-UTF-8 encoding"},
	"xml_parse_failed":        {Slug: "xml_parse_failed", DefaultSeverity: SeverityCritical, DefaultMessage: "XML sitemap parse failed"},
	"text_parse_failed":       {Slug: "text_parse_failed", DefaultSeverity: SeverityCritical, DefaultMessage: "text sitemap parse failed"},
	"empty_urlset":            {Slug: "empty_urlset", DefaultSeverity: SeverityWarning, DefaultMessage: "urlset contains no URLs"},
	"empty_text_sitemap":      {Slug: "empty_text_sitemap", DefaultSeverity: SeverityWarning, DefaultMessage: "text sitemap contains no URLs"},
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
