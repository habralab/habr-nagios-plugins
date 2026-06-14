package sitemap

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"mime"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/habralab/habr-nagios-plugins/internal/probe/sitemap/ext"
	"golang.org/x/net/html/charset"
)

func parseSitemapDocument(cfg Config, sourceURL, contentType string, body []byte) (parsedSitemap, []Problem) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		switch normalizeContentType(contentType) {
		case "text/plain", "application/octet-stream":
			return parseTextSitemap(cfg, sourceURL, body)
		default:
			return parsedSitemap{Kind: "unknown"}, []Problem{makeProblem(cfg, "empty_document", sourceURL, "")}
		}
	}

	if bytes.HasPrefix(trimmed, []byte("<?xml")) || bytes.HasPrefix(trimmed, []byte("<")) {
		return parseXMLSitemap(cfg, sourceURL, contentType, body)
	}
	return parseTextSitemap(cfg, sourceURL, body)
}

func normalizeContentType(raw string) string {
	mediaType, _, err := mime.ParseMediaType(raw)
	if err != nil {
		return strings.TrimSpace(strings.ToLower(raw))
	}
	return strings.ToLower(mediaType)
}

func unexpectedContentTypeMessage(raw, kind string) (string, bool) {
	if raw == "" || kind == "unknown" {
		return "", false
	}
	contentType := normalizeContentType(raw)
	if contentType == "" {
		return "", false
	}

	switch kind {
	case "index", "urlset":
		switch contentType {
		case "application/xml", "text/xml", "application/octet-stream", "application/gzip", "application/x-gzip":
			return "", false
		}
	case "text":
		switch contentType {
		case "text/plain", "application/octet-stream":
			return "", false
		}
	}

	return fmt.Sprintf("unexpected content type %q for %s sitemap", contentType, kind), true
}

type urlset struct {
	XMLName xml.Name `xml:"urlset"`
	URLs    []struct {
		Loc string `xml:"loc"`
	} `xml:"url"`
}

type sitemapIndex struct {
	XMLName  xml.Name `xml:"sitemapindex"`
	Sitemaps []struct {
		Loc string `xml:"loc"`
	} `xml:"sitemap"`
}

type rawURLSet struct {
	XMLName xml.Name      `xml:"urlset"`
	URLs    []rawURLEntry `xml:"url"`
}

type rawURLEntry struct {
	Loc      string       `xml:"loc"`
	Children []rawElement `xml:",any"`
}

type rawElement struct {
	XMLName  xml.Name
	Attrs    []xml.Attr   `xml:",any,attr"`
	Text     string       `xml:",chardata"`
	Children []rawElement `xml:",any"`
}

func parseXMLSitemap(cfg Config, sourceURL, contentType string, body []byte) (parsedSitemap, []Problem) {
	var problems []Problem
	encoding := "utf-8"

	newDecoder := func(r io.Reader) *xml.Decoder {
		d := xml.NewDecoder(r)
		d.CharsetReader = charset.NewReaderLabel
		return d
	}

	detectEncoding := func() string {
		_, name, certain := charset.DetermineEncoding(body, contentType)
		if strings.EqualFold(name, "utf-8") {
			return "utf-8"
		}
		if !certain {
			// Sitemaps are UTF-8 by default. If we are not certain, assume UTF-8.
			return "utf-8"
		}
		return name
	}
	encoding = detectEncoding()
	if !strings.EqualFold(encoding, "utf-8") {
		problems = append(problems, makeProblem(cfg, "non_utf8_encoding", sourceURL, fmt.Sprintf("non-UTF-8 sitemap encoding %q", encoding)))
	}

	var index sitemapIndex
	d := newDecoder(bytes.NewReader(body))
	if err := d.Decode(&index); err == nil && index.XMLName.Local == "sitemapindex" {
		children := make([]string, 0, len(index.Sitemaps))
		if len(index.Sitemaps) > maxSitemapEntries {
			problems = append(problems, makeProblem(cfg, "entry_limit_exceeded", sourceURL, fmt.Sprintf("sitemap index exceeds %d entries", maxSitemapEntries)))
		}
		for _, sm := range index.Sitemaps {
			loc := strings.TrimSpace(sm.Loc)
			if loc == "" {
				problems = append(problems, makeProblem(cfg, "missing_loc", sourceURL, "sitemap index entry missing loc"))
				continue
			}
			u, err := normalizeURL(loc)
			if err != nil {
				problems = append(problems, makeProblem(cfg, "invalid_loc", sourceURL, err.Error()))
				continue
			}
			children = append(children, u)
		}
		return parsedSitemap{Kind: "index", Children: uniqueURLs(children), Encoding: encoding}, problems
	}

	var set urlset
	d = newDecoder(bytes.NewReader(body))
	if err := d.Decode(&set); err == nil && set.XMLName.Local == "urlset" {
		urls := make([]string, 0, len(set.URLs))
		extensions := make([]ExtensionObservation, 0)
		if len(set.URLs) > maxSitemapEntries {
			problems = append(problems, makeProblem(cfg, "entry_limit_exceeded", sourceURL, fmt.Sprintf("urlset exceeds %d entries", maxSitemapEntries)))
		}
		if len(set.URLs) == 0 {
			problems = append(problems, makeProblem(cfg, "empty_urlset", sourceURL, ""))
		}
		for _, entry := range set.URLs {
			loc := strings.TrimSpace(entry.Loc)
			if loc == "" {
				problems = append(problems, makeProblem(cfg, "missing_loc", sourceURL, "url entry missing loc"))
				continue
			}
			u, err := normalizeURL(loc)
			if err != nil {
				problems = append(problems, makeProblem(cfg, "invalid_url", sourceURL, err.Error()))
				continue
			}
			urls = append(urls, u)
		}

		var rawSet rawURLSet
		d = newDecoder(bytes.NewReader(body))
		if err := d.Decode(&rawSet); err == nil && rawSet.XMLName.Local == "urlset" {
			for _, rawEntry := range rawSet.URLs {
				loc := strings.TrimSpace(rawEntry.Loc)
				if loc == "" {
					continue
				}
				entryURL, err := normalizeURL(loc)
				if err != nil {
					continue
				}
				observations, issues := ext.Validate(ext.URLEntry{
					Loc:      entryURL,
					Children: convertRawElements(rawEntry.Children),
				})
				for _, obs := range observations {
					extensions = append(extensions, ExtensionObservation{
						ID:           obs.ID,
						NamespaceURI: obs.NamespaceURI,
						Count:        obs.Count,
						IssueCount:   obs.IssueCount,
					})
				}
				for _, issue := range issues {
					problems = append(problems, makeProblem(cfg, issue.Code, sourceURL, issue.Message, severityFromExt(issue.Severity, cfg.Strict)))
				}
			}
		}

		return parsedSitemap{Kind: "urlset", URLCount: len(set.URLs), URLs: urls, Extensions: mergeExtensionObservations(extensions), Encoding: encoding}, problems
	}

	return parsedSitemap{Kind: "unknown", Encoding: encoding}, append(problems, makeProblem(cfg, "xml_parse_failed", sourceURL, "document is neither a sitemapindex nor a urlset"))
}

func convertRawElements(nodes []rawElement) []ext.Element {
	out := make([]ext.Element, 0, len(nodes))
	for _, node := range nodes {
		out = append(out, ext.Element{
			Name:     node.XMLName,
			Attrs:    node.Attrs,
			Text:     node.Text,
			Children: convertRawElements(node.Children),
		})
	}
	return out
}

func mergeExtensionObservations(items []ExtensionObservation) []ExtensionObservation {
	merged := map[string]ExtensionObservation{}
	for _, item := range items {
		current, ok := merged[item.NamespaceURI]
		if !ok {
			merged[item.NamespaceURI] = item
			continue
		}
		current.Count += item.Count
		current.IssueCount += item.IssueCount
		merged[item.NamespaceURI] = current
	}

	out := make([]ExtensionObservation, 0, len(merged))
	for _, item := range merged {
		out = append(out, item)
	}
	return out
}

func parseTextSitemap(cfg Config, sourceURL string, body []byte) (parsedSitemap, []Problem) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	count := 0
	urls := make([]string, 0)
	var problems []Problem
	if !utf8.Valid(body) {
		problems = append(problems, makeProblem(cfg, "non_utf8_encoding", sourceURL, `text sitemap is not valid UTF-8`))
	}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		count++
		if msg, ok := textSitemapURLNeedsEscaping(line); ok {
			problems = append(problems, makeProblem(cfg, "url_not_escaped", sourceURL, msg))
		}
		u, err := normalizeURL(line)
		if err != nil {
			problems = append(problems, makeProblem(cfg, "invalid_url", sourceURL, err.Error()))
			continue
		}
		urls = append(urls, u)
	}
	if err := scanner.Err(); err != nil {
		problems = append(problems, makeProblem(cfg, "text_parse_failed", sourceURL, err.Error()))
	}
	if count > maxSitemapEntries {
		problems = append(problems, makeProblem(cfg, "entry_limit_exceeded", sourceURL, fmt.Sprintf("text sitemap exceeds %d entries", maxSitemapEntries)))
	}
	if count == 0 {
		problems = append(problems, makeProblem(cfg, "empty_text_sitemap", sourceURL, ""))
	}
	return parsedSitemap{Kind: "text", URLCount: count, URLs: urls}, problems
}

func textSitemapURLNeedsEscaping(raw string) (string, bool) {
	for _, r := range raw {
		switch {
		case unicode.IsControl(r):
			return fmt.Sprintf("URL contains control character %q and should be escaped", r), true
		case unicode.IsSpace(r):
			return fmt.Sprintf("URL contains unescaped whitespace %q", r), true
		case r > unicode.MaxASCII:
			return fmt.Sprintf("URL contains non-ASCII character %q and should be percent-encoded", r), true
		}
	}
	return "", false
}

func validateChildURL(parent, child, baseSite string, trustedHosts map[string]bool, cfg Config) error {
	childURL, err := url.Parse(child)
	if err != nil {
		return fmt.Errorf("child sitemap URL parse failed: %w", err)
	}
	if childURL.Scheme == "" || childURL.Host == "" {
		return fmt.Errorf("child sitemap URL must be absolute")
	}

	if !cfg.AllowCrossHost {
		parentURL, err := url.Parse(parent)
		if err != nil {
			return nil
		}
		if !sameHost(parentURL, childURL) && !hostTrusted(childURL, trustedHosts) {
			return fmt.Errorf("child sitemap host %q differs from parent host %q", childURL.Host, parentURL.Host)
		}
	}

	if cfg.Strict && baseSite != "" {
		baseURL, err := url.Parse(baseSite)
		if err == nil && !sameHost(baseURL, childURL) && !hostTrusted(childURL, trustedHosts) {
			return fmt.Errorf("child sitemap host %q differs from site host %q", childURL.Host, baseURL.Host)
		}
	}
	return nil
}

func validateEntryURL(sourceURL, entry string, trustedHosts map[string]bool, cfg Config) error {
	entryURL, err := url.Parse(entry)
	if err != nil {
		return fmt.Errorf("entry URL parse failed: %w", err)
	}
	if entryURL.Scheme == "" || entryURL.Host == "" {
		return fmt.Errorf("entry URL must be absolute")
	}

	scopeURL, err := url.Parse(sourceURL)
	if err != nil {
		return nil
	}

	if !sameHost(scopeURL, entryURL) && !hostTrusted(entryURL, trustedHosts) {
		return fmt.Errorf("entry URL host %q violates sitemap host scope %q", entryURL.Host, scopeURL.Host)
	}
	if !strings.EqualFold(scopeURL.Scheme, entryURL.Scheme) {
		return fmt.Errorf("entry URL scheme %q violates sitemap scheme scope %q", entryURL.Scheme, scopeURL.Scheme)
	}

	scopePrefix := parentDirPrefix(scopeURL.String())
	if !strings.HasPrefix(entryURL.Path, scopePrefix) {
		return fmt.Errorf("entry URL path %q violates sitemap path scope %q", entryURL.Path, scopePrefix)
	}

	return nil
}

func hostTrusted(u *url.URL, trustedHosts map[string]bool) bool {
	if u == nil || trustedHosts == nil {
		return false
	}
	key := strings.ToLower(u.Hostname()) + ":" + normalizedPort(u)
	return trustedHosts[key]
}

func severityFromStrict(strict bool) Severity {
	if strict {
		return SeverityCritical
	}
	return SeverityWarning
}

func severityFromExt(sev ext.Severity, strict bool) Severity {
	if strict || sev == ext.SeverityCritical {
		return SeverityCritical
	}
	return SeverityWarning
}
