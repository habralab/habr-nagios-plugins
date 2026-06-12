package sitemap

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"mime"
	"net/url"
	"strings"
)

func parseSitemapDocument(cfg Config, sourceURL string, body []byte) (parsedSitemap, []Problem) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return parsedSitemap{Kind: "unknown"}, []Problem{makeProblem(cfg, "empty_document", sourceURL, "")}
	}

	if bytes.HasPrefix(trimmed, []byte("<?xml")) || bytes.HasPrefix(trimmed, []byte("<")) {
		return parseXMLSitemap(cfg, sourceURL, body)
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

func parseXMLSitemap(cfg Config, sourceURL string, body []byte) (parsedSitemap, []Problem) {
	var index sitemapIndex
	if err := xml.Unmarshal(body, &index); err == nil && index.XMLName.Local == "sitemapindex" {
		children := make([]string, 0, len(index.Sitemaps))
		var problems []Problem
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
		return parsedSitemap{Kind: "index", Children: uniqueURLs(children)}, problems
	}

	var set urlset
	if err := xml.Unmarshal(body, &set); err == nil && set.XMLName.Local == "urlset" {
		var problems []Problem
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
			if _, err := normalizeURL(loc); err != nil {
				problems = append(problems, makeProblem(cfg, "invalid_url", sourceURL, err.Error()))
			}
		}
		return parsedSitemap{Kind: "urlset", URLCount: len(set.URLs)}, problems
	}

	return parsedSitemap{Kind: "unknown"}, []Problem{makeProblem(cfg, "xml_parse_failed", sourceURL, "document is neither a sitemapindex nor a urlset")}
}

func parseTextSitemap(cfg Config, sourceURL string, body []byte) (parsedSitemap, []Problem) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	count := 0
	var problems []Problem
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		count++
		if _, err := normalizeURL(line); err != nil {
			problems = append(problems, makeProblem(cfg, "invalid_url", sourceURL, err.Error()))
		}
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
	return parsedSitemap{Kind: "text", URLCount: count}, problems
}

func validateChildURL(parent, child, baseSite string, cfg Config) error {
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
		if !sameHost(parentURL, childURL) {
			return fmt.Errorf("child sitemap host %q differs from parent host %q", childURL.Host, parentURL.Host)
		}
	}

	if cfg.Strict && baseSite != "" {
		baseURL, err := url.Parse(baseSite)
		if err == nil && !sameHost(baseURL, childURL) {
			return fmt.Errorf("child sitemap host %q differs from site host %q", childURL.Host, baseURL.Host)
		}
	}
	return nil
}

func severityFromStrict(strict bool) Severity {
	if strict {
		return SeverityCritical
	}
	return SeverityWarning
}
