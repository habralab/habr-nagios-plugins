package sitemap

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/finding"
	"github.com/habralab/habr-nagios-plugins/internal/core/httpx"
)

const (
	ExitOK       = 0
	ExitWarning  = 1
	ExitCritical = 2
	ExitUnknown  = 3

	maxSitemapFileBytes = 52_428_800
	maxSitemapEntries   = 50_000
)

var DefaultFallbackPaths = []string{
	"/sitemap.xml",
	"/sitemap_index.xml",
	"/sitemap.txt",
	"/sitemap.xml.gz",
}

type FallbackSeverity string

const (
	FallbackOK   FallbackSeverity = "ok"
	FallbackWarn FallbackSeverity = "warn"
)

type Config struct {
	Hostname       string
	URL            string
	Entrypoint     string
	RobotsURL      string
	Strict         bool
	FallbackProbe  bool
	Verbosity      int
	FallbackStatus string
	AllowCrossHost bool
	MaxDepth       int
	MaxFiles       int
	MaxURLs        int
	HTTP           httpx.Options
	Timeout        time.Duration
	HTTPClient     *http.Client
	FallbackPaths  []string
	IgnoreErrors   []string
	IgnoreErrorSet map[string]bool
	ShowHelp       bool
	ShowErrorSlugs bool
	ShowVersion    bool
}

func DefaultConfig() Config {
	return Config{
		FallbackProbe:  true,
		Verbosity:      0,
		FallbackStatus: string(FallbackWarn),
		MaxDepth:       0,
		MaxFiles:       0,
		MaxURLs:        0,
		HTTP: httpx.Options{
			UserAgent: httpx.DefaultUserAgent(),
		},
		Timeout:        60 * time.Second,
		FallbackPaths:  slices.Clone(DefaultFallbackPaths),
		IgnoreErrorSet: map[string]bool{},
	}
}

type Severity = finding.Severity
type Problem = finding.Problem

const (
	SeverityOK       = finding.SeverityOK
	SeverityWarning  = finding.SeverityWarning
	SeverityCritical = finding.SeverityCritical
)

type Result struct {
	Config           Config
	Entrypoints      []string
	Documents        []DocumentResult
	Problems         []Problem
	IgnoredProblems  []Problem
	Rules            []RuleCheck
	DiscoveryTrace   []string
	HTTPTrace        []HTTPCall
	DiscoveredVia    string
	TargetSource     string
	EffectiveBaseURL string
	TotalURLs        int
	TotalNetBytes    int
	TotalRawBytes    int
	Elapsed          time.Duration
	PeakHeapAlloc    uint64
	PeakHeapSys      uint64
	MaxObservedDepth int
}

type DocumentResult struct {
	URL        string
	Kind       string
	StatusCode int
	Depth      int
	Entries    int
	Children   int
	Compressed bool
}

type RuleCheck struct {
	Status string
	Name   string
	Target string
	Detail string
}

type HTTPCall struct {
	Method        string
	URL           string
	StatusCode    int
	FinalURL      string
	HeadersTime   time.Duration
	ReadTime      time.Duration
	ParseTime     time.Duration
	TotalTime     time.Duration
	Compressed    bool
	NetBytes      int
	RawBytes      int
	Note          string
}

type queueItem struct {
	URL    string
	Depth  int
	Parent string
}

type robotsDiscovery struct {
	Sitemaps []string
}

type fetchResult struct {
	StatusCode    int
	Body          []byte
	Compressed    bool
	ContentType   string
	HeadersTime   time.Duration
	ReadTime      time.Duration
	NetBytes      int
	RawBytes      int
}

type countingReader struct {
	io.Reader
	N int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.Reader.Read(p)
	c.N += n
	return n, err
}

type parsedSitemap struct {
	Kind       string
	URLCount   int
	Children   []string
	Compressed bool
}

func Run(ctx context.Context, cfg Config) (*Result, error) {
	startedAt := time.Now()
	baseSite, err := normalizeBaseSite(cfg)
	if err != nil {
		return nil, err
	}

	if cfg.MaxDepth < 0 || cfg.MaxFiles < 0 || cfg.MaxURLs < 0 {
		return nil, fmt.Errorf("max-depth, max-files, and max-urls must be non-negative")
	}

	client := cfg.HTTPClient
	if client == nil {
		client = httpx.NewClient(cfg.Timeout, cfg.HTTP)
	}
	result := &Result{Config: cfg}
	defer func() {
		result.Elapsed = time.Since(startedAt)
		result.updateRuntimeStats()
	}()
	client = withTraceRedirects(client, result)
	result.TargetSource = targetSource(cfg)
	result.EffectiveBaseURL = baseSite
	result.updateRuntimeStats()

	result.addTrace("input hostname=%q url=%q entrypoint=%q timeout=%s strict=%t fallback=%t", cfg.Hostname, cfg.URL, cfg.Entrypoint, cfg.Timeout, cfg.Strict, cfg.FallbackProbe)
	if cfg.HTTP.InsecureSkipVerify {
		result.addTrace("tls verification disabled by --insecure-skip-verify")
		result.addRule("WARN", "tls.verify", baseSiteOrHostname(baseSite, cfg.Hostname), "TLS certificate verification disabled by flag")
	}
	result.addTrace("%s", targetSelectionTrace(cfg, baseSite))

	entrypoints, via, discoveryProblems := discoverEntrypoints(ctx, client, cfg, baseSite, result)
	result.addProblems(discoveryProblems...)
	result.Entrypoints = entrypoints
	result.DiscoveredVia = via
	result.addTrace("resolved entrypoints via=%s count=%d", via, len(entrypoints))

	if len(entrypoints) == 0 {
		result.addRule("FAIL", "entrypoint.discovery", baseSiteOrHostname(baseSite, cfg.Hostname), "no sitemap entrypoint discovered")
		result.addProblem(makeProblem(cfg, "entrypoint_not_found", baseSiteOrHostname(baseSite, cfg.Hostname), ""))
		return result, nil
	}

	visited := map[string]bool{}
	queued := map[string]bool{}
	parents := map[string]string{}
	queue := make([]queueItem, 0, len(entrypoints))
	for _, ep := range entrypoints {
		if queued[ep] {
			continue
		}
		queue = append(queue, queueItem{URL: ep, Depth: 0})
		queued[ep] = true
		parents[ep] = ""
	}

	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			if !hasProblemCode(result.Problems, "fetch_timeout") && !hasProblemCode(result.Problems, "check_timeout") {
				result.addRule("FAIL", "check.timeout", baseSiteOrHostname(baseSite, cfg.Hostname), fmt.Sprintf("timeout after %s", cfg.Timeout))
				result.addProblem(makeProblem(cfg, "check_timeout", baseSiteOrHostname(baseSite, cfg.Hostname), fmt.Sprintf("check timeout after %s", cfg.Timeout)))
			}
			break
		}

		item := queue[0]
		queue = queue[1:]

		if visited[item.URL] {
			continue
		}
		visited[item.URL] = true

		if cfg.MaxFiles > 0 && len(result.Documents) >= cfg.MaxFiles {
			result.addRule("FAIL", "limit.max_files", item.URL, fmt.Sprintf("reached max sitemap files limit %d", cfg.MaxFiles))
			result.addProblem(makeProblem(cfg, "max_files_exceeded", item.URL, fmt.Sprintf("reached max sitemap files limit %d", cfg.MaxFiles)))
			break
		}
		if cfg.MaxDepth > 0 && item.Depth > cfg.MaxDepth {
			result.addRule("FAIL", "limit.max_depth", item.URL, fmt.Sprintf("sitemap depth exceeds limit %d", cfg.MaxDepth))
			result.addProblem(makeProblem(cfg, "max_depth_exceeded", item.URL, fmt.Sprintf("sitemap depth exceeds limit %d", cfg.MaxDepth)))
			continue
		}

		doc, problems, children, urlCount := inspectDocument(ctx, client, cfg, baseSite, item, result)
		result.Documents = append(result.Documents, doc)
		result.addProblems(problems...)
		result.TotalURLs += urlCount
		if item.Depth > result.MaxObservedDepth {
			result.MaxObservedDepth = item.Depth
		}
		result.updateRuntimeStats()

		if cfg.MaxURLs > 0 && result.TotalURLs > cfg.MaxURLs {
			result.addRule("FAIL", "limit.max_urls", item.URL, fmt.Sprintf("parsed URL count exceeds limit %d", cfg.MaxURLs))
			result.addProblem(makeProblem(cfg, "max_urls_exceeded", item.URL, fmt.Sprintf("parsed URL count exceeds limit %d", cfg.MaxURLs)))
			break
		}

		for _, child := range children {
			if createsCycle(item.URL, child, parents) {
				result.addProblem(makeProblem(cfg, "cycle_detected", child, fmt.Sprintf("child sitemap %q points back into the current sitemap chain", child)))
				result.addRule("WARN", "tree.cycle", child, "cyclic sitemap reference detected")
				continue
			}
			if queued[child] || visited[child] {
				result.addProblem(makeProblem(cfg, "duplicate_child", child, ""))
				result.addRule("WARN", "tree.duplicate_child", child, "duplicate child sitemap reference")
				continue
			}
			queue = append(queue, queueItem{URL: child, Depth: item.Depth + 1, Parent: item.URL})
			queued[child] = true
			parents[child] = item.URL
		}
	}

	if len(result.Problems) == 0 {
		result.addRule("PASS", "sitemap.tree", baseSiteOrHostname(baseSite, cfg.Hostname), "tree fetched and parsed successfully")
	}

	return result, nil
}

func discoverEntrypoints(ctx context.Context, client *http.Client, cfg Config, baseSite string, result *Result) ([]string, string, []Problem) {
	if cfg.Entrypoint != "" {
		ep, err := normalizeURL(cfg.Entrypoint)
		if err != nil {
			return nil, "explicit", []Problem{makeProblem(cfg, "invalid_entrypoint", cfg.Entrypoint, err.Error())}
		}
		result.addTrace("using explicit entrypoint %s", ep)
		result.addRule("PASS", "entrypoint.explicit", ep, "using explicit sitemap entrypoint")
		return []string{ep}, "explicit", nil
	}

	robotsURL := cfg.RobotsURL
	if robotsURL == "" && baseSite != "" {
		robotsURL = strings.TrimRight(baseSite, "/") + "/robots.txt"
	}

	var problems []Problem
	if robotsURL != "" {
		result.addTrace("trying robots discovery via %s", robotsURL)
		discovery, err := parseRobots(ctx, client, cfg, robotsURL, result)
		if err != nil {
			result.addRule("WARN", "robots.fetch", robotsURL, err.Error())
			problems = append(problems, makeProblem(cfg, "robots_fetch_failed", robotsURL, err.Error()))
		} else if len(discovery.Sitemaps) > 0 {
			result.addRule("PASS", "robots.sitemap_directive", robotsURL, fmt.Sprintf("found %d sitemap entrypoints", len(discovery.Sitemaps)))
			result.addTrace("robots discovery found %d sitemap entrypoints", len(discovery.Sitemaps))
			return uniqueURLs(discovery.Sitemaps), "robots", problems
		}
		result.addRule("WARN", "robots.sitemap_directive", robotsURL, "no Sitemap directive found")
		result.addTrace("robots discovery found no Sitemap directives")
	}

	if !cfg.FallbackProbe || baseSite == "" {
		return nil, "none", problems
	}

	found := make([]string, 0, 1)
	for _, p := range cfg.FallbackPaths {
		u := strings.TrimRight(baseSite, "/") + p
		ok, err := probeURL(ctx, client, cfg, u, result)
		if err != nil {
			result.addTrace("fallback probe failed %s: %v", u, err)
			problems = append(problems, makeProblem(cfg, "fallback_probe_failed", u, err.Error()))
			continue
		}
		if ok {
			result.addTrace("fallback probe matched %s", u)
			found = append(found, u)
		} else {
			result.addTrace("fallback probe miss %s", u)
		}
	}

	if len(found) > 0 {
		severity := SeverityWarning
		if FallbackSeverity(cfg.FallbackStatus) == FallbackOK {
			severity = SeverityOK
		}
		status := "WARN"
		if severity == SeverityOK {
			status = "PASS"
		}
		result.addRule(status, "fallback.discovery", found[0], "resolved sitemap via common-path fallback")
		problems = append(problems, makeProblem(cfg, "fallback_used", found[0], "", severity))
	}

	if len(found) == 0 {
		result.addRule("FAIL", "fallback.discovery", baseSite, "no sitemap found in fallback paths")
	}

	return uniqueURLs(found), "fallback", problems
}

func parseRobots(ctx context.Context, client *http.Client, cfg Config, robotsURL string, result *Result) (*robotsDiscovery, error) {
	res, err := fetch(ctx, client, cfg, robotsURL, result)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("robots.txt returned HTTP %d", res.StatusCode)
	}

	scanner := bufio.NewScanner(bytes.NewReader(res.Body))
	out := &robotsDiscovery{}
	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(strings.ToLower(parts[0]))
		value := strings.TrimSpace(parts[1])
		if key != "sitemap" || value == "" {
			continue
		}
		normalized, err := normalizeURL(value)
		if err != nil {
			continue
		}
		out.Sitemaps = append(out.Sitemaps, normalized)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	result.addTrace("parsed robots.txt %s, sitemap_directives=%d", robotsURL, len(out.Sitemaps))
	return out, nil
}

func probeURL(ctx context.Context, client *http.Client, cfg Config, rawURL string, result *Result) (bool, error) {
	res, err := fetchHTTP(ctx, client, cfg, rawURL, http.MethodHead, result, "fallback probe")
	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusMethodNotAllowed || res.StatusCode == http.StatusNotImplemented {
		return probeURLByContent(ctx, client, cfg, rawURL, result, "fallback probe retry after HEAD rejected")
	}
	if res.StatusCode != http.StatusOK {
		return false, nil
	}
	return probeURLByContent(ctx, client, cfg, rawURL, result, "fallback probe content validation")
}

func probeURLByContent(ctx context.Context, client *http.Client, cfg Config, rawURL string, result *Result, note string) (bool, error) {
	res, err := fetchHTTP(ctx, client, cfg, rawURL, http.MethodGet, result, note)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return false, nil
	}

	body, compressed, readTime, netBytes, rawBytes, err := decodeBody(rawURL, res)
	if err != nil {
		if result != nil {
			result.attachHTTPError(rawURL, http.MethodGet, fmt.Sprintf("read error: %v", err), readTime, netBytes, rawBytes)
		}
		return false, err
	}
	if result != nil {
		result.attachHTTPRead(rawURL, http.MethodGet, readTime, netBytes, rawBytes, compressed)
	}
	parsed, _ := parseSitemapDocument(cfg, rawURL, body)
	if parsed.Kind == "unknown" {
		return false, nil
	}
	return true, nil
}

func inspectDocument(ctx context.Context, client *http.Client, cfg Config, baseSite string, item queueItem, result *Result) (DocumentResult, []Problem, []string, int) {
	doc := DocumentResult{URL: item.URL, Depth: item.Depth}
	var problems []Problem
	parseStart := time.Now()

	res, err := fetch(ctx, client, cfg, item.URL, result)
	if err != nil {
		code := "fetch_failed"
		message := err.Error()
		ruleName := "document.fetch"
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			code = "check_timeout"
			message = fmt.Sprintf("check timeout after %s while fetching sitemap document", cfg.Timeout)
			ruleName = "check.timeout"
		} else if errors.Is(err, context.DeadlineExceeded) {
			code = "fetch_timeout"
			message = fmt.Sprintf("request timeout after %s", cfg.Timeout)
		}
		problems = append(problems, makeProblem(cfg, code, item.URL, message))
		result.addRule("FAIL", ruleName, item.URL, message)
		return doc, problems, nil, 0
	}

	doc.StatusCode = res.StatusCode
	doc.Compressed = res.Compressed

	if res.StatusCode != http.StatusOK {
		problems = append(problems, makeProblem(cfg, "bad_status", item.URL, fmt.Sprintf("HTTP %d", res.StatusCode)))
		result.addRule("FAIL", "document.status", item.URL, fmt.Sprintf("HTTP %d", res.StatusCode))
		return doc, problems, nil, 0
	}

	parsed, parseProblems := parseSitemapDocument(cfg, item.URL, res.Body)
	parseDuration := time.Since(parseStart) - res.HeadersTime - res.ReadTime
	if parseDuration < 0 {
		parseDuration = 0
	}
	problems = append(problems, parseProblems...)
	doc.Kind = parsed.Kind
	doc.Entries = parsed.URLCount
	doc.Children = len(parsed.Children)
	result.attachDocumentTiming(item.URL, res.HeadersTime, res.ReadTime, parseDuration, res.HeadersTime+res.ReadTime+parseDuration, res.Compressed, res.NetBytes, res.RawBytes)
	result.TotalNetBytes += res.NetBytes
	result.TotalRawBytes += res.RawBytes
	if message, ok := unexpectedContentTypeMessage(res.ContentType, doc.Kind); ok {
		problems = append(problems, makeProblem(cfg, "content_type_unexpected", item.URL, message))
		result.addRule("WARN", "document.content_type", item.URL, message)
	} else if res.ContentType != "" {
		result.addRule("PASS", "document.content_type", item.URL, normalizeContentType(res.ContentType))
	}

	for _, child := range parsed.Children {
		if err := validateChildURL(item.URL, child, baseSite, cfg); err != nil {
			problems = append(problems, makeProblem(cfg, "child_scope_invalid", child, err.Error(), severityFromStrict(cfg.Strict)))
			result.addRule(ruleStatusFromSeverity(severityFromStrict(cfg.Strict)), "child.scope", child, err.Error())
		}
	}

	if parsed.Kind == "unknown" {
		problems = append(problems, makeProblem(cfg, "unsupported_format", item.URL, ""))
		result.addRule("FAIL", "document.parse", item.URL, "unsupported sitemap document format")
		return doc, problems, parsed.Children, parsed.URLCount
	}

	result.addRule("PASS", "document.parse", item.URL, fmt.Sprintf("kind=%s entries=%d children=%d gzip=%t", doc.Kind, doc.Entries, doc.Children, doc.Compressed))

	return doc, problems, parsed.Children, parsed.URLCount
}

func fetch(ctx context.Context, client *http.Client, cfg Config, rawURL string, result *Result) (*fetchResult, error) {
	res, err := fetchHTTP(ctx, client, cfg, rawURL, http.MethodGet, result, "")
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, compressed, readTime, netBytes, rawBytes, err := decodeBody(rawURL, res)
	if err != nil {
		if result != nil {
			note := fmt.Sprintf("read error: %v", err)
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				note = fmt.Sprintf("check timeout during body read: %v", err)
			}
			result.attachHTTPError(rawURL, http.MethodGet, note, readTime, netBytes, rawBytes)
		}
		return nil, err
	}
	if result != nil {
		result.attachHTTPRead(rawURL, http.MethodGet, readTime, netBytes, rawBytes, compressed)
	}
	return &fetchResult{
		StatusCode:    res.StatusCode,
		Body:          body,
		Compressed:    compressed,
		ContentType:   res.Header.Get("Content-Type"),
		HeadersTime:   lastHTTPCallHeadersTime(result, rawURL, http.MethodGet),
		ReadTime:      readTime,
		NetBytes:      netBytes,
		RawBytes:      rawBytes,
	}, nil
}

func fetchHTTP(ctx context.Context, client *http.Client, cfg Config, rawURL string, method string, result *Result, note string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", cfg.HTTP.UserAgent)
	req.Header.Set("Accept", "application/xml,text/xml,text/plain,*/*")
	start := time.Now()
	res, err := client.Do(req)
	headersTime := time.Since(start)
	if err != nil {
		if result != nil {
			note := fmt.Sprintf("error: %v", err)
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				note = fmt.Sprintf("check timeout: %v", err)
			}
			result.HTTPTrace = append(result.HTTPTrace, HTTPCall{Method: method, URL: rawURL, HeadersTime: headersTime, StatusCode: 0, Note: note})
		}
		return nil, err
	}
	if result != nil {
		finalURL := ""
		if res.Request != nil && res.Request.URL != nil {
			finalURL = res.Request.URL.String()
		}
		if finalURL != "" && finalURL != rawURL {
			if note != "" {
				note = fmt.Sprintf("%s; final=%s", note, finalURL)
			} else {
				note = fmt.Sprintf("final=%s", finalURL)
			}
		}
		result.HTTPTrace = append(result.HTTPTrace, HTTPCall{Method: method, URL: rawURL, FinalURL: finalURL, HeadersTime: headersTime, StatusCode: res.StatusCode, Note: note})
	}
	return res, nil
}

func decodeBody(rawURL string, res *http.Response) ([]byte, bool, time.Duration, int, int, error) {
	counter := &countingReader{Reader: res.Body}
	var reader io.Reader = counter
	compressed := false

	contentEncoding := strings.ToLower(strings.TrimSpace(res.Header.Get("Content-Encoding")))
	if strings.Contains(contentEncoding, "gzip") || strings.HasSuffix(strings.ToLower(rawURL), ".gz") {
		gzr, err := gzip.NewReader(counter)
		if err != nil {
			return nil, false, 0, counter.N, 0, fmt.Errorf("gzip decode failed: %w", err)
		}
		defer gzr.Close()
		reader = gzr
		compressed = true
	}

	start := time.Now()
	limited := io.LimitReader(reader, maxSitemapFileBytes+1)
	body, err := io.ReadAll(limited)
	readTime := time.Since(start)
	if err != nil {
		return nil, compressed, readTime, counter.N, len(body), err
	}
	if len(body) > maxSitemapFileBytes {
		return nil, compressed, readTime, counter.N, len(body), fmt.Errorf("uncompressed sitemap exceeds %d bytes", maxSitemapFileBytes)
	}
	return body, compressed, readTime, counter.N, len(body), nil
}

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

func (r *Result) ExitCode() int {
	if r.hasTraversalLimitProblem() {
		return ExitUnknown
	}
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

	if len(r.Problems) > 0 {
		primary := r.primaryProblem()
		if r.hasReliableStats() {
			return fmt.Sprintf("%s - %s (%s) | sitemap_files=%d urls=%d depth=%d warnings=%d criticals=%d ignored=%d bytes_net=%d bytes_raw=%d elapsed_ms=%d heap_alloc_peak=%d heap_sys_peak=%d",
				label,
				primary.Message,
				primary.URL,
				len(r.Documents),
				r.TotalURLs,
				r.MaxObservedDepth,
				r.countProblems(SeverityWarning),
				r.countProblems(SeverityCritical),
				len(r.IgnoredProblems),
				r.TotalNetBytes,
				r.TotalRawBytes,
				r.Elapsed.Milliseconds(),
				r.PeakHeapAlloc,
				r.PeakHeapSys,
			)
		}
		return fmt.Sprintf("%s - %s (%s) | warnings=%d criticals=%d ignored=%d partial=1 bytes_net=%d bytes_raw=%d elapsed_ms=%d heap_alloc_peak=%d heap_sys_peak=%d",
			label,
			primary.Message,
			primary.URL,
			r.countProblems(SeverityWarning),
			r.countProblems(SeverityCritical),
			len(r.IgnoredProblems),
			r.TotalNetBytes,
			r.TotalRawBytes,
			r.Elapsed.Milliseconds(),
			r.PeakHeapAlloc,
			r.PeakHeapSys,
		)
	}

	if r.Config.Verbosity > 0 {
		return fmt.Sprintf("%s - discovery=%s entrypoints=%d sitemap_files=%d urls=%d depth=%d bytes_net=%d bytes_raw=%d | sitemap_files=%d urls=%d depth=%d warnings=0 criticals=0 ignored=%d bytes_net=%d bytes_raw=%d elapsed_ms=%d heap_alloc_peak=%d heap_sys_peak=%d",
			label, r.DiscoveredVia, len(r.Entrypoints), len(r.Documents), r.TotalURLs, r.MaxObservedDepth,
			r.TotalNetBytes, r.TotalRawBytes,
			len(r.Documents), r.TotalURLs, r.MaxObservedDepth, len(r.IgnoredProblems), r.TotalNetBytes, r.TotalRawBytes, r.Elapsed.Milliseconds(), r.PeakHeapAlloc, r.PeakHeapSys)
	}

	return fmt.Sprintf("%s - %d sitemap files, %d URLs, depth %d, net %d B, raw %d B | sitemap_files=%d urls=%d depth=%d warnings=0 criticals=0 ignored=%d bytes_net=%d bytes_raw=%d elapsed_ms=%d heap_alloc_peak=%d heap_sys_peak=%d",
		label, len(r.Documents), r.TotalURLs, r.MaxObservedDepth,
		r.TotalNetBytes, r.TotalRawBytes,
		len(r.Documents), r.TotalURLs, r.MaxObservedDepth, len(r.IgnoredProblems), r.TotalNetBytes, r.TotalRawBytes, r.Elapsed.Milliseconds(), r.PeakHeapAlloc, r.PeakHeapSys)
}

func (r *Result) Detail() string {
	var b strings.Builder
	b.WriteString(r.Summary())
	b.WriteByte('\n')
	if r.Config.Verbosity > 0 {
		b.WriteString("Target:\n")
		fmt.Fprintf(&b, "  - source=%s effective_base=%s hostname=%q url=%q entrypoint=%q\n", r.TargetSource, emptyAsDash(r.EffectiveBaseURL), r.Config.Hostname, r.Config.URL, r.Config.Entrypoint)
		b.WriteString("Discovery:\n")
		fmt.Fprintf(&b, "  - method=%s entrypoints=%d\n", r.DiscoveredVia, len(r.Entrypoints))
		for _, line := range r.DiscoveryTrace {
			b.WriteString("  - ")
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	if len(r.Rules) > 0 {
		b.WriteString("Rules:\n")
		for _, rule := range r.Rules {
			fmt.Fprintf(&b, "  - %s %s: %s [%s]\n", rule.Status, rule.Name, rule.Detail, rule.Target)
		}
	}
	if len(r.Entrypoints) > 0 {
		b.WriteString("Entrypoints:\n")
		for _, ep := range r.Entrypoints {
			b.WriteString("  - ")
			b.WriteString(ep)
			b.WriteByte('\n')
		}
	}
	if len(r.Documents) > 0 && r.Config.Verbosity > 0 {
		b.WriteString("Documents:\n")
		for _, doc := range r.Documents {
			fmt.Fprintf(&b, "  - depth=%d kind=%s status=%d entries=%d children=%d gzip=%t url=%s\n",
				doc.Depth, doc.Kind, doc.StatusCode, doc.Entries, doc.Children, doc.Compressed, doc.URL)
		}
	}
	if len(r.HTTPTrace) > 0 && r.Config.Verbosity > 1 {
		b.WriteString("HTTP:\n")
		for _, call := range r.HTTPTrace {
			target := call.URL
			if call.FinalURL != "" && call.FinalURL != call.URL {
				target = fmt.Sprintf("%s -> %s", call.URL, call.FinalURL)
			}
			if call.Note != "" {
				fmt.Fprintf(&b, "  - %s %d headers=%s read=%s parse=%s total=%s net_bytes=%d raw_bytes=%d gzip=%t %s (%s)\n",
					call.Method, call.StatusCode, call.HeadersTime, call.ReadTime, call.ParseTime, call.TotalTime, call.NetBytes, call.RawBytes, call.Compressed, target, call.Note)
				continue
			}
			fmt.Fprintf(&b, "  - %s %d headers=%s read=%s parse=%s total=%s net_bytes=%d raw_bytes=%d gzip=%t %s\n",
				call.Method, call.StatusCode, call.HeadersTime, call.ReadTime, call.ParseTime, call.TotalTime, call.NetBytes, call.RawBytes, call.Compressed, target)
		}
	}
	if r.Config.Verbosity > 0 {
		b.WriteString("Performance:\n")
		fmt.Fprintf(&b, "  - elapsed=%s net_bytes=%d raw_bytes=%d heap_alloc_peak=%d heap_sys_peak=%d\n",
			r.Elapsed, r.TotalNetBytes, r.TotalRawBytes, r.PeakHeapAlloc, r.PeakHeapSys)
	}
	if len(r.Problems) > 0 {
		b.WriteString("Problems:\n")
		for _, p := range r.Problems {
			fmt.Fprintf(&b, "  - %s %s: %s [%s]\n", severityName(p.Severity), p.Code, p.Message, p.URL)
		}
	}
	if len(r.IgnoredProblems) > 0 {
		b.WriteString("Ignored Problems:\n")
		for _, p := range r.IgnoredProblems {
			fmt.Fprintf(&b, "  - IGNORED %s original=%s: %s [%s]\n", p.Code, severityName(p.Severity), p.Message, p.URL)
		}
	}
	return b.String()
}

func (r *Result) addTrace(format string, args ...any) {
	r.DiscoveryTrace = append(r.DiscoveryTrace, fmt.Sprintf(format, args...))
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
		if r.Config.Verbosity > 0 {
			r.addRule("IGNORE", "problem."+p.Code, p.URL, p.Message)
		}
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

func (r *Result) attachDocumentTiming(rawURL string, headersTime, readTime, parseTime, totalTime time.Duration, compressed bool, netBytes, rawBytes int) {
	for i := len(r.HTTPTrace) - 1; i >= 0; i-- {
		call := &r.HTTPTrace[i]
		if call.Method != http.MethodGet || call.URL != rawURL {
			continue
		}
		call.ReadTime = readTime
		call.ParseTime = parseTime
		call.TotalTime = totalTime
		call.Compressed = compressed
		call.NetBytes = netBytes
		call.RawBytes = rawBytes
		return
	}
}

func (r *Result) attachHTTPRead(rawURL, method string, readTime time.Duration, netBytes, rawBytes int, compressed bool) {
	for i := len(r.HTTPTrace) - 1; i >= 0; i-- {
		call := &r.HTTPTrace[i]
		if call.Method != method || call.URL != rawURL {
			continue
		}
		call.ReadTime = readTime
		call.TotalTime = call.HeadersTime + readTime
		call.Compressed = compressed
		call.NetBytes = netBytes
		call.RawBytes = rawBytes
		return
	}
}

func (r *Result) attachHTTPError(rawURL, method, note string, readTime time.Duration, netBytes, rawBytes int) {
	for i := len(r.HTTPTrace) - 1; i >= 0; i-- {
		call := &r.HTTPTrace[i]
		if call.Method != method || call.URL != rawURL {
			continue
		}
		call.Note = note
		call.ReadTime = readTime
		call.NetBytes = netBytes
		call.RawBytes = rawBytes
		call.TotalTime = call.HeadersTime + readTime
		return
	}
}

func (r *Result) updateRuntimeStats() {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	if ms.HeapAlloc > r.PeakHeapAlloc {
		r.PeakHeapAlloc = ms.HeapAlloc
	}
	if ms.HeapSys > r.PeakHeapSys {
		r.PeakHeapSys = ms.HeapSys
	}
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

func statusLabel(exitCode int) string {
	switch exitCode {
	case ExitWarning:
		return "WARNING"
	case ExitCritical:
		return "CRITICAL"
	case ExitUnknown:
		return "UNKNOWN"
	default:
		return "OK"
	}
}

func (r *Result) primaryProblem() Problem {
	primary := r.Problems[0]
	for _, p := range r.Problems[1:] {
		if p.Severity > primary.Severity || (p.Severity == primary.Severity && problemPriority(p) > problemPriority(primary)) {
			primary = p
		}
	}
	return primary
}

func problemPriority(p Problem) int {
	switch p.Code {
	case "check_timeout":
		return 100
	case "entrypoint_not_found":
		return 90
	case "fetch_timeout":
		return 80
	case "fetch_failed", "bad_status":
		return 70
	case "max_files_exceeded", "max_depth_exceeded", "max_urls_exceeded":
		return 60
	default:
		return 10
	}
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

func (r *Result) hasReliableStats() bool {
	for _, p := range r.Problems {
		switch p.Code {
		case "check_timeout",
			"fetch_timeout",
			"fetch_failed",
			"bad_status",
			"max_files_exceeded",
			"max_depth_exceeded",
			"max_urls_exceeded":
			return false
		}
	}
	return true
}

func (r *Result) hasTraversalLimitProblem() bool {
	for _, p := range r.Problems {
		switch p.Code {
		case "max_files_exceeded", "max_depth_exceeded", "max_urls_exceeded":
			return true
		}
	}
	return false
}

func createsCycle(parentURL, childURL string, parents map[string]string) bool {
	if childURL == parentURL {
		return true
	}
	current := parentURL
	for current != "" {
		if current == childURL {
			return true
		}
		current = parents[current]
	}
	return false
}

func severityName(sev Severity) string { return finding.SeverityName(sev) }

func hasProblemCode(problems []Problem, code string) bool {
	for _, p := range problems {
		if p.Code == code {
			return true
		}
	}
	return false
}

func ruleStatusFromSeverity(sev Severity) string {
	switch sev {
	case SeverityCritical:
		return "FAIL"
	case SeverityWarning:
		return "WARN"
	default:
		return "PASS"
	}
}

func lastHTTPCallHeadersTime(result *Result, rawURL, method string) time.Duration {
	if result == nil {
		return 0
	}
	for i := len(result.HTTPTrace) - 1; i >= 0; i-- {
		call := result.HTTPTrace[i]
		if call.Method == method && call.URL == rawURL {
			return call.HeadersTime
		}
	}
	return 0
}

func normalizeBaseSite(cfg Config) (string, error) {
	if cfg.URL != "" {
		u, err := normalizeURL(cfg.URL)
		if err != nil {
			return "", fmt.Errorf("invalid --url: %w", err)
		}
		parsed, _ := url.Parse(u)
		parsed.Path = "/"
		parsed.RawQuery = ""
		parsed.Fragment = ""
		return strings.TrimRight(parsed.String(), "/"), nil
	}
	if cfg.Hostname == "" {
		return "", nil
	}
	return normalizeURL("https://" + strings.TrimSpace(cfg.Hostname))
}

func targetSelectionTrace(cfg Config, baseSite string) string {
	switch {
	case cfg.Entrypoint != "":
		return fmt.Sprintf("effective target source=entrypoint base_site=%q hostname_ignored=%t url_ignored=%t", baseSite, cfg.Hostname != "", cfg.URL != "")
	case cfg.URL != "":
		return fmt.Sprintf("effective target source=url base_site=%q hostname=%q hostname_used_for_discovery=false", baseSite, cfg.Hostname)
	case cfg.Hostname != "":
		return fmt.Sprintf("effective target source=hostname base_site=%q", baseSite)
	default:
		return "effective target source=none"
	}
}

func targetSource(cfg Config) string {
	switch {
	case cfg.Entrypoint != "":
		return "entrypoint"
	case cfg.URL != "":
		return "url"
	case cfg.Hostname != "":
		return "hostname"
	default:
		return "none"
	}
}

func withTraceRedirects(client *http.Client, result *Result) *http.Client {
	if client == nil {
		return nil
	}

	cloned := *client
	original := client.CheckRedirect
	cloned.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if result != nil && len(via) > 0 {
			prev := via[len(via)-1]
			status := 0
			if req.Response != nil {
				status = req.Response.StatusCode
			}
			result.HTTPTrace = append(result.HTTPTrace, HTTPCall{
				Method:     prev.Method,
				URL:        prev.URL.String(),
				FinalURL:   req.URL.String(),
				StatusCode: status,
				Note:       "redirect",
			})
		}
		if original != nil {
			return original(req, via)
		}
		return nil
	}
	return &cloned
}

func normalizeURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("URL must be absolute: %q", raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("unsupported URL scheme %q", u.Scheme)
	}
	if u.Path == "" {
		u.Path = "/"
	}
	u.Fragment = ""
	return u.String(), nil
}

func uniqueURLs(items []string) []string {
	seen := make(map[string]bool, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

func sameHost(a, b *url.URL) bool {
	return strings.EqualFold(a.Hostname(), b.Hostname()) && normalizedPort(a) == normalizedPort(b)
}

func normalizedPort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

func parentDirPrefix(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "/"
	}
	dir := path.Dir(u.Path)
	if dir == "." {
		return "/"
	}
	if !strings.HasSuffix(dir, "/") {
		dir += "/"
	}
	return dir
}

func baseSiteOrHostname(baseSite, hostname string) string {
	if baseSite != "" {
		return baseSite
	}
	return hostname
}

func emptyAsDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
