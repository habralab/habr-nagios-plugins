package sitemap

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

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

	scopeSourceURL := item.URL
	if res.FinalURL != "" {
		scopeSourceURL = res.FinalURL
		result.trustHost(res.FinalURL)
	}

	doc.StatusCode = res.StatusCode
	doc.Compressed = res.Payload.Compressed

	if res.StatusCode != http.StatusOK {
		problems = append(problems, makeProblem(cfg, "bad_status", item.URL, fmt.Sprintf("HTTP %d", res.StatusCode)))
		result.addRule("FAIL", "document.status", item.URL, fmt.Sprintf("HTTP %d", res.StatusCode))
		return doc, problems, nil, 0
	}

	parsed, parseProblems := parseSitemapDocument(cfg, item.URL, res.ContentType, res.Body)
	parseDuration := time.Since(parseStart) - res.HeadersTime - res.ReadTime
	if parseDuration < 0 {
		parseDuration = 0
	}
	problems = append(problems, parseProblems...)
	doc.Kind = parsed.Kind
	doc.Entries = parsed.URLCount
	doc.Children = len(parsed.Children)
	doc.Encoding = parsed.Encoding
	result.attachDocumentTiming(item.URL, res.HeadersTime, res.ReadTime, parseDuration, res.HeadersTime+res.ReadTime+parseDuration, res.Payload)
	result.Perf.TotalNetBytes += res.Payload.NetBytes
	result.Perf.TotalRawBytes += res.Payload.RawBytes
	if message, ok := unexpectedContentTypeMessage(res.ContentType, doc.Kind); ok {
		problems = append(problems, makeProblem(cfg, "content_type_unexpected", item.URL, message))
		result.addRule("WARN", "document.content_type", item.URL, message)
	} else if res.ContentType != "" {
		result.addRule("PASS", "document.content_type", item.URL, normalizeContentType(res.ContentType))
	}

	for _, child := range parsed.Children {
		if err := checkChildScope(ctx, client, cfg, scopeSourceURL, child, baseSite, result); err != nil {
			problems = append(problems, makeProblem(cfg, "child_scope_invalid", child, err.Error(), severityFromStrict(cfg.Strict)))
			result.addRule(ruleStatusFromSeverity(severityFromStrict(cfg.Strict)), "child.scope", child, err.Error())
		}
	}

	for _, entry := range parsed.URLs {
		if err := checkEntryScope(ctx, client, cfg, scopeSourceURL, entry, result); err != nil {
			problems = append(problems, makeProblem(cfg, "url_scope_invalid", entry, err.Error(), severityFromStrict(cfg.Strict)))
			result.addRule(ruleStatusFromSeverity(severityFromStrict(cfg.Strict)), "url.scope", entry, err.Error())
		}
	}

	for _, obs := range parsed.Extensions {
		status := "PASS"
		detail := fmt.Sprintf("namespace=%s entries=%d issues=%d", obs.NamespaceURI, obs.Count, obs.IssueCount)
		if obs.IssueCount > 0 {
			status = "WARN"
		}
		result.addRule(status, "extension."+obs.ID, item.URL, detail)
	}

	if parsed.Kind == "unknown" {
		problems = append(problems, makeProblem(cfg, "unsupported_format", item.URL, ""))
		result.addRule("FAIL", "document.parse", item.URL, "unsupported sitemap document format")
		return doc, problems, parsed.Children, parsed.URLCount
	}

	result.addRule("PASS", "document.parse", item.URL, fmt.Sprintf("kind=%s entries=%d children=%d encoding=%s gzip=%t", doc.Kind, doc.Entries, doc.Children, doc.Encoding, doc.Compressed))

	return doc, problems, parsed.Children, parsed.URLCount
}

func checkChildScope(ctx context.Context, client *http.Client, cfg Config, currentSitemap, child, baseSite string, result *Result) error {
	if err := validateChildURL(currentSitemap, child, baseSite, result.CrossHostTrust, cfg); err == nil {
		return nil
	}

	if cfg.AllowCrossHost {
		return nil
	}
	trusted, robotsURL, trustErr := verifyCrossSubmitHost(ctx, client, cfg, child, currentSitemap, result)
	if trusted {
		if err := validateChildURL(currentSitemap, child, baseSite, result.CrossHostTrust, cfg); err == nil {
			return nil
		}
	}
	if trustErr != nil {
		return fmt.Errorf("child sitemap host could not be verified for cross-submit via %s: %v", robotsURL, trustErr)
	}
	if robotsURL != "" {
		return fmt.Errorf("child sitemap host is not delegated via %s to the current sitemap tree", robotsURL)
	}
	return validateChildURL(currentSitemap, child, baseSite, result.CrossHostTrust, cfg)
}

func checkEntryScope(ctx context.Context, client *http.Client, cfg Config, currentSitemap, entry string, result *Result) error {
	if err := validateEntryURL(currentSitemap, entry, result.CrossHostTrust, cfg); err == nil {
		return nil
	}

	if cfg.AllowCrossHost {
		return nil
	}
	trusted, robotsURL, trustErr := verifyCrossSubmitHost(ctx, client, cfg, entry, currentSitemap, result)
	if trusted {
		if err := validateEntryURL(currentSitemap, entry, result.CrossHostTrust, cfg); err == nil {
			return nil
		}
	}
	if trustErr != nil {
		return fmt.Errorf("entry URL host could not be verified for cross-submit via %s: %v", robotsURL, trustErr)
	}
	if robotsURL != "" {
		return fmt.Errorf("entry URL host is not delegated via %s to the current sitemap tree", robotsURL)
	}
	return validateEntryURL(currentSitemap, entry, result.CrossHostTrust, cfg)
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
		StatusCode:  res.StatusCode,
		Body:        body,
		ContentType: res.Header.Get("Content-Type"),
		HeadersTime: lastHTTPCallHeadersTime(result, rawURL, http.MethodGet),
		ReadTime:    readTime,
		FinalURL:    res.Request.URL.String(),
		Payload: PayloadStats{
			Compressed: compressed,
			NetBytes:   netBytes,
			RawBytes:   rawBytes,
		},
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
	isGzipURL := strings.HasSuffix(strings.ToLower(rawURL), ".gz")

	// We only wrap in gzip reader if Content-Encoding is gzip OR it's a .gz file.
	// However, if net/http already decompressed it (it strips Content-Encoding),
	// we shouldn't try to decompress again.
	if strings.Contains(contentEncoding, "gzip") || (isGzipURL && contentEncoding == "") {
		// Peek for gzip magic bytes to be absolutely sure before wrapping.
		// Since we don't have an easy way to peek a Reader without complex buffering here,
		// we'll try to create the reader and if it fails immediately with "invalid header",
		// we might fall back to raw reader if it was just a .gz extension but not actually gzipped.
		gzr, err := gzip.NewReader(counter)
		if err != nil {
			if isGzipURL && errors.Is(err, gzip.ErrHeader) {
				// It has .gz extension but invalid header. Maybe it's already decompressed by CDN?
				// Try to read it as raw.
				reader = counter
			} else {
				return nil, false, 0, counter.N, 0, fmt.Errorf("gzip decode failed: %w", err)
			}
		} else {
			defer gzr.Close()
			reader = gzr
			compressed = true
		}
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
