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

	doc.StatusCode = res.StatusCode
	doc.Compressed = res.Payload.Compressed

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
		StatusCode:  res.StatusCode,
		Body:        body,
		ContentType: res.Header.Get("Content-Type"),
		HeadersTime: lastHTTPCallHeadersTime(result, rawURL, http.MethodGet),
		ReadTime:    readTime,
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
