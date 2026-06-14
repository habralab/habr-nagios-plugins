package robots

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var ErrRobotsBodyTooLarge = errors.New("robots.txt exceeds size limit")

type fetchResult struct {
	StatusCode  int
	Body        []byte
	ContentType string
	FinalURL    string
	HeadersTime time.Duration
	ReadTime    time.Duration
	Bytes       int
}

func fetch(ctx context.Context, client *http.Client, cfg Config, rawURL string, result *Result) (*fetchResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", cfg.HTTP.UserAgent)
	req.Header.Set("Accept", "text/plain,*/*")

	start := time.Now()
	res, err := client.Do(req)
	headersTime := time.Since(start)
	if err != nil {
		if result != nil {
			result.HTTPTrace = append(result.HTTPTrace, HTTPCall{
				Method:      http.MethodGet,
				URL:         rawURL,
				HeadersTime: headersTime,
				TotalTime:   headersTime,
				Note:        fmt.Sprintf("error: %v", err),
			})
		}
		return nil, err
	}
	defer res.Body.Close()

	readStart := time.Now()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxRobotsBodyBytes+1))
	readTime := time.Since(readStart)
	if len(body) > maxRobotsBodyBytes {
		if result != nil {
			result.HTTPTrace = append(result.HTTPTrace, HTTPCall{
				Method:      http.MethodGet,
				URL:         rawURL,
				StatusCode:  res.StatusCode,
				FinalURL:    responseURL(res),
				HeadersTime: headersTime,
				ReadTime:    readTime,
				TotalTime:   headersTime + readTime,
				Bytes:       len(body),
				Note:        fmt.Sprintf("body exceeds %d bytes", maxRobotsBodyBytes),
			})
		}
		return nil, fmt.Errorf("%w: %d bytes > %d bytes", ErrRobotsBodyTooLarge, len(body), maxRobotsBodyBytes)
	}
	if err != nil {
		if result != nil {
			note := fmt.Sprintf("read error: %v", err)
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				note = fmt.Sprintf("check timeout during body read: %v", err)
			}
			result.HTTPTrace = append(result.HTTPTrace, HTTPCall{
				Method:      http.MethodGet,
				URL:         rawURL,
				StatusCode:  res.StatusCode,
				FinalURL:    responseURL(res),
				HeadersTime: headersTime,
				ReadTime:    readTime,
				TotalTime:   headersTime + readTime,
				Bytes:       len(body),
				Note:        note,
			})
		}
		return nil, err
	}

	if result != nil {
		result.HTTPTrace = append(result.HTTPTrace, HTTPCall{
			Method:      http.MethodGet,
			URL:         rawURL,
			StatusCode:  res.StatusCode,
			FinalURL:    responseURL(res),
			HeadersTime: headersTime,
			ReadTime:    readTime,
			TotalTime:   headersTime + readTime,
			Bytes:       len(body),
		})
	}
	return &fetchResult{
		StatusCode:  res.StatusCode,
		Body:        body,
		ContentType: res.Header.Get("Content-Type"),
		FinalURL:    responseURL(res),
		HeadersTime: headersTime,
		ReadTime:    readTime,
		Bytes:       len(body),
	}, nil
}

func responseURL(res *http.Response) string {
	if res == nil || res.Request == nil || res.Request.URL == nil {
		return ""
	}
	return res.Request.URL.String()
}

func normalizeContentType(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if idx := strings.Index(raw, ";"); idx >= 0 {
		raw = raw[:idx]
	}
	return raw
}

func unexpectedContentTypeMessage(raw string) (string, bool) {
	contentType := normalizeContentType(raw)
	if contentType == "" {
		return "", false
	}
	switch contentType {
	case "text/plain", "text/plain; charset=utf-8", "application/octet-stream":
		return "", false
	default:
		return fmt.Sprintf("unexpected content type %q for robots.txt", contentType), true
	}
}
