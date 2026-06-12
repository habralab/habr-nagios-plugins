//go:build live

package sitemap

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRunLiveHTTPServer(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			http.Redirect(w, r, server.URL+"/robots-final.txt", http.StatusMovedPermanently)
		case "/robots-final.txt":
			fmt.Fprintf(w, "User-agent: *\nSitemap: %s/sitemap.xml\n", server.URL)
		case "/sitemap.xml":
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><urlset><url><loc>%s/page</loc></url></urlset>`, server.URL)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.URL = server.URL
	cfg.Timeout = 3 * time.Second
	cfg.Verbosity = 3

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitOK {
		t.Fatalf("ExitCode = %d, want %d", got, ExitOK)
	}

	detail := result.Detail()
	if !strings.Contains(detail, "redirect") {
		t.Fatalf("Detail() = %q, want redirect trace", detail)
	}
	if !strings.Contains(detail, "PASS document.content_type: application/xml") {
		t.Fatalf("Detail() = %q, want content type pass rule", detail)
	}
}

func TestRunLiveHTTPBadStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.URL = server.URL
	cfg.Entrypoint = server.URL
	cfg.Verbosity = 1
	cfg.Timeout = 3 * time.Second

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitCritical {
		t.Fatalf("ExitCode = %d, want %d", got, ExitCritical)
	}
	if got := result.Summary(); !strings.Contains(got, "HTTP 400") {
		t.Fatalf("Summary() = %q, want HTTP 400", got)
	}
}

func TestRunLiveBrokenXML(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><urlset><url><loc>https://probe.test/page</loc></url>`)
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.URL = server.URL
	cfg.Entrypoint = server.URL
	cfg.Verbosity = 1
	cfg.Timeout = 3 * time.Second

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitCritical {
		t.Fatalf("ExitCode = %d, want %d", got, ExitCritical)
	}
	if got := result.Summary(); !strings.Contains(got, "document is neither a sitemapindex nor a urlset") {
		t.Fatalf("Summary() = %q, want XML parse failure", got)
	}
}

func TestRunLiveUnexpectedContentType(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><urlset><url><loc>%s/page</loc></url></urlset>`, server.URL)
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.URL = server.URL
	cfg.Entrypoint = server.URL
	cfg.Verbosity = 1
	cfg.Timeout = 3 * time.Second

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitWarning {
		t.Fatalf("ExitCode = %d, want %d", got, ExitWarning)
	}
	if got := result.Summary(); !strings.Contains(got, `unexpected content type "text/html" for urlset sitemap`) {
		t.Fatalf("Summary() = %q, want content-type warning", got)
	}
}

func TestRunLiveBrokenGzip(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Header().Set("Content-Encoding", "gzip")
		fmt.Fprint(w, "not-a-gzip-stream")
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.URL = server.URL
	cfg.Entrypoint = server.URL
	cfg.Verbosity = 1
	cfg.Timeout = 3 * time.Second

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitCritical {
		t.Fatalf("ExitCode = %d, want %d", got, ExitCritical)
	}
	if got := result.Summary(); !strings.Contains(got, "gzip: invalid header") {
		t.Fatalf("Summary() = %q, want gzip decode failure", got)
	}
}

func TestRunLiveEmptyDocument(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.URL = server.URL
	cfg.Entrypoint = server.URL
	cfg.Verbosity = 1
	cfg.Timeout = 3 * time.Second

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitCritical {
		t.Fatalf("ExitCode = %d, want %d", got, ExitCritical)
	}
	if got := result.Summary(); !strings.Contains(got, "empty sitemap document") {
		t.Fatalf("Summary() = %q, want empty document error", got)
	}
}

func TestRunLiveInvalidURLPayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><urlset><url><loc>://bad-url</loc></url></urlset>`)
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.URL = server.URL
	cfg.Entrypoint = server.URL
	cfg.Verbosity = 1
	cfg.Timeout = 3 * time.Second

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitCritical {
		t.Fatalf("ExitCode = %d, want %d", got, ExitCritical)
	}
	if got := result.Summary(); !strings.Contains(got, `parse "://bad-url": missing protocol scheme`) {
		t.Fatalf("Summary() = %q, want invalid URL error", got)
	}
}

func TestRunLiveTruncatedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatalf("ResponseWriter does not support hijacking")
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			t.Fatalf("Hijack() error = %v", err)
		}
		defer conn.Close()

		raw := "HTTP/1.1 200 OK\r\n" +
			"Content-Type: application/xml\r\n" +
			"Content-Length: 128\r\n" +
			"\r\n" +
			`<?xml version="1.0" encoding="UTF-8"?><urlset><url><loc>https://probe.test/page</loc></url>`
		if _, err := buf.WriteString(raw); err != nil {
			t.Fatalf("WriteString() error = %v", err)
		}
		if err := buf.Flush(); err != nil {
			t.Fatalf("Flush() error = %v", err)
		}
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.URL = server.URL
	cfg.Entrypoint = server.URL
	cfg.Verbosity = 2
	cfg.Timeout = 3 * time.Second

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitCritical {
		t.Fatalf("ExitCode = %d, want %d", got, ExitCritical)
	}
	summary := result.Summary()
	if !strings.Contains(summary, "unexpected EOF") && !strings.Contains(summary, "EOF") {
		t.Fatalf("Summary() = %q, want truncated body read error", summary)
	}
}
