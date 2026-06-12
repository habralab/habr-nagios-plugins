package sitemap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestRunDiscoversEntrypointFromRobots(t *testing.T) {
	serverURL := "https://probe.test"

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Timeout = 2 * time.Second
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/robots.txt":
			return stringResponse(req, http.StatusOK, fmt.Sprintf("User-agent: *\nSitemap: %s/sitemap.xml\n", serverURL)), nil
		case "/sitemap.xml":
			return stringResponse(req, http.StatusOK, fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><urlset><url><loc>%s/page</loc></url></urlset>`, serverURL)), nil
		default:
			return stringResponse(req, http.StatusNotFound, "not found"), nil
		}
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got, want := result.DiscoveredVia, "robots"; got != want {
		t.Fatalf("DiscoveredVia = %q, want %q", got, want)
	}
	if got := len(result.Entrypoints); got != 1 {
		t.Fatalf("Entrypoints len = %d, want 1", got)
	}
	if got := result.ExitCode(); got != ExitOK {
		t.Fatalf("ExitCode = %d, want %d", got, ExitOK)
	}
	if got := result.TotalURLs; got != 1 {
		t.Fatalf("TotalURLs = %d, want 1", got)
	}
}

func TestIgnoredFallbackWarningIsReportedSeparately(t *testing.T) {
	serverURL := "https://probe.test"

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Timeout = 2 * time.Second
	cfg.Verbosity = 1
	cfg.IgnoreErrors = []string{"fallback_used"}
	cfg.IgnoreErrorSet = map[string]bool{"fallback_used": true}
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/robots.txt":
			return stringResponse(req, http.StatusOK, "User-agent: *\nDisallow:\n"), nil
		case "/sitemap.xml":
			return stringResponse(req, http.StatusOK, fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><urlset><url><loc>%s/page</loc></url></urlset>`, serverURL)), nil
		default:
			return stringResponse(req, http.StatusNotFound, "not found"), nil
		}
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitOK {
		t.Fatalf("ExitCode = %d, want %d", got, ExitOK)
	}
	if got := len(result.Problems); got != 0 {
		t.Fatalf("Problems len = %d, want 0", got)
	}
	if got := len(result.IgnoredProblems); got != 1 {
		t.Fatalf("IgnoredProblems len = %d, want 1", got)
	}
	if got := result.IgnoredProblems[0].Code; got != "fallback_used" {
		t.Fatalf("Ignored problem slug = %q, want fallback_used", got)
	}
}

func TestRunPrefersURLOverHostnameInDiscoveryTrace(t *testing.T) {
	serverURL := "https://career.habr.test"

	cfg := DefaultConfig()
	cfg.Hostname = "habr.com"
	cfg.URL = serverURL
	cfg.Timeout = 2 * time.Second
	cfg.Verbosity = 1
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Host {
		case "career.habr.test":
			switch req.URL.Path {
			case "/robots.txt":
				return stringResponse(req, http.StatusOK, fmt.Sprintf("User-agent: *\nSitemap: %s/sitemap.xml\n", serverURL)), nil
			case "/sitemap.xml":
				return stringResponse(req, http.StatusOK, fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><urlset><url><loc>%s/page</loc></url></urlset>`, serverURL)), nil
			}
		case "habr.com":
			t.Fatalf("hostname target should not be used for discovery when --url is set: %s", req.URL.String())
		}
		return stringResponse(req, http.StatusNotFound, "not found"), nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.DiscoveryTrace[1]; !strings.Contains(got, `source=url`) {
		t.Fatalf("DiscoveryTrace target selection = %q, want source=url", got)
	}
	if got := result.DiscoveryTrace[1]; !strings.Contains(got, `hostname_used_for_discovery=false`) {
		t.Fatalf("DiscoveryTrace target selection = %q, want hostname_used_for_discovery=false", got)
	}
}

func TestRunRecordsHTTPRedirectTrace(t *testing.T) {
	serverURL := "http://career.habr.test"

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Timeout = 2 * time.Second
	cfg.Verbosity = 3
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/robots.txt":
			res := stringResponse(req, http.StatusMovedPermanently, "")
			res.Header.Set("Location", serverURL+"/robots-final.txt")
			return res, nil
		case "/robots-final.txt":
			return stringResponse(req, http.StatusOK, fmt.Sprintf("User-agent: *\nSitemap: %s/sitemap.xml\n", serverURL)), nil
		case "/sitemap.xml":
			return stringResponse(req, http.StatusOK, fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><urlset><url><loc>%s/page</loc></url></urlset>`, serverURL)), nil
		default:
			return stringResponse(req, http.StatusNotFound, "not found"), nil
		}
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	foundRedirect := false
	for _, call := range result.HTTPTrace {
		if call.Note == "redirect" && strings.Contains(call.URL, "/robots.txt") && strings.Contains(call.FinalURL, "/robots-final.txt") {
			foundRedirect = true
			break
		}
	}
	if !foundRedirect {
		t.Fatalf("HTTPTrace did not contain expected redirect: %+v", result.HTTPTrace)
	}
}

func TestRunReportsFetchTimeoutInSummaryAndDetail(t *testing.T) {
	serverURL := "https://probe.test"

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Entrypoint = serverURL + "/sitemap.xml"
	cfg.Timeout = 1500 * time.Millisecond
	cfg.Verbosity = 1
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return nil, context.DeadlineExceeded
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if got := result.Summary(); !strings.Contains(got, "request timeout after 1.5s") {
		t.Fatalf("Summary() = %q, want timeout message", got)
	}
	detail := result.Detail()
	if !strings.Contains(detail, "FAIL document.fetch: request timeout after 1.5s") {
		t.Fatalf("Detail() = %q, want fetch timeout rule", detail)
	}
	if !strings.Contains(detail, "CRITICAL fetch_timeout: request timeout after 1.5s") {
		t.Fatalf("Detail() = %q, want fetch_timeout problem", detail)
	}
}

func TestRunReportsNetworkFetchFailureInSummaryAndDetail(t *testing.T) {
	serverURL := "https://probe.test"
	networkErr := errors.New(`dial tcp 203.0.113.10:443: connect: no route to host`)

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Entrypoint = serverURL + "/sitemap.xml"
	cfg.Verbosity = 2
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return nil, networkErr
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if got := result.Summary(); !strings.Contains(got, networkErr.Error()) {
		t.Fatalf("Summary() = %q, want raw network error", got)
	}
	detail := result.Detail()
	if !strings.Contains(detail, `FAIL document.fetch: Get "https://probe.test/sitemap.xml": `+networkErr.Error()) {
		t.Fatalf("Detail() = %q, want fetch failure rule", detail)
	}
	if !strings.Contains(detail, `CRITICAL fetch_failed: Get "https://probe.test/sitemap.xml": `+networkErr.Error()) {
		t.Fatalf("Detail() = %q, want fetch_failed problem", detail)
	}
	if !strings.Contains(detail, "HTTP:\n") || !strings.Contains(detail, "error: Get") {
		t.Fatalf("Detail() = %q, want HTTP error trace", detail)
	}
}

func TestRunReportsBrokenXMLInSummaryAndDetail(t *testing.T) {
	serverURL := "https://probe.test"
	brokenXML := `<?xml version="1.0" encoding="UTF-8"?><urlset><url><loc>https://probe.test/page</loc></url>`

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Entrypoint = serverURL + "/sitemap.xml"
	cfg.Verbosity = 1
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		res := stringResponse(req, http.StatusOK, brokenXML)
		res.Header.Set("Content-Type", "application/xml")
		return res, nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if got := result.Summary(); !strings.Contains(got, "document is neither a sitemapindex nor a urlset") {
		t.Fatalf("Summary() = %q, want parse failure message", got)
	}
	detail := result.Detail()
	if !strings.Contains(detail, "FAIL document.parse: unsupported sitemap document format") {
		t.Fatalf("Detail() = %q, want parse failure rule", detail)
	}
	if !strings.Contains(detail, "CRITICAL xml_parse_failed: document is neither a sitemapindex nor a urlset") {
		t.Fatalf("Detail() = %q, want xml_parse_failed problem", detail)
	}
}

func TestRunWarnsOnUnexpectedContentType(t *testing.T) {
	serverURL := "https://probe.test"

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Entrypoint = serverURL + "/sitemap.xml"
	cfg.Verbosity = 1
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		res := stringResponse(req, http.StatusOK, fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><urlset><url><loc>%s/page</loc></url></urlset>`, serverURL))
		res.Header.Set("Content-Type", "text/html; charset=utf-8")
		return res, nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if got := result.ExitCode(); got != ExitWarning {
		t.Fatalf("ExitCode = %d, want %d", got, ExitWarning)
	}
	if got := result.Summary(); !strings.Contains(got, `unexpected content type "text/html" for urlset sitemap`) {
		t.Fatalf("Summary() = %q, want content type warning", got)
	}
	detail := result.Detail()
	if !strings.Contains(detail, `WARN document.content_type: unexpected content type "text/html" for urlset sitemap`) {
		t.Fatalf("Detail() = %q, want content type rule", detail)
	}
	if !strings.Contains(detail, `WARNING content_type_unexpected: unexpected content type "text/html" for urlset sitemap`) {
		t.Fatalf("Detail() = %q, want content type problem", detail)
	}
}

func TestRunFallbackStatusOKReturnsOK(t *testing.T) {
	serverURL := "https://probe.test"

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.FallbackStatus = string(FallbackOK)
	cfg.Verbosity = 1
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/robots.txt":
			return stringResponse(req, http.StatusOK, "User-agent: *\nDisallow:\n"), nil
		case "/sitemap.xml":
			return stringResponse(req, http.StatusOK, fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><urlset><url><loc>%s/page</loc></url></urlset>`, serverURL)), nil
		default:
			return stringResponse(req, http.StatusNotFound, "not found"), nil
		}
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitOK {
		t.Fatalf("ExitCode = %d, want %d", got, ExitOK)
	}
	if got := result.Summary(); !strings.Contains(got, "OK -") {
		t.Fatalf("Summary() = %q, want OK summary", got)
	}
	detail := result.Detail()
	if !strings.Contains(detail, "PASS fallback.discovery: resolved sitemap via common-path fallback") {
		t.Fatalf("Detail() = %q, want fallback pass rule", detail)
	}
}

func TestRunIgnoreErrorsSuppressesFallbackWarningRegardlessOfFallbackStatus(t *testing.T) {
	serverURL := "https://probe.test"

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.FallbackStatus = string(FallbackWarn)
	cfg.Verbosity = 1
	cfg.IgnoreErrors = []string{"fallback_used"}
	cfg.IgnoreErrorSet = map[string]bool{"fallback_used": true}
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/robots.txt":
			return stringResponse(req, http.StatusOK, "User-agent: *\nDisallow:\n"), nil
		case "/sitemap.xml":
			return stringResponse(req, http.StatusOK, fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><urlset><url><loc>%s/page</loc></url></urlset>`, serverURL)), nil
		default:
			return stringResponse(req, http.StatusNotFound, "not found"), nil
		}
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitOK {
		t.Fatalf("ExitCode = %d, want %d", got, ExitOK)
	}
	if got := len(result.IgnoredProblems); got != 1 {
		t.Fatalf("IgnoredProblems len = %d, want 1", got)
	}
	detail := result.Detail()
	if !strings.Contains(detail, "Ignored Problems:\n") || !strings.Contains(detail, "IGNORED fallback_used") {
		t.Fatalf("Detail() = %q, want ignored fallback problem section", detail)
	}
}

func TestRunStrictEscalatesChildScopeViolation(t *testing.T) {
	serverURL := "https://probe.test"
	childURL := "https://other.test/child.xml"

	for _, tc := range []struct {
		name         string
		strict       bool
		wantExitCode int
		wantRule     string
		wantProblem  string
	}{
		{
			name:         "practical",
			strict:       false,
			wantExitCode: ExitWarning,
			wantRule:     "WARN child.scope: child sitemap host \"other.test\" differs from parent host \"probe.test\"",
			wantProblem:  "WARNING child_scope_invalid: child sitemap host \"other.test\" differs from parent host \"probe.test\"",
		},
		{
			name:         "strict",
			strict:       true,
			wantExitCode: ExitCritical,
			wantRule:     "FAIL child.scope: child sitemap host \"other.test\" differs from parent host \"probe.test\"",
			wantProblem:  "CRITICAL child_scope_invalid: child sitemap host \"other.test\" differs from parent host \"probe.test\"",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.URL = serverURL
			cfg.Entrypoint = serverURL + "/sitemap.xml"
			cfg.Strict = tc.strict
			cfg.Verbosity = 1
			cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
				switch req.URL.Host {
				case "probe.test":
					switch req.URL.Path {
					case "/sitemap.xml":
						return stringResponse(req, http.StatusOK, fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><sitemapindex><sitemap><loc>%s</loc></sitemap></sitemapindex>`, childURL)), nil
					}
				case "other.test":
					switch req.URL.Path {
					case "/child.xml":
						return stringResponse(req, http.StatusOK, `<?xml version="1.0" encoding="UTF-8"?><urlset><url><loc>https://other.test/page</loc></url></urlset>`), nil
					}
				}
				return stringResponse(req, http.StatusNotFound, "not found"), nil
			})

			result, err := Run(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if got := result.ExitCode(); got != tc.wantExitCode {
				t.Fatalf("ExitCode = %d, want %d", got, tc.wantExitCode)
			}
			detail := result.Detail()
			if !strings.Contains(detail, tc.wantRule) {
				t.Fatalf("Detail() = %q, want rule %q", detail, tc.wantRule)
			}
			if !strings.Contains(detail, tc.wantProblem) {
				t.Fatalf("Detail() = %q, want problem %q", detail, tc.wantProblem)
			}
		})
	}
}

func TestRunAllowCrossHostPermitsChildFetchAcrossHosts(t *testing.T) {
	serverURL := "https://probe.test"
	childURL := "https://other.test/child.xml"

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Entrypoint = serverURL + "/sitemap.xml"
	cfg.AllowCrossHost = true
	cfg.Verbosity = 1
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Host {
		case "probe.test":
			switch req.URL.Path {
			case "/sitemap.xml":
				return stringResponse(req, http.StatusOK, fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><sitemapindex><sitemap><loc>%s</loc></sitemap></sitemapindex>`, childURL)), nil
			}
		case "other.test":
			switch req.URL.Path {
			case "/child.xml":
				return stringResponse(req, http.StatusOK, `<?xml version="1.0" encoding="UTF-8"?><urlset><url><loc>https://other.test/page</loc></url></urlset>`), nil
			}
		}
		return stringResponse(req, http.StatusNotFound, "not found"), nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitOK {
		t.Fatalf("ExitCode = %d, want %d", got, ExitOK)
	}
	if got := len(result.Documents); got != 2 {
		t.Fatalf("Documents len = %d, want 2", got)
	}
	detail := result.Detail()
	if strings.Contains(detail, "child_scope_invalid") {
		t.Fatalf("Detail() = %q, want no child_scope_invalid problem", detail)
	}
}

func TestRunReportsBadStatusInSummaryAndDetail(t *testing.T) {
	serverURL := "https://probe.test"

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Entrypoint = serverURL + "/sitemap.xml"
	cfg.Verbosity = 1
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return stringResponse(req, http.StatusBadRequest, "bad request"), nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if got := result.Summary(); !strings.Contains(got, "HTTP 400") {
		t.Fatalf("Summary() = %q, want HTTP 400", got)
	}
	detail := result.Detail()
	if !strings.Contains(detail, "FAIL document.status: HTTP 400") {
		t.Fatalf("Detail() = %q, want bad status rule", detail)
	}
	if !strings.Contains(detail, "CRITICAL bad_status: HTTP 400") {
		t.Fatalf("Detail() = %q, want bad_status problem", detail)
	}
}

func TestRunReportsTLSTransportFailureInSummaryAndDetail(t *testing.T) {
	serverURL := "https://probe.test"
	tlsErr := errors.New("tls: failed to verify certificate: x509: certificate signed by unknown authority")

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Entrypoint = serverURL + "/sitemap.xml"
	cfg.Verbosity = 2
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return nil, tlsErr
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if got := result.Summary(); !strings.Contains(got, tlsErr.Error()) {
		t.Fatalf("Summary() = %q, want TLS transport error", got)
	}
	detail := result.Detail()
	if !strings.Contains(detail, tlsErr.Error()) {
		t.Fatalf("Detail() = %q, want TLS transport error", detail)
	}
	if !strings.Contains(detail, "CRITICAL fetch_failed: Get") {
		t.Fatalf("Detail() = %q, want fetch_failed classification", detail)
	}
}

func TestRunReportsMissingLocInSummaryAndDetail(t *testing.T) {
	serverURL := "https://probe.test"

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Entrypoint = serverURL + "/sitemap.xml"
	cfg.Verbosity = 1
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		res := stringResponse(req, http.StatusOK, `<?xml version="1.0" encoding="UTF-8"?><urlset><url></url></urlset>`)
		res.Header.Set("Content-Type", "application/xml")
		return res, nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if got := result.Summary(); !strings.Contains(got, "url entry missing loc") {
		t.Fatalf("Summary() = %q, want missing loc message", got)
	}
	detail := result.Detail()
	if !strings.Contains(detail, "CRITICAL missing_loc: url entry missing loc") {
		t.Fatalf("Detail() = %q, want missing_loc problem", detail)
	}
}

func TestRunReportsInvalidURLValueInSummaryAndDetail(t *testing.T) {
	serverURL := "https://probe.test"

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Entrypoint = serverURL + "/sitemap.xml"
	cfg.Verbosity = 1
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		res := stringResponse(req, http.StatusOK, `<?xml version="1.0" encoding="UTF-8"?><urlset><url><loc>://bad-url</loc></url></urlset>`)
		res.Header.Set("Content-Type", "application/xml")
		return res, nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if got := result.Summary(); !strings.Contains(got, `parse "://bad-url": missing protocol scheme`) {
		t.Fatalf("Summary() = %q, want invalid URL message", got)
	}
	detail := result.Detail()
	if !strings.Contains(detail, `CRITICAL invalid_url: parse "://bad-url": missing protocol scheme`) {
		t.Fatalf("Detail() = %q, want invalid_url problem", detail)
	}
}

type mockRoundTripper func(*http.Request) (*http.Response, error)

func (m mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return m(req)
}

func newMockHTTPClient(fn mockRoundTripper) *http.Client {
	return &http.Client{
		Timeout:   2 * time.Second,
		Transport: fn,
	}
}

func stringResponse(req *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}
