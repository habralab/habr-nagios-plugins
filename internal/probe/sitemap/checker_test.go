package sitemap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
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

func TestReportViewDoesNotDependOnVerbosityForIgnoredProblems(t *testing.T) {
	startedAt := time.Date(2026, time.June, 14, 12, 0, 0, 0, time.UTC)
	base := Result{
		Config: Config{
			OutputMode: checkreport.OutputJSON,
		},
		StartedAt:        startedAt,
		TargetSource:     "hostname",
		EffectiveBaseURL: "https://example.com/",
		DiscoveredVia:    "robots",
		Entrypoints:      []string{"https://example.com/sitemap.xml"},
		IgnoredProblems: []Problem{{
			Severity: SeverityWarning,
			Code:     "fallback_used",
			Message:  "sitemap discovered via fallback probing, robots.txt has no Sitemap directive",
			URL:      "https://example.com/sitemap.xml",
		}},
	}

	withLowVerbosity := base
	withLowVerbosity.Config.Verbosity = 0
	withHighVerbosity := base
	withHighVerbosity.Config.Verbosity = 3

	lowJSON, err := withLowVerbosity.reportView().JSON()
	if err != nil {
		t.Fatalf("low verbosity JSON() error = %v", err)
	}
	highJSON, err := withHighVerbosity.reportView().JSON()
	if err != nil {
		t.Fatalf("high verbosity JSON() error = %v", err)
	}

	if !bytes.Equal(lowJSON, highJSON) {
		t.Fatalf("report JSON changed with verbosity\nlow=%s\nhigh=%s", lowJSON, highJSON)
	}

	var report checkreport.Report
	if err := json.Unmarshal(lowJSON, &report); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	validation := checkreport.StageByID(&report, "validation")
	if validation == nil {
		t.Fatalf("validation stage missing")
	}
	var foundIgnored bool
	for _, check := range validation.Checks {
		if check.ID == "problem.fallback_used" && check.State == checkreport.CheckIgnore {
			foundIgnored = true
			break
		}
	}
	if !foundIgnored {
		t.Fatalf("validation stage checks = %#v, want ignored problem check", validation.Checks)
	}
	if report.StartedAt != startedAt {
		t.Fatalf("report.StartedAt = %v, want %v", report.StartedAt, startedAt)
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

func TestRunDoesNotAcceptHTMLFallbackAsSitemap(t *testing.T) {
	serverURL := "https://probe.test"

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Timeout = 2 * time.Second
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/robots.txt":
			return stringResponse(req, http.StatusOK, "User-agent: *\nDisallow:\n"), nil
		case "/sitemap.xml":
			res := stringResponse(req, http.StatusOK, "<!DOCTYPE html><html><title>challenge</title></html>")
			res.Header.Set("Content-Type", "text/html")
			return res, nil
		default:
			return stringResponse(req, http.StatusNotFound, "not found"), nil
		}
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got, want := result.DiscoveredVia, "fallback"; got != want {
		t.Fatalf("DiscoveredVia = %q, want %q", got, want)
	}
	if got := len(result.Entrypoints); got != 0 {
		t.Fatalf("Entrypoints len = %d, want 0", got)
	}
	if got := result.ExitCode(); got != ExitCritical {
		t.Fatalf("ExitCode = %d, want %d", got, ExitCritical)
	}
	if got := result.Summary(); !strings.Contains(got, "no sitemap entrypoint discovered") {
		t.Fatalf("Summary() = %q, want entrypoint_not_found", got)
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

func TestRunRecordsHTTPRedirectChainTrace(t *testing.T) {
	serverURL := "http://career.habr.test"

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Timeout = 2 * time.Second
	cfg.Verbosity = 3
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/robots.txt":
			res := stringResponse(req, http.StatusMovedPermanently, "")
			res.Header.Set("Location", serverURL+"/robots-mid.txt")
			return res, nil
		case "/robots-mid.txt":
			res := stringResponse(req, http.StatusFound, "")
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

	var redirects int
	var sawFirstHop bool
	var sawSecondHop bool
	for _, call := range result.HTTPTrace {
		if call.Note != "redirect" {
			continue
		}
		redirects++
		if strings.Contains(call.URL, "/robots.txt") && strings.Contains(call.FinalURL, "/robots-mid.txt") {
			sawFirstHop = true
		}
		if strings.Contains(call.URL, "/robots-mid.txt") && strings.Contains(call.FinalURL, "/robots-final.txt") {
			sawSecondHop = true
		}
	}
	if redirects < 2 || !sawFirstHop || !sawSecondHop {
		t.Fatalf("HTTPTrace = %+v, want both redirect hops", result.HTTPTrace)
	}
	if got := result.Detail(); !strings.Contains(got, "robots discovery redirected to "+serverURL+"/robots-final.txt") {
		t.Fatalf("Detail() = %q, want final robots redirect narrative", got)
	}
}

func TestRunFallbackFollowsRedirectChain(t *testing.T) {
	serverURL := "https://probe.test"

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Timeout = 2 * time.Second
	cfg.Verbosity = 3
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/robots.txt":
			return stringResponse(req, http.StatusOK, "User-agent: *\nDisallow:\n"), nil
		case "/sitemap.xml":
			res := stringResponse(req, http.StatusMovedPermanently, "")
			res.Header.Set("Location", serverURL+"/sitemaps/mid.xml")
			return res, nil
		case "/sitemaps/mid.xml":
			res := stringResponse(req, http.StatusFound, "")
			res.Header.Set("Location", serverURL+"/sitemaps/final.xml")
			return res, nil
		case "/sitemaps/final.xml":
			return stringResponse(req, http.StatusOK, fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><urlset><url><loc>%s/page</loc></url></urlset>`, serverURL)), nil
		default:
			return stringResponse(req, http.StatusNotFound, "not found"), nil
		}
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got, want := result.DiscoveredVia, "fallback"; got != want {
		t.Fatalf("DiscoveredVia = %q, want %q", got, want)
	}
	if got := result.Entrypoints[0]; got != serverURL+"/sitemaps/final.xml" {
		t.Fatalf("Entrypoint = %q, want final redirect target", got)
	}
	detail := result.Detail()
	if !strings.Contains(detail, "trying fallback probe via "+serverURL+"/sitemap.xml") {
		t.Fatalf("Detail() = %q, want fallback try trace", detail)
	}
	if !strings.Contains(detail, "fallback probe redirected to "+serverURL+"/sitemaps/final.xml") {
		t.Fatalf("Detail() = %q, want fallback redirect narrative", detail)
	}
	if !strings.Contains(detail, "PASS fallback.redirect: redirected to "+serverURL+"/sitemaps/final.xml ["+serverURL+"/sitemap.xml]") {
		t.Fatalf("Detail() = %q, want fallback redirect rule", detail)
	}
}

func TestRunReportsCheckTimeoutInSummaryAndDetail(t *testing.T) {
	serverURL := "https://probe.test"

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Entrypoint = serverURL + "/sitemap.xml"
	cfg.Timeout = 5 * time.Millisecond
	cfg.Verbosity = 2
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	})

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	result, err := Run(ctx, cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if got := result.Summary(); !strings.Contains(got, "check timeout after 5ms while fetching sitemap document") {
		t.Fatalf("Summary() = %q, want check timeout message", got)
	}
	if got := result.Summary(); strings.Contains(got, "sitemap_files=") || strings.Contains(got, "urls=") || strings.Contains(got, "depth=") {
		t.Fatalf("Summary() = %q, want no final sitemap stats for partial timeout result", got)
	}
	if got := result.Summary(); !strings.Contains(got, "partial=1") {
		t.Fatalf("Summary() = %q, want partial marker", got)
	}
	detail := result.Detail()
	if !strings.Contains(detail, "FAIL check.timeout: check timeout after 5ms while fetching sitemap document") {
		t.Fatalf("Detail() = %q, want check timeout rule", detail)
	}
	if !strings.Contains(detail, "CRITICAL check_timeout: check timeout after 5ms while fetching sitemap document") {
		t.Fatalf("Detail() = %q, want check_timeout problem", detail)
	}
	if !strings.Contains(detail, "check timeout: Get") {
		t.Fatalf("Detail() = %q, want explicit check-timeout HTTP trace note", detail)
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
	cfg.Verbosity = 2
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
	cfg.Verbosity = 2
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
	if got := result.Summary(); !strings.Contains(got, "sitemap_files=1") || !strings.Contains(got, "urls=1") || !strings.Contains(got, "depth=0") {
		t.Fatalf("Summary() = %q, want trusted sitemap stats for complete warning result", got)
	}
	if got := result.Summary(); !strings.Contains(got, "bytes_net=") || !strings.Contains(got, "bytes_raw=") {
		t.Fatalf("Summary() = %q, want byte counters", got)
	}
	detail := result.Detail()
	if !strings.Contains(detail, `WARN document.content_type: unexpected content type "text/html" for urlset sitemap`) {
		t.Fatalf("Detail() = %q, want content type rule", detail)
	}
	if !strings.Contains(detail, `WARNING content_type_unexpected: unexpected content type "text/html" for urlset sitemap`) {
		t.Fatalf("Detail() = %q, want content type problem", detail)
	}
	if !strings.Contains(detail, "net_bytes=") || !strings.Contains(detail, "raw_bytes=") {
		t.Fatalf("Detail() = %q, want HTTP byte counters", detail)
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
			wantRule:     "WARN child.scope: child sitemap host could not be verified for cross-submit via https://other.test/robots.txt: robots.txt returned HTTP 404",
			wantProblem:  "WARNING child_scope_invalid: child sitemap host could not be verified for cross-submit via https://other.test/robots.txt: robots.txt returned HTTP 404",
		},
		{
			name:         "strict",
			strict:       true,
			wantExitCode: ExitCritical,
			wantRule:     "FAIL child.scope: child sitemap host could not be verified for cross-submit via https://other.test/robots.txt: robots.txt returned HTTP 404",
			wantProblem:  "CRITICAL child_scope_invalid: child sitemap host could not be verified for cross-submit via https://other.test/robots.txt: robots.txt returned HTTP 404",
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

func TestRunAcceptsCrossSubmitDelegationForEntryURLsAndCachesRobotsFetch(t *testing.T) {
	serverURL := "https://probe.test"
	robotsFetches := 0

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Entrypoint = serverURL + "/sitemap.xml"
	cfg.Verbosity = 2
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Host {
		case "probe.test":
			switch req.URL.Path {
			case "/sitemap.xml":
				return stringResponse(req, http.StatusOK, `<?xml version="1.0" encoding="UTF-8"?><urlset><url><loc>https://other.test/page-1</loc></url><url><loc>https://other.test/page-2</loc></url></urlset>`), nil
			}
		case "other.test":
			switch req.URL.Path {
			case "/robots.txt":
				robotsFetches++
				return stringResponse(req, http.StatusOK, "User-agent: *\nSitemap: https://probe.test/sitemap.xml\n"), nil
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
	if robotsFetches != 1 {
		t.Fatalf("robots.txt fetches = %d, want 1", robotsFetches)
	}
	detail := result.Detail()
	if strings.Contains(detail, "url_scope_invalid") {
		t.Fatalf("Detail() = %q, want no url_scope_invalid problem", detail)
	}
	if !strings.Contains(detail, "PASS cross_submit.verify: host verified via https://other.test/robots.txt referencing https://probe.test/sitemap.xml [https://other.test/page-1]") {
		t.Fatalf("Detail() = %q, want explicit cross-submit verification rule", detail)
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

func TestRunReportsTraversalLimitAsUnknown(t *testing.T) {
	serverURL := "https://probe.test"

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Entrypoint = serverURL + "/sitemap.xml"
	cfg.MaxFiles = 1
	cfg.Verbosity = 1
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Host {
		case "probe.test":
			switch req.URL.Path {
			case "/sitemap.xml":
				return stringResponse(req, http.StatusOK, `<?xml version="1.0" encoding="UTF-8"?><sitemapindex><sitemap><loc>https://probe.test/child-1.xml</loc></sitemap><sitemap><loc>https://probe.test/child-2.xml</loc></sitemap></sitemapindex>`), nil
			case "/child-1.xml":
				return stringResponse(req, http.StatusOK, `<?xml version="1.0" encoding="UTF-8"?><urlset><url><loc>https://probe.test/page-1</loc></url></urlset>`), nil
			case "/child-2.xml":
				return stringResponse(req, http.StatusOK, `<?xml version="1.0" encoding="UTF-8"?><urlset><url><loc>https://probe.test/page-2</loc></url></urlset>`), nil
			}
		}
		return stringResponse(req, http.StatusNotFound, "not found"), nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitUnknown {
		t.Fatalf("ExitCode = %d, want %d", got, ExitUnknown)
	}
	if got := result.Summary(); !strings.HasPrefix(got, "UNKNOWN - reached max sitemap files limit 1") {
		t.Fatalf("Summary() = %q, want UNKNOWN traversal-limit summary", got)
	}
	if got := result.Summary(); !strings.Contains(got, "partial=1") {
		t.Fatalf("Summary() = %q, want partial marker", got)
	}
}

func TestRunWarnsOnCycleDetected(t *testing.T) {
	serverURL := "https://probe.test"

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Entrypoint = serverURL + "/root.xml"
	cfg.Verbosity = 1
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/root.xml":
			return stringResponse(req, http.StatusOK, `<?xml version="1.0" encoding="UTF-8"?><sitemapindex><sitemap><loc>https://probe.test/child.xml</loc></sitemap></sitemapindex>`), nil
		case "/child.xml":
			return stringResponse(req, http.StatusOK, `<?xml version="1.0" encoding="UTF-8"?><sitemapindex><sitemap><loc>https://probe.test/root.xml</loc></sitemap></sitemapindex>`), nil
		}
		return stringResponse(req, http.StatusNotFound, "not found"), nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitWarning {
		t.Fatalf("ExitCode = %d, want %d", got, ExitWarning)
	}
	detail := result.Detail()
	if !strings.Contains(detail, "WARN tree.cycle: cyclic sitemap reference detected") {
		t.Fatalf("Detail() = %q, want cycle rule", detail)
	}
	if !strings.Contains(detail, "WARNING cycle_detected: child sitemap \"https://probe.test/root.xml\" points back into the current sitemap chain") {
		t.Fatalf("Detail() = %q, want cycle problem", detail)
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

func TestRunParsesTextSitemap(t *testing.T) {
	serverURL := "https://probe.test"

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Entrypoint = serverURL + "/catalog/sitemap.txt"
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		res := stringResponse(req, http.StatusOK, "https://probe.test/catalog/page-1\nhttps://probe.test/catalog/page-2\n")
		res.Header.Set("Content-Type", "text/plain; charset=utf-8")
		return res, nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitOK {
		t.Fatalf("ExitCode = %d, want %d", got, ExitOK)
	}
	if got := len(result.Documents); got != 1 {
		t.Fatalf("Documents len = %d, want 1", got)
	}
	if got := result.Documents[0].Kind; got != "text" {
		t.Fatalf("Document kind = %q, want text", got)
	}
	if got := result.TotalURLs; got != 2 {
		t.Fatalf("TotalURLs = %d, want 2", got)
	}
}

func TestRunReportsEmptyTextSitemap(t *testing.T) {
	serverURL := "https://probe.test"

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Entrypoint = serverURL + "/sitemap.txt"
	cfg.Verbosity = 1
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		res := stringResponse(req, http.StatusOK, "\n \n")
		res.Header.Set("Content-Type", "text/plain")
		return res, nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.Summary(); !strings.Contains(got, "text sitemap contains no URLs") {
		t.Fatalf("Summary() = %q, want empty text sitemap message", got)
	}
	if detail := result.Detail(); !strings.Contains(detail, "WARNING empty_text_sitemap: text sitemap contains no URLs") {
		t.Fatalf("Detail() = %q, want empty_text_sitemap problem", detail)
	}
}

func TestRunReportsTextSitemapScopeViolation(t *testing.T) {
	serverURL := "https://probe.test"

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Entrypoint = serverURL + "/catalog/sitemap.txt"
	cfg.Verbosity = 1
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		res := stringResponse(req, http.StatusOK, "https://probe.test/outside/page-1\n")
		res.Header.Set("Content-Type", "text/plain")
		return res, nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.Summary(); !strings.Contains(got, "violates sitemap path scope") {
		t.Fatalf("Summary() = %q, want url scope violation", got)
	}
	detail := result.Detail()
	if !strings.Contains(detail, "WARN url.scope: entry URL path \"/outside/page-1\" violates sitemap path scope \"/catalog/\"") {
		t.Fatalf("Detail() = %q, want url.scope rule", detail)
	}
	if !strings.Contains(detail, "WARNING url_scope_invalid: entry URL path \"/outside/page-1\" violates sitemap path scope \"/catalog/\"") {
		t.Fatalf("Detail() = %q, want url_scope_invalid problem", detail)
	}
}

func TestRunAcceptsTextSitemapURLOnSameHostAndPort(t *testing.T) {
	serverURL := "https://probe.test:8443"

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Entrypoint = serverURL + "/catalog/sitemap.txt"
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		res := stringResponse(req, http.StatusOK, "https://probe.test:8443/catalog/page-1\n")
		res.Header.Set("Content-Type", "text/plain; charset=utf-8")
		return res, nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitOK {
		t.Fatalf("ExitCode = %d, want %d", got, ExitOK)
	}
}

func TestRunReportsTextSitemapPortScopeViolation(t *testing.T) {
	serverURL := "https://probe.test:8443"

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Entrypoint = serverURL + "/catalog/sitemap.txt"
	cfg.Verbosity = 1
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		res := stringResponse(req, http.StatusOK, "https://probe.test/catalog/page-1\n")
		res.Header.Set("Content-Type", "text/plain; charset=utf-8")
		return res, nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.Summary(); !strings.Contains(got, `is not delegated via https://probe.test/robots.txt to the current sitemap tree`) {
		t.Fatalf("Summary() = %q, want cross-submit failure for different port authority", got)
	}
	detail := result.Detail()
	if !strings.Contains(detail, `WARN url.scope: entry URL host is not delegated via https://probe.test/robots.txt to the current sitemap tree`) {
		t.Fatalf("Detail() = %q, want url.scope cross-submit rule", detail)
	}
}

func TestRunWarnsOnNonUTF8TextSitemap(t *testing.T) {
	serverURL := "https://probe.test"

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Entrypoint = serverURL + "/sitemap.txt"
	cfg.Verbosity = 1
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		body := []byte{
			'h', 't', 't', 'p', 's', ':', '/', '/', 'p', 'r', 'o', 'b', 'e', '.', 't', 'e', 's', 't', '/',
			0xff, 'p', 'a', 'g', 'e', '\n',
		}
		res := &http.Response{
			StatusCode: http.StatusOK,
			Status:     fmt.Sprintf("%d %s", http.StatusOK, http.StatusText(http.StatusOK)),
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader(body)),
			Request:    req,
		}
		res.Header.Set("Content-Type", "text/plain")
		return res, nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.Summary(); !strings.Contains(got, "text sitemap is not valid UTF-8") {
		t.Fatalf("Summary() = %q, want non-UTF8 text warning", got)
	}
	if detail := result.Detail(); !strings.Contains(detail, "WARNING non_utf8_encoding: text sitemap is not valid UTF-8") {
		t.Fatalf("Detail() = %q, want non_utf8_encoding problem", detail)
	}
}

func TestRunWarnsOnUnescapedTextSitemapURL(t *testing.T) {
	serverURL := "https://probe.test"

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Entrypoint = serverURL + "/sitemap.txt"
	cfg.Verbosity = 1
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		res := stringResponse(req, http.StatusOK, "https://probe.test/ümlat\n")
		res.Header.Set("Content-Type", "text/plain; charset=utf-8")
		return res, nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitWarning {
		t.Fatalf("ExitCode = %d, want %d", got, ExitWarning)
	}
	if got := result.Summary(); !strings.Contains(got, "should be percent-encoded") {
		t.Fatalf("Summary() = %q, want escaped URL warning", got)
	}
	detail := result.Detail()
	if !strings.Contains(detail, "WARNING url_not_escaped: URL contains non-ASCII character 'ü' and should be percent-encoded") {
		t.Fatalf("Detail() = %q, want url_not_escaped problem", detail)
	}
}

func TestRunAcceptsValidHreflangExtension(t *testing.T) {
	serverURL := "https://probe.test"

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Entrypoint = serverURL + "/sitemap.xml"
	cfg.Verbosity = 1
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		res := stringResponse(req, http.StatusOK, `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">
  <url>
    <loc>https://probe.test/page</loc>
    <xhtml:link rel="alternate" hreflang="en" href="https://probe.test/page"/>
    <xhtml:link rel="alternate" hreflang="de" href="https://probe.test/de/page"/>
  </url>
</urlset>`)
		res.Header.Set("Content-Type", "application/xml")
		return res, nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitOK {
		t.Fatalf("ExitCode = %d, want %d", got, ExitOK)
	}
	if detail := result.Detail(); !strings.Contains(detail, "PASS extension.xhtml_hreflang: namespace=http://www.w3.org/1999/xhtml entries=2 issues=0") {
		t.Fatalf("Detail() = %q, want passing hreflang extension rule", detail)
	}
}

func TestRunReportsBrokenHreflangExtension(t *testing.T) {
	serverURL := "https://probe.test"

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Entrypoint = serverURL + "/sitemap.xml"
	cfg.Verbosity = 1
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		res := stringResponse(req, http.StatusOK, `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">
  <url>
    <loc>https://probe.test/page</loc>
    <xhtml:link rel="alternate" hreflang="de" href="https://probe.test/de/page"/>
    <xhtml:link rel="alternate" hreflang="de" href="https://probe.test/de-2/page"/>
  </url>
</urlset>`)
		res.Header.Set("Content-Type", "application/xml")
		return res, nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitWarning {
		t.Fatalf("ExitCode = %d, want %d", got, ExitWarning)
	}
	detail := result.Detail()
	if !strings.Contains(detail, "WARN extension.xhtml_hreflang: namespace=http://www.w3.org/1999/xhtml entries=2 issues=2") {
		t.Fatalf("Detail() = %q, want failing hreflang extension rule", detail)
	}
	if !strings.Contains(detail, "WARNING extension_hreflang_invalid: xhtml hreflang set does not include a self-referencing href") {
		t.Fatalf("Detail() = %q, want hreflang self-link problem", detail)
	}
}

func TestRunAcceptsValidImageExtension(t *testing.T) {
	serverURL := "https://probe.test"

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Entrypoint = serverURL + "/sitemap.xml"
	cfg.Verbosity = 1
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		res := stringResponse(req, http.StatusOK, `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">
  <url>
    <loc>https://probe.test/page</loc>
    <image:image>
      <image:loc>https://probe.test/image.jpg</image:loc>
    </image:image>
  </url>
</urlset>`)
		res.Header.Set("Content-Type", "application/xml")
		return res, nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitOK {
		t.Fatalf("ExitCode = %d, want %d", got, ExitOK)
	}
	if detail := result.Detail(); !strings.Contains(detail, "PASS extension.image: namespace=http://www.google.com/schemas/sitemap-image/1.1 entries=1 issues=0") {
		t.Fatalf("Detail() = %q, want passing image extension rule", detail)
	}
}

func TestRunReportsInvalidImageExtension(t *testing.T) {
	serverURL := "https://probe.test"

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Entrypoint = serverURL + "/sitemap.xml"
	cfg.Verbosity = 1
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		res := stringResponse(req, http.StatusOK, `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">
  <url>
    <loc>https://probe.test/page</loc>
    <image:image>
      <image:caption>missing loc</image:caption>
    </image:image>
  </url>
</urlset>`)
		res.Header.Set("Content-Type", "application/xml")
		return res, nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitWarning {
		t.Fatalf("ExitCode = %d, want %d", got, ExitWarning)
	}
	if detail := result.Detail(); !strings.Contains(detail, "WARNING extension_image_invalid: image extension entry missing image:loc") {
		t.Fatalf("Detail() = %q, want image:loc missing problem", detail)
	}
}

func TestRunAcceptsValidNewsExtension(t *testing.T) {
	serverURL := "https://probe.test"

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Entrypoint = serverURL + "/sitemap.xml"
	cfg.Verbosity = 1
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		res := stringResponse(req, http.StatusOK, `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:news="http://www.google.com/schemas/sitemap-news/0.9">
  <url>
    <loc>https://probe.test/news/page</loc>
    <news:news>
      <news:publication>
        <news:name>The Example Times</news:name>
        <news:language>en</news:language>
      </news:publication>
      <news:publication_date>2026-06-13T12:00:00Z</news:publication_date>
      <news:title>Sitemap Extensions Are Great</news:title>
    </news:news>
  </url>
</urlset>`)
		res.Header.Set("Content-Type", "application/xml")
		return res, nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitOK {
		t.Fatalf("ExitCode = %d, want %d", got, ExitOK)
	}
	if detail := result.Detail(); !strings.Contains(detail, "PASS extension.news: namespace=http://www.google.com/schemas/sitemap-news/0.9 entries=1 issues=0") {
		t.Fatalf("Detail() = %q, want passing news extension rule", detail)
	}
}

func TestRunAcceptsValidVideoExtension(t *testing.T) {
	serverURL := "https://probe.test"

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Entrypoint = serverURL + "/sitemap.xml"
	cfg.Verbosity = 1
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		res := stringResponse(req, http.StatusOK, `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:video="http://www.google.com/schemas/sitemap-video/1.1">
  <url>
    <loc>https://probe.test/video/page</loc>
    <video:video>
      <video:thumbnail_loc>https://probe.test/thumb.jpg</video:thumbnail_loc>
      <video:title>Tutorial</video:title>
      <video:description>Description</video:description>
      <video:content_loc>https://probe.test/video.mp4</video:content_loc>
    </video:video>
  </url>
</urlset>`)
		res.Header.Set("Content-Type", "application/xml")
		return res, nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitOK {
		t.Fatalf("ExitCode = %d, want %d", got, ExitOK)
	}
	if detail := result.Detail(); !strings.Contains(detail, "PASS extension.video: namespace=http://www.google.com/schemas/sitemap-video/1.1 entries=1 issues=0") {
		t.Fatalf("Detail() = %q, want passing video extension rule", detail)
	}
}

func TestRunParsesWindows1251Sitemap(t *testing.T) {
	serverURL := "https://probe.test"

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Entrypoint = serverURL + "/sitemap.xml"
	cfg.Verbosity = 1
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		// "тест" in windows-1251 is \xf2\xe5\xf1\xf2
		body := `<?xml version="1.0" encoding="windows-1251"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://probe.test/` + "\xf2\xe5\xf1\xf2" + `</loc>
  </url>
</urlset>`
		res := stringResponse(req, http.StatusOK, body)
		res.Header.Set("Content-Type", "application/xml; charset=windows-1251")
		return res, nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitWarning {
		t.Fatalf("ExitCode = %d, want %d (Warning for non-UTF8)", got, ExitWarning)
	}
	if got := result.Summary(); !strings.Contains(got, "non-UTF-8 sitemap encoding \"windows-1251\"") {
		t.Fatalf("Summary() = %q, want non-UTF8 warning", got)
	}
	if got := result.TotalURLs; got != 1 {
		t.Fatalf("TotalURLs = %d, want 1", got)
	}
	if detail := result.Detail(); !strings.Contains(detail, "encoding=windows-1251") {
		t.Fatalf("Detail() = %q, want encoding=windows-1251 in output", detail)
	}
}

func TestRunFollowsHostRedirect(t *testing.T) {
	serverURL := "https://entry.test"
	finalURL := "https://final.test"

	cfg := DefaultConfig()
	cfg.URL = serverURL
	cfg.Entrypoint = serverURL + "/sitemap.xml"
	cfg.Verbosity = 1
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() == serverURL+"/sitemap.xml" {
			// Redirect to another host
			res := &http.Response{
				StatusCode: http.StatusMovedPermanently,
				Header:     make(http.Header),
				Request:    req,
			}
			res.Header.Set("Location", finalURL+"/sitemap.xml")
			return res, nil
		}
		if req.URL.String() == finalURL+"/sitemap.xml" {
			// Serve sitemap from the final host with URLs pointing to the final host
			body := `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://final.test/page1</loc></url>
</urlset>`
			res := stringResponse(req, http.StatusOK, body)
			res.Header.Set("Content-Type", "application/xml")
			return res, nil
		}
		return nil, fmt.Errorf("unexpected request: %s", req.URL)
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	// Should be OK because we followed the host redirect
	if got := result.ExitCode(); got != ExitOK {
		t.Fatalf("ExitCode = %d, want %d (should follow redirect host scope)", got, ExitOK)
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
