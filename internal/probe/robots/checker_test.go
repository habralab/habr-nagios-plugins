package robots

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRunOKWithSitemapAndPolicies(t *testing.T) {
	cfg := DefaultConfig()
	cfg.URL = "https://probe.test"
	cfg.RequireSitemap = true
	cfg.RequireUserAgents = []string{"*", "Googlebot"}
	cfg.RequireDisallows = []string{"/admin"}
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		body := "User-agent: *\nDisallow: /admin\n\nUser-agent: Googlebot\nAllow: /\nSitemap: https://probe.test/sitemap.xml\n"
		res := stringResponse(req, http.StatusOK, body)
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
	if got, want := len(result.Groups), 2; got != want {
		t.Fatalf("Groups len = %d, want %d", got, want)
	}
	if got, want := len(result.Sitemaps), 1; got != want {
		t.Fatalf("Sitemaps len = %d, want %d", got, want)
	}
}

func TestRunFailsWhenRequiredSitemapMissing(t *testing.T) {
	cfg := DefaultConfig()
	cfg.URL = "https://probe.test"
	cfg.RequireSitemap = true
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return stringResponse(req, http.StatusOK, "User-agent: *\nDisallow: /tmp\n"), nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitCritical {
		t.Fatalf("ExitCode = %d, want %d", got, ExitCritical)
	}
	if got := result.Summary(); !strings.Contains(got, "required Sitemap directive not found") {
		t.Fatalf("Summary() = %q, want missing sitemap policy", got)
	}
}

func TestRunWarnsOnInvalidSitemapAndDirectiveSyntax(t *testing.T) {
	cfg := DefaultConfig()
	cfg.URL = "https://probe.test"
	cfg.Verbosity = 1
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return stringResponse(req, http.StatusOK, "User-agent: *\nSitemap: not-a-url\nBrokenLine\n"), nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitWarning {
		t.Fatalf("ExitCode = %d, want %d", got, ExitWarning)
	}
	if detail := result.Detail(); !strings.Contains(detail, "robots_invalid_sitemap") || !strings.Contains(detail, "robots_invalid_line") {
		t.Fatalf("Detail() = %q, want parse findings", detail)
	}
}

func TestRunAcceptsUTF8BOM(t *testing.T) {
	cfg := DefaultConfig()
	cfg.URL = "https://probe.test"
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		body := string([]byte{0xEF, 0xBB, 0xBF}) + "User-agent: *\nDisallow: /admin\n"
		return stringResponse(req, http.StatusOK, body), nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitOK {
		t.Fatalf("ExitCode = %d, want %d", got, ExitOK)
	}
}

func TestRunAcceptsKnownExtensionDirectiveByDefault(t *testing.T) {
	cfg := DefaultConfig()
	cfg.URL = "https://probe.test"
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return stringResponse(req, http.StatusOK, "User-agent: *\nCrawl-delay: 10\nDisallow: /tmp\n"), nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitOK {
		t.Fatalf("ExitCode = %d, want %d", got, ExitOK)
	}
	if detail := result.Detail(); !strings.Contains(detail, "extension=Crawl-delay") {
		t.Fatalf("Detail() = %q, want recognized extension output", detail)
	}
}

func TestRunRecognizesCleanParamAsVendorDirective(t *testing.T) {
	cfg := DefaultConfig()
	cfg.URL = "https://probe.test"
	cfg.Verbosity = 1
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return stringResponse(req, http.StatusOK, "User-agent: Yandex\nClean-param: ref /some_dir/get_book.pl\n"), nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitOK {
		t.Fatalf("ExitCode = %d, want %d", got, ExitOK)
	}
	detail := result.Detail()
	if !strings.Contains(detail, "extension=Clean-param") {
		t.Fatalf("Detail() = %q, want Clean-param extension output", detail)
	}
	if !strings.Contains(detail, "provenance=vendor-doc") {
		t.Fatalf("Detail() = %q, want vendor-doc provenance", detail)
	}
	if !strings.Contains(detail, "ref=Yandex Webmaster Clean-param directive") {
		t.Fatalf("Detail() = %q, want Yandex reference", detail)
	}
}

func TestRunWarnsOnInvalidCleanParamValue(t *testing.T) {
	cfg := DefaultConfig()
	cfg.URL = "https://probe.test"
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return stringResponse(req, http.StatusOK, "User-agent: Yandex\nClean-param: ref path-without-slash\n"), nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitWarning {
		t.Fatalf("ExitCode = %d, want %d", got, ExitWarning)
	}
	if detail := result.Detail(); !strings.Contains(detail, "robots_invalid_directive_value") {
		t.Fatalf("Detail() = %q, want invalid directive value warning", detail)
	}
}

func TestRunWarnsOnKnownExtensionDirectiveInStrictMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.URL = "https://probe.test"
	cfg.Strict = true
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return stringResponse(req, http.StatusOK, "User-agent: *\nCrawl-delay: 10\nDisallow: /tmp\n"), nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitWarning {
		t.Fatalf("ExitCode = %d, want %d", got, ExitWarning)
	}
	if detail := result.Detail(); !strings.Contains(detail, "robots_extension_directive") {
		t.Fatalf("Detail() = %q, want extension directive warning", detail)
	}
}

func TestRunWarnsOnInvalidPathPattern(t *testing.T) {
	cfg := DefaultConfig()
	cfg.URL = "https://probe.test"
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return stringResponse(req, http.StatusOK, "User-agent: *\nDisallow: admin/\n"), nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitWarning {
		t.Fatalf("ExitCode = %d, want %d", got, ExitWarning)
	}
	if detail := result.Detail(); !strings.Contains(detail, "robots_invalid_path") {
		t.Fatalf("Detail() = %q, want invalid path warning", detail)
	}
}

func TestRunFailsWhenForbiddenDisallowPresent(t *testing.T) {
	cfg := DefaultConfig()
	cfg.URL = "https://probe.test"
	cfg.ForbidDisallows = []string{"/"}
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return stringResponse(req, http.StatusOK, "User-agent: *\nDisallow: /\n"), nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitCritical {
		t.Fatalf("ExitCode = %d, want %d", got, ExitCritical)
	}
}

func TestRunWarnsOnUnexpectedContentType(t *testing.T) {
	cfg := DefaultConfig()
	cfg.URL = "https://probe.test"
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		res := stringResponse(req, http.StatusOK, "User-agent: *\nDisallow: /tmp\n")
		res.Header.Set("Content-Type", "text/html")
		return res, nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitWarning {
		t.Fatalf("ExitCode = %d, want %d", got, ExitWarning)
	}
}

func TestRunWarnsOnNonUTF8Payload(t *testing.T) {
	cfg := DefaultConfig()
	cfg.URL = "https://probe.test"
	cfg.Verbosity = 1
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		body := string([]byte{'U', 's', 'e', 'r', '-', 'a', 'g', 'e', 'n', 't', ':', ' ', '*', '\n', 0xff})
		return stringResponse(req, http.StatusOK, body), nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitWarning {
		t.Fatalf("ExitCode = %d, want %d", got, ExitWarning)
	}
	if detail := result.Detail(); !strings.Contains(detail, "encoding=non-utf8") {
		t.Fatalf("Detail() = %q, want non-utf8 encoding", detail)
	}
}

func TestRunVendorAwareDoesNotWarnForDedicatedYandexMobileBotGroup(t *testing.T) {
	cfg := DefaultConfig()
	cfg.URL = "https://probe.test"
	cfg.BehaviorProfile = BehaviorProfileVendorAware
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return stringResponse(req, http.StatusOK, "User-agent: YandexMobileBot\nDisallow: /private\n"), nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitOK {
		t.Fatalf("ExitCode = %d, want %d", got, ExitOK)
	}
	detail := result.Detail()
	if !strings.Contains(detail, "behavior_profile=vendor-aware") {
		t.Fatalf("Detail() = %q, want behavior profile trace", detail)
	}
	if strings.Contains(detail, "robots_agent_ignores_rules") {
		t.Fatalf("Detail() = %q, want no dedicated-group ignore warning", detail)
	}
}

func TestRunVendorAwareWarnsWhenAgentIgnoresRobotsRecords(t *testing.T) {
	cfg := DefaultConfig()
	cfg.URL = "https://probe.test"
	cfg.BehaviorProfile = BehaviorProfileVendorAware
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return stringResponse(req, http.StatusOK, "User-agent: Baiduspider-video\nDisallow: /private\n"), nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitWarning {
		t.Fatalf("ExitCode = %d, want %d", got, ExitWarning)
	}
	if detail := result.Detail(); !strings.Contains(detail, "robots_agent_ignores_rules") {
		t.Fatalf("Detail() = %q, want robots-records ignore warning", detail)
	}
}

func TestRunVendorAwareWarnsWhenAgentIgnoresDirective(t *testing.T) {
	cfg := DefaultConfig()
	cfg.URL = "https://probe.test"
	cfg.BehaviorProfile = BehaviorProfileVendorAware
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return stringResponse(req, http.StatusOK, "User-agent: MojeekBot\nCrawl-delay: 10\nDisallow: /private\n"), nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitWarning {
		t.Fatalf("ExitCode = %d, want %d", got, ExitWarning)
	}
	if detail := result.Detail(); !strings.Contains(detail, "robots_agent_ignores_directive") {
		t.Fatalf("Detail() = %q, want directive ignore warning", detail)
	}
}

func TestRunStrictWarnsWhenExtensionSupportIsUndocumented(t *testing.T) {
	cfg := DefaultConfig()
	cfg.URL = "https://probe.test"
	cfg.BehaviorProfile = BehaviorProfileStrict
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return stringResponse(req, http.StatusOK, "User-agent: DuckDuckBot\nCrawl-delay: 10\nDisallow: /private\n"), nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitWarning {
		t.Fatalf("ExitCode = %d, want %d", got, ExitWarning)
	}
	if detail := result.Detail(); !strings.Contains(detail, "robots_agent_directive_undocumented") {
		t.Fatalf("Detail() = %q, want undocumented extension warning", detail)
	}
}

func TestRunTreats4xxAsUnavailableWarning(t *testing.T) {
	cfg := DefaultConfig()
	cfg.URL = "https://probe.test"
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return stringResponse(req, http.StatusForbidden, "blocked"), nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitWarning {
		t.Fatalf("ExitCode = %d, want %d", got, ExitWarning)
	}
	if detail := result.Detail(); !strings.Contains(detail, "robots_unavailable_status") {
		t.Fatalf("Detail() = %q, want unavailable-status finding", detail)
	}
}

func TestRunTreats404AsOKAbsentFile(t *testing.T) {
	cfg := DefaultConfig()
	cfg.URL = "https://probe.test"
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return stringResponse(req, http.StatusNotFound, "not found"), nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitOK {
		t.Fatalf("ExitCode = %d, want %d", got, ExitOK)
	}
	if !result.Absent {
		t.Fatalf("Absent = false, want true")
	}
	if got := result.Summary(); !strings.Contains(got, "robots.txt not present (HTTP 404)") {
		t.Fatalf("Summary() = %q, want absent status", got)
	}
}

func TestRunTreats429AsUnavailableWarning(t *testing.T) {
	cfg := DefaultConfig()
	cfg.URL = "https://probe.test"
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return stringResponse(req, http.StatusTooManyRequests, "slow down"), nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitWarning {
		t.Fatalf("ExitCode = %d, want %d", got, ExitWarning)
	}
}

func TestRunReportsRedirectLimitExceeded(t *testing.T) {
	cfg := DefaultConfig()
	cfg.URL = "https://probe.test"
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		rawHop := req.URL.Query().Get("n")
		switch rawHop {
		case "":
			res := stringResponse(req, http.StatusMovedPermanently, "")
			res.Header.Set("Location", "https://probe.test/robots.txt?n=1")
			return res, nil
		case "1", "2", "3", "4", "5":
			hop, _ := strconv.Atoi(rawHop)
			res := stringResponse(req, http.StatusMovedPermanently, "")
			res.Header.Set("Location", fmt.Sprintf("https://probe.test/robots.txt?n=%d", hop+1))
			return res, nil
		default:
			return stringResponse(req, http.StatusOK, "User-agent: *\nDisallow:\n"), nil
		}
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitWarning {
		t.Fatalf("ExitCode = %d, want %d", got, ExitWarning)
	}
	if detail := result.Detail(); !strings.Contains(detail, "robots_redirect_limit_exceeded") {
		t.Fatalf("Detail() = %q, want redirect limit finding", detail)
	}
}

func TestRunWarnsWhenNoUserAgentGroupsExist(t *testing.T) {
	cfg := DefaultConfig()
	cfg.URL = "https://probe.test"
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return stringResponse(req, http.StatusOK, "Sitemap: https://probe.test/sitemap.xml\n"), nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitWarning {
		t.Fatalf("ExitCode = %d, want %d", got, ExitWarning)
	}
	if detail := result.Detail(); !strings.Contains(detail, "robots_no_groups") {
		t.Fatalf("Detail() = %q, want no-groups finding", detail)
	}
}

func TestRunRecognizesContentSignalDirective(t *testing.T) {
	cfg := DefaultConfig()
	cfg.URL = "https://probe.test"
	cfg.Verbosity = 1
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return stringResponse(req, http.StatusOK, "User-agent: *\nContent-Signal: ai-train=yes, search=yes\nDisallow: /tmp\n"), nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitOK {
		t.Fatalf("ExitCode = %d, want %d", got, ExitOK)
	}
	if detail := result.Detail(); !strings.Contains(detail, "extension=Content-Signal") {
		t.Fatalf("Detail() = %q, want Content-Signal extension output", detail)
	}
}

func TestRunAcceptsCleanParamWithLeadingAmpersands(t *testing.T) {
	cfg := DefaultConfig()
	cfg.URL = "https://probe.test"
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return stringResponse(req, http.StatusOK, "User-agent: Yandex\nClean-param: &appsearch_header=1&comments=1 /news/story/\n"), nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitOK {
		t.Fatalf("ExitCode = %d, want %d", got, ExitOK)
	}
	if detail := result.Detail(); strings.Contains(detail, "robots_invalid_directive_value") {
		t.Fatalf("Detail() = %q, want no invalid Clean-param warning", detail)
	}
}

func TestRunReturnsUnknownOnDNSFailure(t *testing.T) {
	cfg := DefaultConfig()
	cfg.URL = "https://probe.test"
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return nil, &neturl.Error{
			Op:  "Get",
			URL: req.URL.String(),
			Err: &net.DNSError{Err: "no such host", Name: req.URL.Hostname()},
		}
	})

	_, err := Run(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "DNS resolution failed") {
		t.Fatalf("Run() error = %v, want DNS resolution failure", err)
	}
}

func TestRunWarnsWhenSizeIsNearLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.URL = "https://probe.test"
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		body := "User-agent: *\nDisallow: /\n#" + strings.Repeat("x", warnRobotsBodyBytes)
		return stringResponse(req, http.StatusOK, body), nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitWarning {
		t.Fatalf("ExitCode = %d, want %d", got, ExitWarning)
	}
	if detail := result.Detail(); !strings.Contains(detail, "robots_size_near_limit") {
		t.Fatalf("Detail() = %q, want near-limit finding", detail)
	}
}

func TestRunRecognizesKnownAIAgent(t *testing.T) {
	cfg := DefaultConfig()
	cfg.URL = "https://probe.test"
	cfg.Verbosity = 1
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		return stringResponse(req, http.StatusOK, "User-agent: GPTBot\nDisallow: /\n"), nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitOK {
		t.Fatalf("ExitCode = %d, want %d", got, ExitOK)
	}
	if detail := result.Detail(); !strings.Contains(detail, "known_agent=GPTBot") {
		t.Fatalf("Detail() = %q, want recognized AI agent", detail)
	}
}

func TestRunFailsWhenBodyExceedsRFCSizeLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.URL = "https://probe.test"
	cfg.HTTPClient = newMockHTTPClient(func(req *http.Request) (*http.Response, error) {
		body := "User-agent: *\nDisallow: /\n" + string(bytes.Repeat([]byte("x"), maxRobotsBodyBytes+8))
		return stringResponse(req, http.StatusOK, body), nil
	})

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := result.ExitCode(); got != ExitCritical {
		t.Fatalf("ExitCode = %d, want %d", got, ExitCritical)
	}
	if detail := result.Detail(); !strings.Contains(detail, "robots_too_large") {
		t.Fatalf("Detail() = %q, want too-large finding", detail)
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
