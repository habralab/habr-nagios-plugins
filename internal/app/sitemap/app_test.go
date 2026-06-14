package sitemapapp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/probe/sitemap"
)

const testProgramName = "check_sitemap"

func TestParseFlagsCoversCommonOptions(t *testing.T) {
	cfg, err := parseFlags(testProgramName, []string{
		"-H", "example.com",
		"--strict",
		"--allow-cross-host",
		"--fallback-status", "ok",
		"--fallback-paths", "/sitemap.xml,/sitemap.xml.gz",
		"--ignore-errors", "fallback_used,content_type_unexpected",
		"--insecure-skip-verify",
		"--max-depth", "5",
		"--max-files", "10",
		"--max-urls", "20",
		"--robots-url", "https://example.com/robots.txt",
		"--output", "json",
		"--user-agent", "custom-agent/1.0",
		"--timeout", "30s",
		"--verbose=2",
	})
	if err != nil {
		t.Fatalf("parseFlags() error = %v", err)
	}

	if !cfg.Strict {
		t.Fatalf("Strict = false, want true")
	}
	if !cfg.AllowCrossHost {
		t.Fatalf("AllowCrossHost = false, want true")
	}
	if got, want := cfg.FallbackStatus, "ok"; got != want {
		t.Fatalf("FallbackStatus = %q, want %q", got, want)
	}
	if got, want := len(cfg.FallbackPaths), 2; got != want {
		t.Fatalf("FallbackPaths len = %d, want %d", got, want)
	}
	if !cfg.HTTP.InsecureSkipVerify {
		t.Fatalf("InsecureSkipVerify = false, want true")
	}
	if got, want := cfg.HTTP.UserAgent, "custom-agent/1.0"; got != want {
		t.Fatalf("UserAgent = %q, want %q", got, want)
	}
	if got, want := cfg.Verbosity, 2; got != want {
		t.Fatalf("Verbosity = %d, want %d", got, want)
	}
	if got, want := cfg.OutputMode, checkreport.OutputJSON; got != want {
		t.Fatalf("OutputMode = %q, want %q", got, want)
	}
	if got, want := cfg.MaxDepth, 5; got != want {
		t.Fatalf("MaxDepth = %d, want %d", got, want)
	}
	if got, want := cfg.MaxFiles, 10; got != want {
		t.Fatalf("MaxFiles = %d, want %d", got, want)
	}
	if got, want := cfg.MaxURLs, 20; got != want {
		t.Fatalf("MaxURLs = %d, want %d", got, want)
	}
	if got, want := len(cfg.IgnoreErrors), 2; got != want {
		t.Fatalf("IgnoreErrors len = %d, want %d", got, want)
	}
	if !cfg.IgnoreErrorSet["fallback_used"] || !cfg.IgnoreErrorSet["content_type_unexpected"] {
		t.Fatalf("IgnoreErrorSet missing expected slugs: %+v", cfg.IgnoreErrorSet)
	}
}

func TestParseFlagsListErrorSlugs(t *testing.T) {
	cfg, err := parseFlags(testProgramName, []string{"--list-error-slugs"})
	if err != nil {
		t.Fatalf("parseFlags() error = %v", err)
	}
	if !cfg.ShowErrorSlugs {
		t.Fatalf("ShowErrorSlugs = false, want true")
	}
}

func TestParseFlagsRejectsUnknownIgnoredSlug(t *testing.T) {
	_, err := parseFlags(testProgramName, []string{"-H", "example.com", "--ignore-errors", "unknown_slug"})
	if err == nil || !strings.Contains(err.Error(), `unknown ignored error slug "unknown_slug"`) {
		t.Fatalf("parseFlags() error = %v, want unknown slug error", err)
	}
}

func TestRunListErrorSlugs(t *testing.T) {
	exitCode, output := runWithCapturedStdout(t, testProgramName, []string{"--list-error-slugs"})

	if exitCode != 0 {
		t.Fatalf("Run() exitCode = %d, want 0", exitCode)
	}
	for _, snippet := range []string{
		"fallback_used",
		"discovery",
		"fetch_failed",
		"transport",
	} {
		if !strings.Contains(output, snippet) {
			t.Fatalf("Run() output missing %q in:\n%s", snippet, output)
		}
	}
}

func TestParseFlagsCombinesVerbosityFormsAndClamps(t *testing.T) {
	cfg, err := parseFlags(testProgramName, []string{
		"-H", "example.com",
		"-v",
		"--verbose", "2",
		"-vv",
	})
	if err != nil {
		t.Fatalf("parseFlags() error = %v", err)
	}
	if got, want := cfg.Verbosity, 3; got != want {
		t.Fatalf("Verbosity = %d, want %d", got, want)
	}
}

func TestParseFlagsStoresOverlappingTargetInputs(t *testing.T) {
	cfg, err := parseFlags(testProgramName, []string{
		"-H", "example.com",
		"-u", "http://docs.example.net",
		"--entrypoint", "https://example.com/sitemap.xml",
		"--robots-url", "https://example.com/custom-robots.txt",
	})
	if err != nil {
		t.Fatalf("parseFlags() error = %v", err)
	}
	if got, want := cfg.Hostname, "example.com"; got != want {
		t.Fatalf("Hostname = %q, want %q", got, want)
	}
	if got, want := cfg.URL, "http://docs.example.net"; got != want {
		t.Fatalf("URL = %q, want %q", got, want)
	}
	if got, want := cfg.Entrypoint, "https://example.com/sitemap.xml"; got != want {
		t.Fatalf("Entrypoint = %q, want %q", got, want)
	}
	if got, want := cfg.RobotsURL, "https://example.com/custom-robots.txt"; got != want {
		t.Fatalf("RobotsURL = %q, want %q", got, want)
	}
}

func TestParseFlagsRejectsInvalidFallbackStatus(t *testing.T) {
	_, err := parseFlags(testProgramName, []string{"-H", "example.com", "--fallback-status", "critical"})
	if err == nil || !strings.Contains(err.Error(), "fallback-status must be one of: ok, warn") {
		t.Fatalf("parseFlags() error = %v, want invalid fallback status error", err)
	}
}

func TestParseFlagsRejectsInvalidFallbackPath(t *testing.T) {
	_, err := parseFlags(testProgramName, []string{"-H", "example.com", "--fallback-paths", "sitemap.xml,/sitemap.xml"})
	if err == nil || !strings.Contains(err.Error(), "fallback paths must start with /") {
		t.Fatalf("parseFlags() error = %v, want invalid fallback path error", err)
	}
}

func TestParseFlagsAllowsDisablingFallback(t *testing.T) {
	cfg, err := parseFlags(testProgramName, []string{"-H", "example.com", "--fallback=false"})
	if err != nil {
		t.Fatalf("parseFlags() error = %v", err)
	}
	if cfg.FallbackProbe {
		t.Fatalf("FallbackProbe = true, want false")
	}
}

func TestRunHelpMentionsConflictSensitiveOptions(t *testing.T) {
	exitCode, output := runWithCapturedStdout(t, "check_habr_sitemap", []string{"--help"})
	if exitCode != 0 {
		t.Fatalf("Run() exitCode = %d, want 0", exitCode)
	}
	wantSnippets := []string{
		"Use --ignore-errors fallback_used to suppress that finding entirely.",
		"Use --list-error-slugs to see the available values.",
		"When both --url and --hostname are provided, --url wins.",
		"Escalate selected scope validation findings from warning to critical.",
		"json emits the structured sitemap waterfall report for external renderers.",
	}
	for _, snippet := range wantSnippets {
		if !strings.Contains(output, snippet) {
			t.Fatalf("Run() help output missing %q in:\n%s", snippet, output)
		}
	}
	if !strings.Contains(output, "check_habr_sitemap") {
		t.Fatalf("Run() help output = %q, want installed binary name", output)
	}
}

func TestRunJSONOutput(t *testing.T) {
	originalRun := sitemapRun
	t.Cleanup(func() { sitemapRun = originalRun })
	sitemapRun = func(_ context.Context, cfg sitemap.Config) (*sitemap.Result, error) {
		result := &sitemap.Result{
			Config:           cfg,
			TargetSource:     "hostname",
			EffectiveBaseURL: "https://example.com/",
			DiscoveredVia:    "robots",
			Entrypoints:      []string{"https://example.com/sitemap.xml"},
			Documents: []sitemap.DocumentResult{{
				URL:        "https://example.com/sitemap.xml",
				Kind:       "urlset",
				StatusCode: 200,
				Depth:      0,
				Entries:    1,
				Children:   0,
				Encoding:   "utf-8",
			}},
			TotalURLs: 1,
		}
		result.Problems = []sitemap.Problem{{
			Severity: sitemap.SeverityWarning,
			Code:     "fallback_used",
			Message:  "sitemap discovered via fallback probing, robots.txt has no Sitemap directive",
			URL:      "https://example.com/sitemap.xml",
		}}
		return result, nil
	}

	exitCode, output := runWithCapturedStdout(t, testProgramName, []string{"-H", "example.com", "--output", "json"})
	if exitCode != 1 {
		t.Fatalf("Run() exitCode = %d, want 1", exitCode)
	}
	var report checkreport.Report
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\noutput=%s", err, output)
	}
	if got, want := report.Probe, "sitemap"; got != want {
		t.Fatalf("report.Probe = %q, want %q", got, want)
	}
	if got, want := report.Status, checkreport.StatusWarning; got != want {
		t.Fatalf("report.Status = %q, want %q", got, want)
	}
	if len(report.Findings) == 0 || report.Findings[0].Code != "fallback_used" {
		t.Fatalf("report.Findings = %#v, want fallback_used", report.Findings)
	}
}

func TestRunRejectsMissingTarget(t *testing.T) {
	exitCode, output := runWithCapturedStdout(t, "check_sitemap", nil)
	if exitCode != 3 {
		t.Fatalf("Run() exitCode = %d, want 3", exitCode)
	}
	if !strings.Contains(output, "UNKNOWN - either -H/--hostname, -u/--url or --entrypoint is required") {
		t.Fatalf("Run() output = %q, want missing target error", output)
	}
}

func TestRunRejectsInvalidFallbackStatus(t *testing.T) {
	exitCode, output := runWithCapturedStdout(t, "check_sitemap", []string{"-H", "example.com", "--fallback-status", "critical"})
	if exitCode != 3 {
		t.Fatalf("Run() exitCode = %d, want 3", exitCode)
	}
	if !strings.Contains(output, "UNKNOWN - fallback-status must be one of: ok, warn") {
		t.Fatalf("Run() output = %q, want fallback-status error", output)
	}
}

func TestRunVersionPrintsBinaryNameAndMetadata(t *testing.T) {
	exitCode, output := runWithCapturedStdout(t, "check_habr_sitemap", []string{"--version"})
	if exitCode != 0 {
		t.Fatalf("Run() exitCode = %d, want 0", exitCode)
	}
	if !strings.HasPrefix(strings.TrimSpace(output), "check_habr_sitemap ") {
		t.Fatalf("Run() output = %q, want version string starting with binary name", output)
	}
}

func runWithCapturedStdout(t *testing.T, programName string, args []string) (int, string) {
	t.Helper()

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	defer r.Close()
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	exitCode := Run(programName, args)
	w.Close()

	var out bytes.Buffer
	if _, err := io.Copy(&out, r); err != nil {
		t.Fatalf("io.Copy() error = %v", err)
	}
	return exitCode, out.String()
}
