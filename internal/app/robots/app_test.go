package robotsapp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/probe/robots"
)

const testProgramName = "check_robots"

func TestParseFlagsCoversCommonOptions(t *testing.T) {
	cfg, err := parseFlags(testProgramName, []string{
		"-H", "example.com",
		"--robots-url", "https://example.com/robots.txt",
		"--strict",
		"--output", "json",
		"--behavior-profile", "vendor-aware",
		"--require-sitemap",
		"--require-user-agent", "Googlebot,*",
		"--require-disallow", "/admin,/private",
		"--forbid-disallow", "/",
		"--insecure-skip-verify",
		"--user-agent", "custom-agent/1.0",
		"--timeout", "45s",
		"--verbose=2",
	})
	if err != nil {
		t.Fatalf("parseFlags() error = %v", err)
	}

	if !cfg.Strict {
		t.Fatalf("Strict = false, want true")
	}
	if got, want := cfg.BehaviorProfile, robots.BehaviorProfileVendorAware; got != want {
		t.Fatalf("BehaviorProfile = %q, want %q", got, want)
	}
	if !cfg.RequireSitemap {
		t.Fatalf("RequireSitemap = false, want true")
	}
	if got, want := len(cfg.RequireUserAgents), 2; got != want {
		t.Fatalf("RequireUserAgents len = %d, want %d", got, want)
	}
	if got, want := len(cfg.RequireDisallows), 2; got != want {
		t.Fatalf("RequireDisallows len = %d, want %d", got, want)
	}
	if got, want := len(cfg.ForbidDisallows), 1; got != want {
		t.Fatalf("ForbidDisallows len = %d, want %d", got, want)
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
}

func TestParseFlagsRejectsInvalidBehaviorProfile(t *testing.T) {
	_, err := parseFlags(testProgramName, []string{"-H", "example.com", "--behavior-profile", "weird"})
	if err == nil {
		t.Fatalf("parseFlags() error = nil, want invalid behavior profile error")
	}
	if !strings.Contains(err.Error(), "invalid --behavior-profile") {
		t.Fatalf("parseFlags() error = %v, want invalid behavior profile message", err)
	}
}

func TestRunListErrorSlugs(t *testing.T) {
	exitCode, output := runWithCapturedStdout(t, testProgramName, []string{"--list-error-slugs"})
	if exitCode != 0 {
		t.Fatalf("Run() exitCode = %d, want 0", exitCode)
	}
	for _, snippet := range []string{
		"robots_empty",
		"content",
		"robots_bad_status",
		"transport",
	} {
		if !strings.Contains(output, snippet) {
			t.Fatalf("Run() output missing %q in:\n%s", snippet, output)
		}
	}
}

func TestRunListAgentBehaviors(t *testing.T) {
	exitCode, output := runWithCapturedStdout(t, testProgramName, []string{"--list-agent-behaviors"})
	if exitCode != 0 {
		t.Fatalf("Run() exitCode = %d, want 0", exitCode)
	}
	for _, snippet := range []string{
		"Yeti\tcategory=http-status\tsubject=5xx\tdisposition=interprets-as-disallow-all",
		"MojeekBot\tcategory=directive\tsubject=Crawl-delay\tdisposition=ignores",
	} {
		if !strings.Contains(output, snippet) {
			t.Fatalf("Run() output missing %q in:\n%s", snippet, output)
		}
	}
}

func TestRunRejectsMissingTarget(t *testing.T) {
	exitCode, output := runWithCapturedStdout(t, "check_robots", nil)
	if exitCode != 3 {
		t.Fatalf("Run() exitCode = %d, want 3", exitCode)
	}
	if !strings.Contains(output, "UNKNOWN - either -H/--hostname, -u/--url or --robots-url is required") {
		t.Fatalf("Run() output = %q, want missing target error", output)
	}
}

func TestRunHelpMentionsPolicyOptions(t *testing.T) {
	exitCode, output := runWithCapturedStdout(t, "check_habr_robots", []string{"--help"})
	if exitCode != 0 {
		t.Fatalf("Run() exitCode = %d, want 0", exitCode)
	}
	for _, snippet := range []string{
		"Require at least one Sitemap directive.",
		"Require one or more User-agent values to exist.",
		"Fail when one or more Disallow rules are present exactly as written.",
		"json emits the structured robots waterfall report for external renderers.",
	} {
		if !strings.Contains(output, snippet) {
			t.Fatalf("Run() help output missing %q in:\n%s", snippet, output)
		}
	}
	if !strings.Contains(output, "check_habr_robots") {
		t.Fatalf("Run() help output = %q, want installed binary name", output)
	}
}

func TestRunJSONOutput(t *testing.T) {
	originalRun := robotsRun
	t.Cleanup(func() { robotsRun = originalRun })
	robotsRun = func(_ context.Context, cfg robots.Config) (*robots.Result, error) {
		result := &robots.Result{
			Config:             cfg,
			TargetSource:       "hostname",
			EffectiveBaseURL:   "https://example.com",
			EffectiveRobotsURL: "https://example.com/robots.txt",
			FinalURL:           "https://example.com/robots.txt",
			StatusCode:         200,
			Encoding:           "utf-8",
			Perf:               robots.PerfStats{},
		}
		result.Problems = []robots.Problem{{
			Severity: robots.SeverityWarning,
			Code:     "robots_empty",
			Message:  "robots.txt is empty",
			URL:      "https://example.com/robots.txt",
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
	if got, want := report.Probe, "robots"; got != want {
		t.Fatalf("report.Probe = %q, want %q", got, want)
	}
	if got, want := report.Status, checkreport.StatusWarning; got != want {
		t.Fatalf("report.Status = %q, want %q", got, want)
	}
	if len(report.Findings) == 0 || report.Findings[0].Code != "robots_empty" {
		t.Fatalf("report.Findings = %#v, want robots_empty", report.Findings)
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
