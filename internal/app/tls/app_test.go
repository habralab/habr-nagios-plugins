package tlsapp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/core/pkix"
	"github.com/habralab/habr-nagios-plugins/internal/core/tlsx"
	tlsprobe "github.com/habralab/habr-nagios-plugins/internal/probe/tls"
	"github.com/habralab/habr-nagios-plugins/internal/testkit/apptest"
)

const testProgramName = "check_tls"

func TestParseFlagsSupportsPoliciesAndJSON(t *testing.T) {
	cfg, err := parseFlags(testProgramName, []string{
		"-H", "www.example.com",
		"--port", "587",
		"--transport", "tcp",
		"--starttls", "smtp",
		"--expect-alpn", "h2,http/1.1",
		"--timeout", "45s",
		"--dns-timeout", "4s",
		"--handshake-timeout", "6s",
		"--policy-untrusted-root", "warning",
		"--policy-dual-stack", "strict",
		"--ocsp-mode", "strict",
		"--ignore-expired-alternative",
		"--output", "json",
		"--verbose=2",
	})
	if err != nil {
		t.Fatalf("parseFlags() error = %v", err)
	}
	if cfg.ShowHelp || cfg.ShowVersion {
		t.Fatalf("unexpected help/version flags: help=%t version=%t", cfg.ShowHelp, cfg.ShowVersion)
	}
	if got, want := cfg.Port, 587; got != want {
		t.Fatalf("Port = %d, want %d", got, want)
	}
	if got, want := cfg.Transport, tlsx.TransportTCP; got != want {
		t.Fatalf("Transport = %q, want %q", got, want)
	}
	if got, want := cfg.STARTTLS, tlsx.STARTTLSSMTP; got != want {
		t.Fatalf("STARTTLS = %q, want %q", got, want)
	}
	if got, want := cfg.PolicyUntrustedRoot, pkix.UntrustedRootWarning; got != want {
		t.Fatalf("PolicyUntrustedRoot = %q, want %q", got, want)
	}
	if got, want := cfg.PolicyDualStack, pkix.DualStackStrict; got != want {
		t.Fatalf("PolicyDualStack = %q, want %q", got, want)
	}
	if got, want := cfg.OCSPMode, pkix.OCSPStrict; got != want {
		t.Fatalf("OCSPMode = %q, want %q", got, want)
	}
	if got, want := cfg.OutputMode, checkreport.OutputJSON; got != want {
		t.Fatalf("OutputMode = %q, want %q", got, want)
	}
	if got, want := cfg.Verbosity, 2; got != want {
		t.Fatalf("Verbosity = %d, want %d", got, want)
	}
	if got, want := len(cfg.ExpectALPN), 2; got != want {
		t.Fatalf("ExpectALPN len = %d, want %d", got, want)
	}
	if got, want := cfg.WarnExpiryDays, 30; got != want {
		t.Fatalf("WarnExpiryDays = %d, want %d", got, want)
	}
	if !cfg.IgnoreExpiredAlternative {
		t.Fatalf("IgnoreExpiredAlternative = false, want true")
	}
}

func TestRunListErrorSlugs(t *testing.T) {
	exitCode, output := runWithCapturedStdout(t, testProgramName, []string{"--list-error-slugs"})
	if exitCode != 0 {
		t.Fatalf("Run() exitCode = %d, want 0", exitCode)
	}
	for _, snippet := range []string{
		"tls_chain_incomplete",
		"pki_chain",
		"tls_dane_mismatch",
		"dane",
	} {
		if !strings.Contains(output, snippet) {
			t.Fatalf("Run() output missing %q in:\n%s", snippet, output)
		}
	}
}

func TestRunJSONOutput(t *testing.T) {
	originalRun := tlsRun
	t.Cleanup(func() { tlsRun = originalRun })
	tlsRun = func(_ context.Context, cfg tlsprobe.Config) (*tlsprobe.Result, error) {
		return &tlsprobe.Result{
			Config: cfg,
			Report: checkreport.Report{
				Probe:         tlsprobe.Meta.Slug,
				Target:        "www.example.com:443",
				PrimaryTarget: "www.example.com:443",
				Status:        checkreport.StatusWarning,
				Summary:       "certificate expires in 5 days",
			},
		}, nil
	}

	exitCode, output := runWithCapturedStdout(t, testProgramName, []string{"-H", "www.example.com", "--output", "json"})
	if exitCode != 1 {
		t.Fatalf("Run() exitCode = %d, want 1", exitCode)
	}
	var report checkreport.Report
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\noutput=%s", err, output)
	}
	if got, want := report.Probe, "tls"; got != want {
		t.Fatalf("report.Probe = %q, want %q", got, want)
	}
	if got, want := report.Status, checkreport.StatusWarning; got != want {
		t.Fatalf("report.Status = %q, want %q", got, want)
	}
}

func TestRunMissingTargetAsJSON(t *testing.T) {
	exitCode, output := runWithCapturedStdout(t, testProgramName, []string{"--output", "json"})
	if exitCode != 3 {
		t.Fatalf("Run() exitCode = %d, want 3", exitCode)
	}
	var report checkreport.Report
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\noutput=%s", err, output)
	}
	if !strings.Contains(report.Summary, "-H/--hostname is required") {
		t.Fatalf("report.Summary = %q, want missing hostname error", report.Summary)
	}
}

func TestRunHelpMentionsPolicyFlags(t *testing.T) {
	exitCode, output := runWithCapturedStdout(t, "check_habr_tls", []string{"--help"})
	if exitCode != 0 {
		t.Fatalf("Run() exitCode = %d, want 0", exitCode)
	}
	for _, snippet := range []string{
		"STARTTLS pre-flight profile.",
		"Policy when a chain is otherwise valid but the trust anchor is missing locally.",
		"Policy when one TLS certificate branch is degraded but another remains valid.",
		"OCSP validation mode.",
		"--cache-backend",
		"redis+unix:///var/run/redis.sock?db=0",
		"json emits the structured TLS waterfall report for external renderers.",
		"check_habr_tls",
	} {
		if !strings.Contains(output, snippet) {
			t.Fatalf("Run() help output missing %q in:\n%s", snippet, output)
		}
	}
}

func TestRunJSONOutputIncludesRuntimeCacheBackendStage(t *testing.T) {
	originalRun := tlsRun
	t.Cleanup(func() { tlsRun = originalRun })
	tlsRun = func(_ context.Context, cfg tlsprobe.Config) (*tlsprobe.Result, error) {
		return &tlsprobe.Result{
			Config: cfg,
			Report: checkreport.Report{
				Probe:         tlsprobe.Meta.Slug,
				Target:        "www.example.com:443",
				PrimaryTarget: "www.example.com:443",
				Status:        checkreport.StatusOK,
				Summary:       "TLS OK",
			},
		}, nil
	}

	exitCode, output := runWithCapturedStdout(t, testProgramName, []string{"-H", "www.example.com", "--output", "json", "--cache-backend", "redis+sentinel://127.0.0.1:26379?master=mymaster"})
	if exitCode != 0 {
		t.Fatalf("Run() exitCode = %d, want 0", exitCode)
	}
	var report checkreport.Report
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\noutput=%s", err, output)
	}
	var found bool
	var familyFound bool
	for _, stage := range report.Stages {
		if stage.ID == "runtime.cache_backend" && len(stage.Checks) > 0 {
			found = true
			if got := stage.Checks[0].Meta; len(got) == 0 {
				t.Fatalf("runtime.cache_backend meta = %#v, want structured metadata", got)
			}
		}
		if stage.ID == "runtime.transport_family" && len(stage.Checks) > 0 {
			familyFound = true
			if !containsKV(stage.Checks[0].Meta, "policy", "auto") {
				t.Fatalf("runtime.transport_family meta = %#v, want policy=auto", stage.Checks[0].Meta)
			}
		}
	}
	if !found {
		t.Fatalf("report.Stages = %#v, want runtime.cache_backend", report.Stages)
	}
	if !familyFound {
		t.Fatalf("report.Stages = %#v, want runtime.transport_family", report.Stages)
	}
}

func containsKV(items []checkreport.KV, key, value string) bool {
	for _, item := range items {
		if item.Key == key && item.Value == value {
			return true
		}
	}
	return false
}

func runWithCapturedStdout(t *testing.T, programName string, args []string) (int, string) {
	t.Helper()
	return apptest.RunWithCapturedStdout(t, func() int {
		return Run(programName, args)
	})
}
