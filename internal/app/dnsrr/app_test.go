package dnsrrapp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/probe/dnsrr"
	"github.com/habralab/habr-nagios-plugins/internal/testkit/apptest"
)

func TestParseFlagsRejectsInvalidModes(t *testing.T) {
	_, err := parseFlags("check_dnsrr", []string{"-H", "www.example.com", "--rrtype", "A", "--mode", "bad"})
	if err == nil || !strings.Contains(err.Error(), "invalid --mode") {
		t.Fatalf("parseFlags() error = %v, want invalid mode error", err)
	}
}

func TestParseFlagsRejectsInvalidDNSSECMode(t *testing.T) {
	_, err := parseFlags("check_dnsrr", []string{"-H", "www.example.com", "--rrtype", "A", "--dnssec-mode", "bad"})
	if err == nil || !strings.Contains(err.Error(), "invalid --dnssec-mode") {
		t.Fatalf("parseFlags() error = %v, want invalid dnssec mode error", err)
	}
}

func TestParseFlagsStoresValueMatchers(t *testing.T) {
	cfg, err := parseFlags("check_dnsrr", []string{"-H", "www.example.com", "--rrtype", "TXT", "--contains", "spf1"})
	if err != nil {
		t.Fatalf("parseFlags() error = %v", err)
	}
	if got, want := cfg.ContainsValue, "spf1"; got != want {
		t.Fatalf("ContainsValue = %q, want %q", got, want)
	}
}

func TestParseFlagsDefaultsDNSSECModeToPrefer(t *testing.T) {
	cfg, err := parseFlags("check_dnsrr", []string{"-H", "www.example.com", "--rrtype", "TXT"})
	if err != nil {
		t.Fatalf("parseFlags() error = %v", err)
	}
	if got, want := string(cfg.DNSSECMode), "prefer"; got != want {
		t.Fatalf("DNSSECMode = %q, want %q", got, want)
	}
}

func TestRenderHelpMentionsValueMatchersAndTimeoutSemantics(t *testing.T) {
	help := renderHelp("check_dnsrr")
	for _, snippet := range []string{
		"--expect-value",
		"--contains",
		"--regex",
		"--cache-backend",
		"redis+unix:///var/run/redis.sock?db=0",
		"Default: prefer.",
		"Perfdata dnssec_status uses -1=disabled, 0=indeterminate, 1=bogus, 2=insecure, 3=secure.",
		"Only one of --expect-value, --contains, or --regex may be used per run.",
		"Bare integers are interpreted as seconds.",
	} {
		if !strings.Contains(help, snippet) {
			t.Fatalf("renderHelp() missing %q in help:\n%s", snippet, help)
		}
	}
}

func TestRunJSONOutputIncludesRuntimeCacheBackendStage(t *testing.T) {
	originalRun := dnsrrRun
	t.Cleanup(func() { dnsrrRun = originalRun })
	dnsrrRun = func(_ context.Context, cfg dnsrr.Config) (*dnsrr.Result, error) {
		return &dnsrr.Result{
			Config: cfg,
			Report: checkreport.Report{
				Probe:         dnsrr.Meta.Slug,
				Target:        "example.com.",
				PrimaryTarget: "example.com.",
				Status:        checkreport.StatusOK,
				Summary:       "TXT RRset is present as requested",
			},
		}, nil
	}

	exitCode, output := apptest.RunWithCapturedStdout(t, func() int {
		return Run("check_dnsrr", []string{"-H", "example.com", "--rrtype", "TXT", "--output", "json", "--cache-backend", "internal://"})
	})
	if exitCode != 0 {
		t.Fatalf("Run() exitCode = %d, want 0", exitCode)
	}
	var report checkreport.Report
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\noutput=%s", err, output)
	}
	var found bool
	for _, stage := range report.Stages {
		if stage.ID == "runtime.cache_backend" {
			found = true
		}
	}
	if !found {
		t.Fatalf("report.Stages = %#v, want runtime.cache_backend", report.Stages)
	}
}
