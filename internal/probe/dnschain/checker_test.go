package dnschain

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
)

func TestRunBuildsStructuredUnknownReport(t *testing.T) {
	prev := DefaultAnalyzerFactory
	DefaultAnalyzerFactory = func() Analyzer { return placeholderAnalyzer{} }
	defer func() { DefaultAnalyzerFactory = prev }()

	cfg := DefaultConfig()
	cfg.Hostname = "www.example.com"

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got, want := result.Report.Status, checkreport.StatusUnknown; got != want {
		t.Fatalf("Report.Status = %q, want %q", got, want)
	}
	if got, want := result.ExitCode(), 3; got != want {
		t.Fatalf("ExitCode() = %d, want %d", got, want)
	}
	if got := result.Detail(); !strings.Contains(got, "Stages:") || !strings.Contains(got, "engine.status") {
		t.Fatalf("Detail() = %q, want waterfall stages", got)
	}
}

func TestRunRequiresTarget(t *testing.T) {
	prev := DefaultAnalyzerFactory
	DefaultAnalyzerFactory = func() Analyzer { return placeholderAnalyzer{} }
	defer func() { DefaultAnalyzerFactory = prev }()

	_, err := Run(context.Background(), DefaultConfig())
	if err == nil || !strings.Contains(err.Error(), "either -H/--hostname or --zone is required") {
		t.Fatalf("Run() error = %v, want missing target error", err)
	}
}

func TestParseOutputMode(t *testing.T) {
	mode, err := ParseOutputMode("json")
	if err != nil {
		t.Fatalf("ParseOutputMode() error = %v", err)
	}
	if got, want := mode, checkreport.OutputJSON; got != want {
		t.Fatalf("ParseOutputMode() = %q, want %q", got, want)
	}
}

func TestSummaryAndDetailReportSuppressedFindingsSeparately(t *testing.T) {
	result := &Result{
		Config: Config{Verbosity: 1},
		Report: checkreport.Report{
			Probe:              Meta.Slug,
			PrimaryTarget:      "example.com.",
			Status:             checkreport.StatusOK,
			Summary:            "authoritative delegation looks healthy for example.com.",
			Metrics:            []checkreport.Metric{countMetric("findings", 0), countMetric("ignored", 1)},
			SuppressedFindings: []checkreport.Finding{{Code: "dnschain_child_soa_inconsistent", Severity: checkreport.StatusWarning, Target: "example.com.", Message: "suppressed warning"}},
		},
	}

	summary := result.Summary()
	if !strings.Contains(summary, "ignored=1") {
		t.Fatalf("Summary() = %q, want ignored metric", summary)
	}

	detail := result.Detail()
	if !strings.Contains(detail, "Suppressed Findings:\n") || !strings.Contains(detail, "dnschain_child_soa_inconsistent") {
		t.Fatalf("Detail() = %q, want suppressed findings section", detail)
	}
}

func TestBuildUnknownReportDoesNotSuppressDifferentTransportFailureClass(t *testing.T) {
	report := buildUnknownReport(checkreport.Report{
		Probe:         Meta.Slug,
		PrimaryTarget: "habr.com",
	}, time.Now(), "habr.com", "dnschain_root_dnskey_fetch_failed", "root DNSKEY lookup failed", map[string]bool{
		"dnschain_nameserver_endpoint_unreachable": true,
	})

	if got, want := report.Status, checkreport.StatusUnknown; got != want {
		t.Fatalf("Report.Status = %q, want %q", got, want)
	}
	if got, want := len(report.Findings), 1; got != want {
		t.Fatalf("len(Findings) = %d, want %d", got, want)
	}
	if got, want := len(report.SuppressedFindings), 0; got != want {
		t.Fatalf("len(SuppressedFindings) = %d, want %d", got, want)
	}
	if got, want := report.Findings[0].Code, "dnschain_root_dnskey_fetch_failed"; got != want {
		t.Fatalf("Finding code = %q, want %q", got, want)
	}
}

func TestBuildUnknownReportSuppressesExactMatchingFailureClass(t *testing.T) {
	report := buildUnknownReport(checkreport.Report{
		Probe:         Meta.Slug,
		PrimaryTarget: "habr.com",
	}, time.Now(), "habr.com", "dnschain_root_dnskey_fetch_failed", "root DNSKEY lookup failed", map[string]bool{
		"dnschain_root_dnskey_fetch_failed": true,
	})

	if got, want := len(report.Findings), 0; got != want {
		t.Fatalf("len(Findings) = %d, want %d", got, want)
	}
	if got, want := len(report.SuppressedFindings), 1; got != want {
		t.Fatalf("len(SuppressedFindings) = %d, want %d", got, want)
	}
	if got, want := report.SuppressedFindings[0].Code, "dnschain_root_dnskey_fetch_failed"; got != want {
		t.Fatalf("Suppressed finding code = %q, want %q", got, want)
	}
}
