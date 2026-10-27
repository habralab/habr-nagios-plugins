package dnsrr

import (
	"testing"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/core/dnsprobe"
	"github.com/habralab/habr-nagios-plugins/internal/core/dnsresolver"
)

func TestFinalizeReportRecomputesStatusAfterSuppression(t *testing.T) {
	report := checkreport.Report{
		Status:   checkreport.StatusUnknown,
		Summary:  "authority lookup failed",
		Findings: []checkreport.Finding{makeFinding("dnsrr_no_authoritative_answers", checkreport.StatusUnknown, "example.com.", "authority lookup failed")},
	}
	finalizeReport(&report, Config{IgnoreErrorSet: map[string]bool{"dnsrr_no_authoritative_answers": true}}, time.Now())
	if report.Status != checkreport.StatusOK || len(report.Findings) != 0 || len(report.SuppressedFindings) != 1 {
		t.Fatalf("report after suppression = %#v", report)
	}
}

func TestDNSSECMetricValue(t *testing.T) {
	tests := []struct {
		name  string
		mode  dnsprobe.DNSSECMode
		state dnsresolver.SecurityState
		want  float64
	}{
		{name: "disabled", mode: dnsprobe.DNSSECIgnore, state: dnsresolver.SecuritySecure, want: -1},
		{name: "secure", mode: dnsprobe.DNSSECPrefer, state: dnsresolver.SecuritySecure, want: 3},
		{name: "insecure", mode: dnsprobe.DNSSECPrefer, state: dnsresolver.SecurityInsecure, want: 2},
		{name: "bogus", mode: dnsprobe.DNSSECPrefer, state: dnsresolver.SecurityBogus, want: 1},
		{name: "indeterminate", mode: dnsprobe.DNSSECPrefer, state: dnsresolver.SecurityIndeterminate, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dnssecMetricValue(tt.mode, tt.state); got != tt.want {
				t.Fatalf("dnssecMetricValue(%q, %q) = %v, want %v", tt.mode, tt.state, got, tt.want)
			}
		})
	}
}

func TestEvaluateDNSSECReturnsMetric(t *testing.T) {
	stage, findings, metric := evaluateDNSSEC(
		Target{Owner: "example.com", RRTypeRaw: "TXT"},
		dnsprobe.DNSSECRequire,
		dnsresolver.LookupResult{Security: dnsresolver.SecurityBogus, ValidationMessage: "broken sig"},
		nil,
	)
	if got, want := stage.Status, checkreport.StatusCritical; got != want {
		t.Fatalf("stage.Status = %q, want %q", got, want)
	}
	if got, want := len(findings), 1; got != want {
		t.Fatalf("len(findings) = %d, want %d", got, want)
	}
	if got, want := metric.Name, "dnssec_status"; got != want {
		t.Fatalf("metric.Name = %q, want %q", got, want)
	}
	if metric.Number == nil || *metric.Number != 1 {
		t.Fatalf("metric.Number = %#v, want 1", metric.Number)
	}
}
