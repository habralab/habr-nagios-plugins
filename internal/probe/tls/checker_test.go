package tlsprobe

import (
	"context"
	"strings"
	"testing"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/core/pkix"
	"github.com/habralab/habr-nagios-plugins/internal/core/probecli"
	"github.com/habralab/habr-nagios-plugins/internal/core/tlsx"
)

func TestRunBuildsPlaceholderReport(t *testing.T) {
	result, err := Run(context.Background(), Config{
		Hostname:            "www.example.com",
		Port:                443,
		Transport:           tlsx.TransportTCP,
		Timeout:             DefaultConfig().Timeout,
		DNSTimeout:          DefaultConfig().DNSTimeout,
		HandshakeTimeout:    DefaultConfig().HandshakeTimeout,
		OutputMode:          checkreport.OutputJSON,
		PolicyUntrustedRoot: pkix.UntrustedRootCritical,
		PolicyDualStack:     pkix.DualStackDegraded,
		IgnoreErrorSet:      map[string]bool{},
		Analyzer:            placeholderAnalyzer{},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got, want := result.Report.Probe, "tls"; got != want {
		t.Fatalf("report.Probe = %q, want %q", got, want)
	}
	if got, want := result.Report.Status, checkreport.StatusUnknown; got != want {
		t.Fatalf("report.Status = %q, want %q", got, want)
	}
	if len(result.Report.Stages) == 0 {
		t.Fatalf("report.Stages is empty")
	}
}

func TestNormalizeTargetRejectsMissingHostname(t *testing.T) {
	_, err := normalizeTarget(DefaultConfig())
	if err == nil || !strings.Contains(err.Error(), "-H/--hostname is required") {
		t.Fatalf("normalizeTarget() error = %v, want missing hostname error", err)
	}
}

func TestParseOutputModeSupportsJSON(t *testing.T) {
	mode, err := probecli.ParseOutputMode("json")
	if err != nil {
		t.Fatalf("ParseOutputMode() error = %v", err)
	}
	if got, want := mode, checkreport.OutputJSON; got != want {
		t.Fatalf("ParseOutputMode() = %q, want %q", got, want)
	}
}
