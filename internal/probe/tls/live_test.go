//go:build integration

package tlsprobe

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/core/tlsx"
)

func TestLiveAnalyzerWithTrustedLocalhost(t *testing.T) {
	restoreDNS := stubDNSResolverFactory()
	defer restoreDNS()

	rootPEM, serverCert := mustIssueServerCertificate(t, []string{"localhost"})
	caFile := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(caFile, rootPEM, 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	ln := mustTLSListener(t, serverCert, []string{"http/1.1"})
	defer ln.Close()
	go serveTLSHandshakes(ln)

	cfg := DefaultConfig()
	cfg.Hostname = "localhost"
	cfg.Port = ln.Addr().(*net.TCPAddr).Port
	cfg.Transport = tlsx.TransportTCP
	cfg.CAFile = caFile
	cfg.ExpectALPN = []string{"http/1.1"}
	cfg.IgnoreErrorSet = map[string]bool{
		"tls_ocsp_stapling_missing": true,
		"tls_sct_missing":           true,
	}

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got, want := result.Report.Status, checkreport.StatusOK; got != want {
		t.Fatalf("report.Status = %q, want %q", got, want)
	}
}

func TestLiveAnalyzerDetectsHostnameMismatch(t *testing.T) {
	restoreDNS := stubDNSResolverFactory()
	defer restoreDNS()

	rootPEM, serverCert := mustIssueServerCertificate(t, []string{"example.com"})
	caFile := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(caFile, rootPEM, 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	ln := mustTLSListener(t, serverCert, []string{"http/1.1"})
	defer ln.Close()
	go serveTLSHandshakes(ln)

	cfg := DefaultConfig()
	cfg.Hostname = "localhost"
	cfg.Port = ln.Addr().(*net.TCPAddr).Port
	cfg.Transport = tlsx.TransportTCP
	cfg.CAFile = caFile
	cfg.IgnoreErrorSet = map[string]bool{
		"tls_ocsp_stapling_missing": true,
		"tls_sct_missing":           true,
	}

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got, want := result.Report.Status, checkreport.StatusCritical; got != want {
		t.Fatalf("report.Status = %q, want %q", got, want)
	}
	found := false
	for _, finding := range result.Report.Findings {
		if finding.Code == "tls_hostname_mismatch" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("report.Findings = %#v, want tls_hostname_mismatch", result.Report.Findings)
	}
}

func TestLiveAnalyzerWithSMTPSTARTTLSLocalhost(t *testing.T) {
	restoreDNS := stubDNSResolverFactory()
	defer restoreDNS()

	rootPEM, serverCert := mustIssueServerCertificate(t, []string{"localhost"})
	caFile := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(caFile, rootPEM, 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	ln := mustTCPListener(t)
	defer ln.Close()
	go serveSMTPSTARTTLS(ln, serverCert)

	cfg := DefaultConfig()
	cfg.Hostname = "localhost"
	cfg.Port = ln.Addr().(*net.TCPAddr).Port
	cfg.Transport = tlsx.TransportTCP
	cfg.STARTTLS = tlsx.STARTTLSSMTP
	cfg.CAFile = caFile
	cfg.IgnoreErrorSet = map[string]bool{
		"tls_ocsp_stapling_missing": true,
		"tls_sct_missing":           true,
	}

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got, want := result.Report.Status, checkreport.StatusOK; got != want {
		t.Fatalf("report.Status = %q, want %q", got, want)
	}
}
