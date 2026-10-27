//go:build integration

package tlsprobe

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/core/dnsresolver"
	"github.com/habralab/habr-nagios-plugins/internal/core/ipfamily"
	"github.com/habralab/habr-nagios-plugins/internal/core/pkix"
	"github.com/habralab/habr-nagios-plugins/internal/core/tlsx"
	"github.com/miekg/dns"
	"golang.org/x/crypto/ocsp"
)

func TestEvaluateOCSPActiveFetchPassesWithoutStaple(t *testing.T) {
	bundle := mustIssueServerCertificateBundleWithOCSP(t, []string{"example.com"}, nil)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || len(body) == 0 {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		response, err := ocsp.CreateResponse(bundle.RootCert, bundle.RootCert, ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: bundle.LeafCert.SerialNumber,
			ThisUpdate:   time.Now().Add(-time.Minute),
			NextUpdate:   time.Now().Add(time.Hour),
		}, bundle.RootKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(response)
	})
	ln := mustTCPListener(t)
	defer ln.Close()
	server := &http.Server{Handler: handler}
	go func() { _ = server.Serve(ln) }()
	defer server.Close()
	serverURL := "http://" + ln.Addr().String()

	bundle = mustIssueServerCertificateBundleWithOCSP(t, []string{"example.com"}, []string{serverURL})
	cfg := DefaultConfig()
	cfg.OCSPMode = pkix.OCSPActive

	assessment := evaluateOCSP(context.Background(), cfg, "example.com:443", "example.com", fakeDNSResolver{}, tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{bundle.LeafCert, bundle.RootCert},
	})
	if assessment.Check.State != checkreport.CheckPass {
		t.Fatalf("check.State = %q, want %q", assessment.Check.State, checkreport.CheckPass)
	}
	if assessment.Finding != nil {
		t.Fatalf("finding = %#v, want nil", assessment.Finding)
	}
}

func TestIntegrationAnalyzerWithTrustedLocalhost(t *testing.T) {
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
	cfg.IgnoreErrorSet = map[string]bool{"tls_sct_missing": true}

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got, want := result.Report.Status, checkreport.StatusOK; got != want {
		t.Fatalf("report.Status = %q, want %q; findings=%#v", got, want, result.Report.Findings)
	}
	pkiStage := checkreport.StageByID(&result.Report, "pki.validation")
	if pkiStage == nil {
		t.Fatalf("pki.validation stage not found")
	}
	if got, want := findStageCheckByID(t, pkiStage.Checks, "pki.chain.presented").State, checkreport.CheckPass; got != want {
		t.Fatalf("pki.chain.presented state = %q, want %q", got, want)
	}
	if got, want := findStageCheckByID(t, pkiStage.Checks, "pki.chain.policy").State, checkreport.CheckPass; got != want {
		t.Fatalf("pki.chain.policy state = %q, want %q", got, want)
	}
	if got, want := findStageCheckByID(t, pkiStage.Checks, "pki.chain.verify").State, checkreport.CheckPass; got != want {
		t.Fatalf("pki.chain.verify state = %q, want %q", got, want)
	}
	transportStage := checkreport.StageByID(&result.Report, "transport.setup")
	if transportStage == nil {
		t.Fatalf("transport.setup stage not found")
	}
	if got, want := findStageCheckByID(t, transportStage.Checks, "transport.endpoint_candidates").State, checkreport.CheckPass; got != want {
		t.Fatalf("transport.endpoint_candidates state = %q, want %q", got, want)
	}
	if got, want := findStageCheckByID(t, transportStage.Checks, "transport.endpoint_attempts").State, checkreport.CheckPass; got != want {
		t.Fatalf("transport.endpoint_attempts state = %q, want %q", got, want)
	}
	if got, want := findStageCheckByID(t, transportStage.Checks, "transport.mode").State, checkreport.CheckPass; got != want {
		t.Fatalf("transport.mode state = %q, want %q", got, want)
	}
	modernStage := checkreport.StageByID(&result.Report, "tls.modern_handshake")
	if modernStage == nil {
		t.Fatalf("tls.modern_handshake stage not found")
	}
	if got, want := findStageCheckByID(t, modernStage.Checks, "handshake.policy").State, checkreport.CheckPass; got != want {
		t.Fatalf("handshake.policy state = %q, want %q", got, want)
	}
	if got, want := findStageCheckByID(t, modernStage.Checks, "handshake.endpoint").State, checkreport.CheckPass; got != want {
		t.Fatalf("handshake.endpoint state = %q, want %q", got, want)
	}
	if got, want := findStageCheckByID(t, modernStage.Checks, "handshake.parameters").State, checkreport.CheckPass; got != want {
		t.Fatalf("handshake.parameters state = %q, want %q", got, want)
	}
	sniStage := checkreport.StageByID(&result.Report, "sni.profile")
	if sniStage == nil {
		t.Fatalf("sni.profile stage not found")
	}
	if got, want := findStageCheckByID(t, sniStage.Checks, "sni.profile").State, checkreport.CheckPass; got != want {
		t.Fatalf("sni.profile state = %q, want %q", got, want)
	}
}

func TestIntegrationAnalyzerWarnsOnPartialAddressCoverage(t *testing.T) {
	prev := defaultDNSResolverFactory
	defaultDNSResolverFactory = func(_ time.Duration, _ string, _ ipfamily.Policy) dnsResolver {
		return partialEndpointDNSResolver{}
	}
	defer func() {
		defaultDNSResolverFactory = prev
	}()

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
	cfg.IgnoreErrorSet = map[string]bool{"tls_sct_missing": true}

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got, want := result.Report.Status, checkreport.StatusWarning; got != want {
		t.Fatalf("report.Status = %q, want %q; findings=%#v", got, want, result.Report.Findings)
	}
	found := false
	for _, finding := range result.Report.Findings {
		if finding.Code == "tls_endpoint_failed" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("report.Findings = %#v, want tls_endpoint_failed", result.Report.Findings)
	}

	addressStage := checkreport.StageByID(&result.Report, "coverage.addresses")
	if addressStage == nil {
		t.Fatalf("coverage.addresses stage not found")
	}
	if got, want := findStageCheckByID(t, addressStage.Checks, "coverage.addresses").State, checkreport.CheckWarning; got != want {
		t.Fatalf("coverage.addresses state = %q, want %q", got, want)
	}
}

func TestIntegrationAnalyzerWarnsOnEndpointPKIDivergence(t *testing.T) {
	if !loopbackAliasLikelyAvailable("127.0.0.2") {
		t.Skip("loopback alias 127.0.0.2 is not available on this host")
	}
	prev := defaultDNSResolverFactory
	defaultDNSResolverFactory = func(_ time.Duration, _ string, _ ipfamily.Policy) dnsResolver {
		return dualLoopbackDNSResolver{}
	}
	defer func() {
		defaultDNSResolverFactory = prev
	}()

	rootPEM, certA := mustIssueServerCertificate(t, []string{"localhost"})
	_, certB := mustIssueServerCertificate(t, []string{"localhost"})
	caFile := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(caFile, rootPEM, 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	ln := mustLocalAddrSwitchingTLSListener(t, certA, certB, []string{"http/1.1"})
	defer ln.Close()
	go serveTLSHandshakes(ln)

	cfg := DefaultConfig()
	cfg.Hostname = "localhost"
	cfg.Port = ln.Addr().(*net.TCPAddr).Port
	cfg.Transport = tlsx.TransportTCP
	cfg.CAFile = caFile
	cfg.ExpectALPN = []string{"http/1.1"}
	cfg.IgnoreErrorSet = map[string]bool{"tls_sct_missing": true}

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got, want := result.Report.Status, checkreport.StatusWarning; got != want {
		t.Fatalf("report.Status = %q, want %q; findings=%#v", got, want, result.Report.Findings)
	}
	found := false
	for _, finding := range result.Report.Findings {
		if finding.Code == "tls_endpoint_pki_differs" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("report.Findings = %#v, want tls_endpoint_pki_differs", result.Report.Findings)
	}
	semanticsStage := checkreport.StageByID(&result.Report, "coverage.endpoint_semantics")
	if semanticsStage == nil {
		t.Fatalf("coverage.endpoint_semantics stage not found")
	}
	if got, want := findStageCheckByID(t, semanticsStage.Checks, "endpoint_semantics.pki").State, checkreport.CheckWarning; got != want {
		t.Fatalf("endpoint_semantics.pki state = %q, want %q", got, want)
	}
	profilesCheck := findStageCheckByID(t, semanticsStage.Checks, "endpoint_semantics.profiles")
	if got, want := len(profilesCheck.Evidence), 1; got != want {
		t.Fatalf("len(endpoint_semantics.profiles evidence) = %d, want %d", got, want)
	}
	if got, want := len(profilesCheck.Evidence[0].Items), 2; got != want {
		t.Fatalf("len(endpoint_semantics.profiles items) = %d, want %d", got, want)
	}
	if got := findStageCheckByID(t, semanticsStage.Checks, "endpoint_semantics.ct").ID; got != "endpoint_semantics.ct" {
		t.Fatalf("endpoint_semantics.ct missing")
	}
}

func TestIntegrationAnalyzerDetectsHostnameMismatch(t *testing.T) {
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
	cfg.IgnoreErrorSet = map[string]bool{"tls_sct_missing": true}

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

func TestIntegrationAnalyzerWithSMTPSTARTTLSLocalhost(t *testing.T) {
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
	cfg.IgnoreErrorSet = map[string]bool{"tls_sct_missing": true}

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got, want := result.Report.Status, checkreport.StatusOK; got != want {
		t.Fatalf("report.Status = %q, want %q; findings=%#v", got, want, result.Report.Findings)
	}
	transportStage := checkreport.StageByID(&result.Report, "transport.setup")
	if transportStage == nil {
		t.Fatalf("transport.setup stage not found")
	}
	if got, want := findStageCheckByID(t, transportStage.Checks, "transport.starttls.profile").State, checkreport.CheckPass; got != want {
		t.Fatalf("transport.starttls.profile state = %q, want %q", got, want)
	}
	if got, want := findStageCheckByID(t, transportStage.Checks, "transport.endpoint_attempts").State, checkreport.CheckPass; got != want {
		t.Fatalf("transport.endpoint_attempts state = %q, want %q", got, want)
	}
}

func TestIntegrationAnalyzerDetectsWeakTLS12CipherSupport(t *testing.T) {
	restoreDNS := stubDNSResolverFactory()
	defer restoreDNS()

	rootPEM, serverCert := mustIssueServerCertificate(t, []string{"localhost"})
	caFile := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(caFile, rootPEM, 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	ln := mustTLS12ListenerWithCipher(t, serverCert, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA})
	defer ln.Close()
	go serveTLSHandshakes(ln)

	cfg := DefaultConfig()
	cfg.Hostname = "localhost"
	cfg.Port = ln.Addr().(*net.TCPAddr).Port
	cfg.Transport = tlsx.TransportTCP
	cfg.CAFile = caFile
	cfg.IgnoreErrorSet = map[string]bool{"tls_sct_missing": true}

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got, want := result.Report.Status, checkreport.StatusWarning; got != want {
		t.Fatalf("report.Status = %q, want %q", got, want)
	}
	found := false
	for _, finding := range result.Report.Findings {
		if finding.Code == "tls_cipher_weak_supported" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("report.Findings = %#v, want tls_cipher_weak_supported", result.Report.Findings)
	}

	cipherStage := checkreport.StageByID(&result.Report, "cipher.audit")
	if cipherStage == nil {
		t.Fatalf("cipher.audit stage not found")
	}
	if got, want := findStageCheckByID(t, cipherStage.Checks, "cipher.weak_support.probe_set").State, checkreport.CheckPass; got != want {
		t.Fatalf("cipher.weak_support.probe_set state = %q, want %q", got, want)
	}
	if got, want := findStageCheckByID(t, cipherStage.Checks, "cipher.weak_support.probe_errors").State, checkreport.CheckPass; got != want {
		t.Fatalf("cipher.weak_support.probe_errors state = %q, want %q", got, want)
	}
	if got, want := findStageCheckByID(t, cipherStage.Checks, "cipher.weak_support").State, checkreport.CheckWarning; got != want {
		t.Fatalf("cipher.weak_support state = %q, want %q", got, want)
	}
}

func TestIntegrationAnalyzerDetectsNoSNIDivergence(t *testing.T) {
	restoreDNS := stubDNSResolverFactory()
	defer restoreDNS()

	rootPEM, sniCert := mustIssueServerCertificate(t, []string{"localhost"})
	_, defaultCert := mustIssueServerCertificate(t, []string{"default.invalid"})
	caFile := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(caFile, rootPEM, 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	ln := mustSNISwitchingListener(t, defaultCert, sniCert)
	defer ln.Close()
	go serveTLSHandshakes(ln)

	cfg := DefaultConfig()
	cfg.Hostname = "localhost"
	cfg.Port = ln.Addr().(*net.TCPAddr).Port
	cfg.Transport = tlsx.TransportTCP
	cfg.CAFile = caFile
	cfg.IgnoreErrorSet = map[string]bool{"tls_sct_missing": true}

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got, want := result.Report.Status, checkreport.StatusOK; got != want {
		t.Fatalf("report.Status = %q, want %q; findings=%#v", got, want, result.Report.Findings)
	}
	for _, finding := range result.Report.Findings {
		if finding.Code == "tls_sni_profile_differs" || finding.Code == "tls_endpoint_sni_differs" {
			t.Fatalf("report.Findings = %#v, did not expect SNI findings to affect status by default", result.Report.Findings)
		}
	}
	sniStage := checkreport.StageByID(&result.Report, "sni.profile")
	if sniStage == nil {
		t.Fatalf("sni.profile stage not found")
	}
	if got, want := findStageCheckByID(t, sniStage.Checks, "sni.profile").State, checkreport.CheckNote; got != want {
		t.Fatalf("sni.profile state = %q, want %q", got, want)
	}
}

func mustTLSListener(t *testing.T, cert tls.Certificate, nextProtos []string) net.Listener {
	t.Helper()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   nextProtos,
		MinVersion:   tls.VersionTLS12,
		CipherSuites: strongTLS12CipherSuites(),
	})
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("sandbox does not allow local TCP listeners: %v", err)
		}
		t.Fatalf("tls.Listen() error = %v", err)
	}
	return ln
}

func mustTCPListener(t *testing.T) net.Listener {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("sandbox does not allow local TCP listeners: %v", err)
		}
		t.Fatalf("net.Listen() error = %v", err)
	}
	return ln
}

func mustTLS12ListenerWithCipher(t *testing.T, cert tls.Certificate, cipherSuites []uint16) net.Listener {
	t.Helper()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: cipherSuites,
	})
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("sandbox does not allow local TCP listeners: %v", err)
		}
		t.Fatalf("tls.Listen() error = %v", err)
	}
	return ln
}

func mustSNISwitchingListener(t *testing.T, defaultCert, sniCert tls.Certificate) net.Listener {
	t.Helper()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{defaultCert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: strongTLS12CipherSuites(),
		NextProtos:   []string{"http/1.1"},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if hello.ServerName == "localhost" {
				return &tls.Config{
					Certificates: []tls.Certificate{sniCert},
					MinVersion:   tls.VersionTLS12,
					CipherSuites: strongTLS12CipherSuites(),
					NextProtos:   []string{"h2"},
				}, nil
			}
			return &tls.Config{
				Certificates: []tls.Certificate{defaultCert},
				MinVersion:   tls.VersionTLS12,
				CipherSuites: strongTLS12CipherSuites(),
				NextProtos:   []string{"http/1.1"},
			}, nil
		},
	})
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("sandbox does not allow local TCP listeners: %v", err)
		}
		t.Fatalf("tls.Listen() error = %v", err)
	}
	return ln
}

func mustLocalAddrSwitchingTLSListener(t *testing.T, certA, certB tls.Certificate, nextProtos []string) net.Listener {
	t.Helper()

	ln, err := tls.Listen("tcp", "0.0.0.0:0", &tls.Config{
		Certificates: []tls.Certificate{certA},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: strongTLS12CipherSuites(),
		NextProtos:   nextProtos,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			selected := certA
			if hello.Conn != nil {
				host, _, splitErr := net.SplitHostPort(hello.Conn.LocalAddr().String())
				if splitErr == nil && host == "127.0.0.2" {
					selected = certB
				}
			}
			return &tls.Config{
				Certificates: []tls.Certificate{selected},
				MinVersion:   tls.VersionTLS12,
				CipherSuites: strongTLS12CipherSuites(),
				NextProtos:   nextProtos,
			}, nil
		},
	})
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("sandbox does not allow local TCP listeners: %v", err)
		}
		t.Fatalf("tls.Listen() error = %v", err)
	}
	return ln
}

func loopbackAliasLikelyAvailable(addr string) bool {
	ln, err := net.Listen("tcp", net.JoinHostPort(addr, "0"))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

func strongTLS12CipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}
}

func serveTLSHandshakes(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "closed network connection") {
				return
			}
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if tlsConn, ok := conn.(*tls.Conn); ok {
				_ = tlsConn.Handshake()
				return
			}
		}(conn)
	}
}

func serveSMTPSTARTTLS(ln net.Listener, cert tls.Certificate) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "closed network connection") {
				return
			}
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			reader := bufio.NewReader(conn)
			if _, err := io.WriteString(conn, "220 localhost ESMTP ready\r\n"); err != nil {
				return
			}
			line, err := reader.ReadString('\n')
			if err != nil || !strings.HasPrefix(strings.ToUpper(line), "EHLO ") {
				return
			}
			if _, err := io.WriteString(conn, "250-localhost\r\n250-PIPELINING\r\n250 STARTTLS\r\n"); err != nil {
				return
			}
			line, err = reader.ReadString('\n')
			if err != nil || !strings.HasPrefix(strings.ToUpper(line), "STARTTLS") {
				return
			}
			if _, err := io.WriteString(conn, "220 Ready to start TLS\r\n"); err != nil {
				return
			}
			_ = conn.SetDeadline(time.Time{})
			tlsConn := tls.Server(conn, &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
				NextProtos:   []string{"smtp"},
				CipherSuites: strongTLS12CipherSuites(),
			})
			defer tlsConn.Close()
			_ = tlsConn.Handshake()
		}(conn)
	}
}

func stubDNSResolverFactory() func() {
	prev := defaultDNSResolverFactory
	defaultDNSResolverFactory = func(_ time.Duration, _ string, _ ipfamily.Policy) dnsResolver {
		return fakeDNSResolver{}
	}
	return func() {
		defaultDNSResolverFactory = prev
	}
}

func findStageCheckByID(t *testing.T, checks []checkreport.Check, id string) checkreport.Check {
	t.Helper()
	for _, check := range checks {
		if check.ID == id {
			return check
		}
	}
	t.Fatalf("check %q not found in %#v", id, checks)
	return checkreport.Check{}
}

type partialEndpointDNSResolver struct{}

func (partialEndpointDNSResolver) Lookup(_ context.Context, qname string, qtype uint16) (dnsresolver.LookupResult, error) {
	switch qtype {
	case dns.TypeA:
		return dnsresolver.LookupResult{
			QName:    dns.Fqdn(qname),
			QType:    qtype,
			Zone:     dns.Fqdn(qname),
			Security: dnsresolver.SecuritySecure,
			Records: []dns.RR{
				&dns.A{Hdr: dns.RR_Header{Name: dns.Fqdn(qname), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("127.0.0.1")},
				&dns.A{Hdr: dns.RR_Header{Name: dns.Fqdn(qname), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("127.0.0.2")},
			},
			ValidationMessage: "stubbed secure dual-address response",
		}, nil
	case dns.TypeAAAA:
		return dnsresolver.LookupResult{
			QName:               dns.Fqdn(qname),
			QType:               qtype,
			Zone:                dns.Fqdn(qname),
			Security:            dnsresolver.SecuritySecure,
			AuthenticatedNoData: true,
			ValidationMessage:   "stubbed secure negative response",
		}, nil
	}
	return dnsresolver.LookupResult{
		QName:               dns.Fqdn(qname),
		QType:               qtype,
		Zone:                dns.Fqdn(qname),
		Security:            dnsresolver.SecuritySecure,
		AuthenticatedNoData: true,
		ValidationMessage:   "stubbed secure negative response",
	}, nil
}

func (partialEndpointDNSResolver) LookupEffectiveCAA(_ context.Context, qname string) (dnsresolver.EffectiveCAAResult, error) {
	return dnsresolver.EffectiveCAAResult{
		EffectiveName: dns.Fqdn(qname),
		Lookup: dnsresolver.LookupResult{
			QName:               dns.Fqdn(qname),
			QType:               dns.TypeCAA,
			Zone:                dns.Fqdn(qname),
			Security:            dnsresolver.SecuritySecure,
			AuthenticatedNoData: true,
			ValidationMessage:   "stubbed secure negative response",
		},
	}, nil
}

type dualLoopbackDNSResolver struct{}

func (dualLoopbackDNSResolver) Lookup(_ context.Context, qname string, qtype uint16) (dnsresolver.LookupResult, error) {
	switch qtype {
	case dns.TypeA:
		return dnsresolver.LookupResult{
			QName:    dns.Fqdn(qname),
			QType:    qtype,
			Zone:     dns.Fqdn(qname),
			Security: dnsresolver.SecuritySecure,
			Records: []dns.RR{
				&dns.A{Hdr: dns.RR_Header{Name: dns.Fqdn(qname), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("127.0.0.1")},
				&dns.A{Hdr: dns.RR_Header{Name: dns.Fqdn(qname), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("127.0.0.2")},
			},
			ValidationMessage: "stubbed secure dual-loopback response",
		}, nil
	case dns.TypeAAAA:
		return dnsresolver.LookupResult{
			QName:               dns.Fqdn(qname),
			QType:               qtype,
			Zone:                dns.Fqdn(qname),
			Security:            dnsresolver.SecuritySecure,
			AuthenticatedNoData: true,
			ValidationMessage:   "stubbed secure negative response",
		}, nil
	}
	return dnsresolver.LookupResult{
		QName:               dns.Fqdn(qname),
		QType:               qtype,
		Zone:                dns.Fqdn(qname),
		Security:            dnsresolver.SecuritySecure,
		AuthenticatedNoData: true,
		ValidationMessage:   "stubbed secure negative response",
	}, nil
}

func (dualLoopbackDNSResolver) LookupEffectiveCAA(_ context.Context, qname string) (dnsresolver.EffectiveCAAResult, error) {
	return dnsresolver.EffectiveCAAResult{
		EffectiveName: dns.Fqdn(qname),
		Lookup: dnsresolver.LookupResult{
			QName:               dns.Fqdn(qname),
			QType:               dns.TypeCAA,
			Zone:                dns.Fqdn(qname),
			Security:            dnsresolver.SecuritySecure,
			AuthenticatedNoData: true,
			ValidationMessage:   "stubbed secure negative response",
		},
	}, nil
}
