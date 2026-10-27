package tlsprobe

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/core/dnsresolver"
	"github.com/miekg/dns"
)

func TestEvaluateDANESecureMatch(t *testing.T) {
	_, serverCert := mustIssueServerCertificate(t, []string{"example.com"})
	leaf, err := x509.ParseCertificate(serverCert.Certificate[0])
	if err != nil {
		t.Fatalf("x509.ParseCertificate() error = %v", err)
	}
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	record := &dns.TLSA{
		Hdr:          dns.RR_Header{Name: "_443._tcp.example.com.", Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 300},
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		Certificate:  fmt.Sprintf("%X", sum[:]),
	}

	result := evaluateDANE(dnsresolver.LookupResult{
		QName:    "_443._tcp.example.com.",
		QType:    dns.TypeTLSA,
		Zone:     "example.com.",
		Records:  []dns.RR{record},
		Security: dnsresolver.SecuritySecure,
	}, tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}})

	if result.Finding != nil {
		t.Fatalf("finding = %#v, want nil", result.Finding)
	}
	check := findCheckByID(t, result.Checks, "dns.dane_lookup")
	if got, want := check.State, checkreport.CheckPass; got != want {
		t.Fatalf("dns.dane_lookup state = %q, want %q", got, want)
	}
	matchCheck := findCheckByID(t, result.Checks, "dns.dane.match")
	if got, want := matchCheck.State, checkreport.CheckPass; got != want {
		t.Fatalf("dns.dane.match state = %q, want %q", got, want)
	}
	if got, want := result.Metric, 2.0; got != want {
		t.Fatalf("metric = %v, want %v", got, want)
	}
}

func TestEvaluateAdditionalDANEEndpointsRejectsMismatchingPeer(t *testing.T) {
	_, matchingCert := mustIssueServerCertificate(t, []string{"example.com"})
	matchingLeaf, err := x509.ParseCertificate(matchingCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	_, otherCert := mustIssueServerCertificate(t, []string{"example.com"})
	otherLeaf, err := x509.ParseCertificate(otherCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(matchingLeaf.RawSubjectPublicKeyInfo)
	result := dnsresolver.LookupResult{
		Security: dnsresolver.SecuritySecure,
		Records: []dns.RR{&dns.TLSA{
			Usage: 3, Selector: 1, MatchingType: 1,
			Certificate: fmt.Sprintf("%X", sum[:]),
		}},
	}
	endpoints := []handshakeResult{
		{Endpoint: "192.0.2.1:25", State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{matchingLeaf}}},
		{Endpoint: "[2001:db8::1]:25", State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{otherLeaf}}},
	}
	checks, findings := evaluateAdditionalDANEEndpoints(result, endpoints)
	if len(checks) != 1 || checks[0].Subject != "[2001:db8::1]:25" || checks[0].State != checkreport.CheckCritical {
		t.Fatalf("checks = %#v, want one critical IPv6 endpoint", checks)
	}
	if len(findings) != 1 || findings[0].Code != "tls_dane_mismatch" {
		t.Fatalf("findings = %#v, want one TLSA mismatch", findings)
	}
}

func TestEvaluateDANESecureMismatch(t *testing.T) {
	_, serverCert := mustIssueServerCertificate(t, []string{"example.com"})
	leaf, err := x509.ParseCertificate(serverCert.Certificate[0])
	if err != nil {
		t.Fatalf("x509.ParseCertificate() error = %v", err)
	}
	record := &dns.TLSA{
		Hdr:          dns.RR_Header{Name: "_443._tcp.example.com.", Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 300},
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		Certificate:  "DEADBEEF",
	}

	result := evaluateDANE(dnsresolver.LookupResult{
		QName:    "_443._tcp.example.com.",
		QType:    dns.TypeTLSA,
		Zone:     "example.com.",
		Records:  []dns.RR{record},
		Security: dnsresolver.SecuritySecure,
	}, tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}})

	if result.Finding == nil || result.Finding.Code != "tls_dane_mismatch" {
		t.Fatalf("finding = %#v, want tls_dane_mismatch", result.Finding)
	}
	check := findCheckByID(t, result.Checks, "dns.dane_lookup")
	if got, want := check.State, checkreport.CheckCritical; got != want {
		t.Fatalf("dns.dane_lookup state = %q, want %q", got, want)
	}
	matchCheck := findCheckByID(t, result.Checks, "dns.dane.match")
	if got, want := matchCheck.State, checkreport.CheckCritical; got != want {
		t.Fatalf("dns.dane.match state = %q, want %q", got, want)
	}
	if got, want := result.Metric, 0.0; got != want {
		t.Fatalf("metric = %v, want %v", got, want)
	}
}

func TestEvaluateDANESecureMixedSetPassesWhenAnyRecordMatches(t *testing.T) {
	_, serverCert := mustIssueServerCertificate(t, []string{"example.com"})
	leaf, err := x509.ParseCertificate(serverCert.Certificate[0])
	if err != nil {
		t.Fatalf("x509.ParseCertificate() error = %v", err)
	}
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	mismatch := &dns.TLSA{
		Hdr:          dns.RR_Header{Name: "_443._tcp.example.com.", Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 300},
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		Certificate:  "DEADBEEF",
	}
	match := &dns.TLSA{
		Hdr:          dns.RR_Header{Name: "_443._tcp.example.com.", Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 300},
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		Certificate:  fmt.Sprintf("%X", sum[:]),
	}

	result := evaluateDANE(dnsresolver.LookupResult{
		QName:    "_443._tcp.example.com.",
		QType:    dns.TypeTLSA,
		Zone:     "example.com.",
		Records:  []dns.RR{mismatch, match},
		Security: dnsresolver.SecuritySecure,
	}, tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}})

	if result.Finding != nil {
		t.Fatalf("finding = %#v, want nil", result.Finding)
	}
	check := findCheckByID(t, result.Checks, "dns.dane_lookup")
	if got, want := check.State, checkreport.CheckPass; got != want {
		t.Fatalf("dns.dane_lookup state = %q, want %q", got, want)
	}
	matchCheck := findCheckByID(t, result.Checks, "dns.dane.match")
	if got, want := matchCheck.State, checkreport.CheckPass; got != want {
		t.Fatalf("dns.dane.match state = %q, want %q", got, want)
	}
	if got, want := result.Metric, 2.0; got != want {
		t.Fatalf("metric = %v, want %v", got, want)
	}
	if len(matchCheck.Evidence) != 2 {
		t.Fatalf("len(matchCheck.Evidence) = %d, want 2", len(matchCheck.Evidence))
	}
}

func TestEvaluateCAABogusEmitsDetailedChecksAndFinding(t *testing.T) {
	result := evaluateCAA(dnsresolver.EffectiveCAAResult{
		EffectiveName: "example.com.",
		Lookup: dnsresolver.LookupResult{
			QName:             "example.com.",
			QType:             dns.TypeCAA,
			Zone:              "example.com.",
			Security:          dnsresolver.SecurityBogus,
			ValidationMessage: "RRSIG validation failed",
		},
	}, "example.com")

	if result.Finding == nil || result.Finding.Code != "tls_caa_dnssec_invalid" {
		t.Fatalf("finding = %#v, want tls_caa_dnssec_invalid", result.Finding)
	}
	if got, want := findCheckByID(t, result.Checks, "dns.caa.security").State, checkreport.CheckWarning; got != want {
		t.Fatalf("dns.caa.security state = %q, want %q", got, want)
	}
	if got, want := findCheckByID(t, result.Checks, "dns.caa_lookup").State, checkreport.CheckWarning; got != want {
		t.Fatalf("dns.caa_lookup state = %q, want %q", got, want)
	}
}

func findCheckByID(t *testing.T, checks []checkreport.Check, id string) checkreport.Check {
	t.Helper()
	for _, check := range checks {
		if check.ID == id {
			return check
		}
	}
	t.Fatalf("check %q not found in %#v", id, checks)
	return checkreport.Check{}
}
