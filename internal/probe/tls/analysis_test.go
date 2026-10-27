package tlsprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	x509pkix "crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/core/dnsresolver"
	"github.com/habralab/habr-nagios-plugins/internal/core/ipfamily"
	"github.com/habralab/habr-nagios-plugins/internal/core/pkix"
	"github.com/miekg/dns"
	"golang.org/x/crypto/ocsp"
)

func TestEvaluateOCSPMissingIsInformational(t *testing.T) {
	assessment := evaluateOCSP(context.Background(), DefaultConfig(), "example.com:443", "example.com", fakeDNSResolver{}, tls.ConnectionState{})
	if assessment.Check.State != checkreport.CheckNote {
		t.Fatalf("check.State = %q, want %q", assessment.Check.State, checkreport.CheckNote)
	}
	if assessment.Finding != nil {
		t.Fatalf("finding = %#v, want nil", assessment.Finding)
	}
	if assessment.Metric.Value != "0" {
		t.Fatalf("metric.Value = %q, want %q", assessment.Metric.Value, "0")
	}
}

func TestEvaluateOCSPDetailedEmitsAtomicChecks(t *testing.T) {
	details := evaluateOCSPDetailed(context.Background(), DefaultConfig(), "example.com:443", "example.com", fakeDNSResolver{}, tls.ConnectionState{})
	if len(details.Checks) != 4 {
		t.Fatalf("len(details.Checks) = %d, want 4", len(details.Checks))
	}
	wantIDs := []string{
		"revocation.ocsp.policy",
		"revocation.ocsp.source.stapled",
		"revocation.ocsp.source.responder",
		"revocation.ocsp",
	}
	for i, want := range wantIDs {
		if details.Checks[i].ID != want {
			t.Fatalf("details.Checks[%d].ID = %q, want %q", i, details.Checks[i].ID, want)
		}
	}
}

func TestEvaluateOCSPPresentPasses(t *testing.T) {
	bundle := mustIssueServerCertificateBundle(t, []string{"example.com"})
	response, err := ocsp.CreateResponse(bundle.RootCert, bundle.RootCert, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: bundle.LeafCert.SerialNumber,
		ThisUpdate:   time.Now().Add(-time.Minute),
		NextUpdate:   time.Now().Add(time.Hour),
	}, bundle.RootKey)
	if err != nil {
		t.Fatalf("ocsp.CreateResponse() error = %v", err)
	}

	assessment := evaluateOCSP(context.Background(), DefaultConfig(), "example.com:443", "example.com", fakeDNSResolver{}, tls.ConnectionState{
		OCSPResponse:     response,
		PeerCertificates: []*x509.Certificate{bundle.LeafCert, bundle.RootCert},
	})
	if assessment.Check.State != checkreport.CheckPass {
		t.Fatalf("check.State = %q, want %q", assessment.Check.State, checkreport.CheckPass)
	}
	if assessment.Finding != nil {
		t.Fatalf("finding = %#v, want nil", assessment.Finding)
	}
	if assessment.Metric.Value != "1" {
		t.Fatalf("metric.Value = %q, want %q", assessment.Metric.Value, "1")
	}
}

func TestEvaluateOCSPInvalidWarns(t *testing.T) {
	bundle := mustIssueServerCertificateBundle(t, []string{"example.com"})
	assessment := evaluateOCSP(context.Background(), DefaultConfig(), "example.com:443", "example.com", fakeDNSResolver{}, tls.ConnectionState{
		OCSPResponse:     []byte{1, 2, 3},
		PeerCertificates: []*x509.Certificate{bundle.LeafCert, bundle.RootCert},
	})
	if assessment.Check.State != checkreport.CheckWarning {
		t.Fatalf("check.State = %q, want %q", assessment.Check.State, checkreport.CheckWarning)
	}
	if assessment.Finding == nil || assessment.Finding.Code != "tls_ocsp_stapling_invalid" {
		t.Fatalf("finding = %#v, want tls_ocsp_stapling_invalid", assessment.Finding)
	}
	if assessment.Metric.Value != "0" {
		t.Fatalf("metric.Value = %q, want %q", assessment.Metric.Value, "0")
	}
}

func TestEvaluateOCSPRevokedIsCritical(t *testing.T) {
	bundle := mustIssueServerCertificateBundle(t, []string{"example.com"})
	response, err := ocsp.CreateResponse(bundle.RootCert, bundle.RootCert, ocsp.Response{
		Status:       ocsp.Revoked,
		SerialNumber: bundle.LeafCert.SerialNumber,
		ThisUpdate:   time.Now().Add(-time.Minute),
		NextUpdate:   time.Now().Add(time.Hour),
		RevokedAt:    time.Now().Add(-time.Hour),
	}, bundle.RootKey)
	if err != nil {
		t.Fatalf("ocsp.CreateResponse() error = %v", err)
	}

	assessment := evaluateOCSP(context.Background(), DefaultConfig(), "example.com:443", "example.com", fakeDNSResolver{}, tls.ConnectionState{
		OCSPResponse:     response,
		PeerCertificates: []*x509.Certificate{bundle.LeafCert, bundle.RootCert},
	})
	if assessment.Check.State != checkreport.CheckCritical {
		t.Fatalf("check.State = %q, want %q", assessment.Check.State, checkreport.CheckCritical)
	}
	if assessment.Finding == nil || assessment.Finding.Code != "tls_ocsp_stapling_revoked" {
		t.Fatalf("finding = %#v, want tls_ocsp_stapling_revoked", assessment.Finding)
	}
	if assessment.Metric.Value != "0" {
		t.Fatalf("metric.Value = %q, want %q", assessment.Metric.Value, "0")
	}
}

func TestEvaluateSCTPassesWhenDeliveredViaTLS(t *testing.T) {
	policy := ctPolicy{Required: true, Reason: "certificate chain validated against system roots"}
	assessment := evaluateSCT("example.com:443", tls.ConnectionState{
		SignedCertificateTimestamps: [][]byte{{1, 2, 3}},
	}, policy)
	check := assessment.Checks[len(assessment.Checks)-1]
	if check.State != checkreport.CheckPass {
		t.Fatalf("check.State = %q, want %q", check.State, checkreport.CheckPass)
	}
	if assessment.Finding != nil {
		t.Fatalf("finding = %#v, want nil", assessment.Finding)
	}
	if !strings.Contains(check.Message, "tls") {
		t.Fatalf("check.Message = %q, want tls source note", check.Message)
	}
}

func TestEvaluateSCTPassesWhenEmbeddedInCertificate(t *testing.T) {
	policy := ctPolicy{Required: true, Reason: "certificate chain validated against system roots"}
	assessment := evaluateSCT("example.com:443", tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{
				Extensions: []x509pkix.Extension{
					{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}, Value: []byte{1}},
				},
			},
		},
	}, policy)
	check := assessment.Checks[len(assessment.Checks)-1]
	if check.State != checkreport.CheckPass {
		t.Fatalf("check.State = %q, want %q", check.State, checkreport.CheckPass)
	}
	if assessment.Finding != nil {
		t.Fatalf("finding = %#v, want nil", assessment.Finding)
	}
	if !strings.Contains(check.Message, "certificate") {
		t.Fatalf("check.Message = %q, want certificate source note", check.Message)
	}
}

func TestEvaluateSCTPassesWhenProvidedViaOCSP(t *testing.T) {
	policy := ctPolicy{Required: true, Reason: "certificate chain validated against system roots"}
	assessment := evaluateSCT("example.com:443", tls.ConnectionState{}, policy, ocspAssessment{
		Status: "good",
		Source: "stapled",
		Parsed: &ocsp.Response{
			Extensions: []x509pkix.Extension{
				{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 5}, Value: []byte{1}},
			},
		},
	})
	check := assessment.Checks[len(assessment.Checks)-1]
	if check.State != checkreport.CheckPass {
		t.Fatalf("check.State = %q, want %q", check.State, checkreport.CheckPass)
	}
	if assessment.Finding != nil {
		t.Fatalf("finding = %#v, want nil", assessment.Finding)
	}
	if !strings.Contains(check.Message, "stapled") {
		t.Fatalf("check.Message = %q, want stapled source note", check.Message)
	}
}

func TestEvaluateSCTPassesWhenStapledOCSPContainsSCT(t *testing.T) {
	bundle := mustIssueServerCertificateBundle(t, []string{"example.com"})
	response, err := ocsp.CreateResponse(bundle.RootCert, bundle.RootCert, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: bundle.LeafCert.SerialNumber,
		ThisUpdate:   time.Now().Add(-time.Minute),
		NextUpdate:   time.Now().Add(time.Hour),
		ExtraExtensions: []x509pkix.Extension{
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 5}, Value: []byte{1}},
		},
	}, bundle.RootKey)
	if err != nil {
		t.Fatalf("ocsp.CreateResponse() error = %v", err)
	}

	policy := ctPolicy{Required: true, Reason: "certificate chain validated against system roots"}
	assessment := evaluateSCT("example.com:443", tls.ConnectionState{
		OCSPResponse:     response,
		PeerCertificates: []*x509.Certificate{bundle.LeafCert, bundle.RootCert},
	}, policy)
	check := assessment.Checks[len(assessment.Checks)-1]
	if check.State != checkreport.CheckPass {
		t.Fatalf("check.State = %q, want %q", check.State, checkreport.CheckPass)
	}
	if assessment.Finding != nil {
		t.Fatalf("finding = %#v, want nil", assessment.Finding)
	}
	if !strings.Contains(check.Message, "stapled") {
		t.Fatalf("check.Message = %q, want stapled source note", check.Message)
	}
}

func TestEvaluateSCTWarnsWhenMissingEverywhere(t *testing.T) {
	policy := ctPolicy{Required: true, Reason: "certificate chain validated against system roots"}
	assessment := evaluateSCT("example.com:443", tls.ConnectionState{}, policy)
	check := assessment.Checks[len(assessment.Checks)-1]
	if check.State != checkreport.CheckWarning {
		t.Fatalf("check.State = %q, want %q", check.State, checkreport.CheckWarning)
	}
	if assessment.Finding == nil || assessment.Finding.Code != "tls_sct_missing" {
		t.Fatalf("finding = %#v, want tls_sct_missing", assessment.Finding)
	}
}

func TestBuildEndpointSemanticsStageWarnsOnPKIDivergence(t *testing.T) {
	bundleA := mustIssueServerCertificateBundle(t, []string{"localhost"})
	bundleB := mustIssueServerCertificateBundle(t, []string{"localhost"})

	roots := x509.NewCertPool()
	for _, pemBundle := range [][]byte{bundleA.RootPEM, bundleB.RootPEM} {
		if ok := roots.AppendCertsFromPEM(pemBundle); !ok {
			t.Fatalf("AppendCertsFromPEM() returned false")
		}
	}

	cfg := DefaultConfig()
	cfg.STARTTLS = "smtp"

	successful := []handshakeResult{
		{
			Endpoint: "127.0.0.1:443",
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{bundleA.LeafCert, bundleA.RootCert},
			},
		},
		{
			Endpoint: "127.0.0.2:443",
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{bundleB.LeafCert, bundleB.RootCert},
			},
		},
	}
	stage, findings := buildEndpointSemanticsStage(context.Background(), cfg, "localhost", "localhost:443", fakeDNSResolver{}, roots, "system roots", nil, successful[0], successful)

	if got, want := findCheckByID(t, stage.Checks, "endpoint_semantics.pki").State, checkreport.CheckWarning; got != want {
		t.Fatalf("endpoint_semantics.pki state = %q, want %q", got, want)
	}
	found := false
	for _, finding := range findings {
		if finding.Code == "tls_endpoint_pki_differs" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("findings = %#v, want tls_endpoint_pki_differs", findings)
	}
	profilesCheck := findCheckByID(t, stage.Checks, "endpoint_semantics.profiles")
	if got, want := len(profilesCheck.Evidence), 1; got != want {
		t.Fatalf("len(profilesCheck.Evidence) = %d, want %d", got, want)
	}
	if got, want := len(profilesCheck.Evidence[0].Items), 2; got != want {
		t.Fatalf("len(profilesCheck.Evidence[0].Items) = %d, want %d", got, want)
	}
	if profilesCheck.Evidence[0].Items[0].Subject == "" {
		t.Fatal("profilesCheck first item subject = empty, want endpoint")
	}
	if !containsKV(profilesCheck.Evidence[0].Items[0].Attributes, "ct.status", "required_missing") &&
		!containsKV(profilesCheck.Evidence[0].Items[0].Attributes, "ct.status", "not_required_absent") &&
		!containsKV(profilesCheck.Evidence[0].Items[0].Attributes, "ct.status", "present") {
		t.Fatalf("profilesCheck first item attributes = %#v, want ct.status", profilesCheck.Evidence[0].Items[0].Attributes)
	}
}

func TestBuildEndpointSemanticsStageWarnsOnTransportDivergence(t *testing.T) {
	cfg := DefaultConfig()
	cfg.STARTTLS = "smtp"

	successful := []handshakeResult{
		{
			Endpoint: "127.0.0.1:443",
			State: tls.ConnectionState{
				Version:            tls.VersionTLS13,
				CipherSuite:        tls.TLS_AES_128_GCM_SHA256,
				NegotiatedProtocol: "h2",
			},
		},
		{
			Endpoint: "127.0.0.2:443",
			State: tls.ConnectionState{
				Version:            tls.VersionTLS12,
				CipherSuite:        tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				NegotiatedProtocol: "http/1.1",
			},
		},
	}
	stage, findings := buildEndpointSemanticsStage(context.Background(), cfg, "localhost", "localhost:443", fakeDNSResolver{}, nil, "", nil, successful[0], successful)

	if got, want := findCheckByID(t, stage.Checks, "endpoint_semantics.transport").State, checkreport.CheckWarning; got != want {
		t.Fatalf("endpoint_semantics.transport state = %q, want %q", got, want)
	}
	found := false
	for _, finding := range findings {
		if finding.Code == "tls_endpoint_transport_differs" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("findings = %#v, want tls_endpoint_transport_differs", findings)
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

func findEvidenceItemByID(t *testing.T, items []checkreport.EvidenceItem, id string) checkreport.EvidenceItem {
	t.Helper()
	for _, item := range items {
		if item.ID == id {
			return item
		}
	}
	t.Fatalf("evidence item %q not found", id)
	return checkreport.EvidenceItem{}
}

func syntheticPKIGraphCert(subjectCN, issuerCN string, isCA bool, serial int64) *x509.Certificate {
	now := time.Now().UTC()
	return &x509.Certificate{
		Raw:          []byte(fmt.Sprintf("%s|%s|%d|%t", subjectCN, issuerCN, serial, isCA)),
		SerialNumber: big.NewInt(serial),
		Subject:      x509pkix.Name{CommonName: subjectCN},
		Issuer:       x509pkix.Name{CommonName: issuerCN},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		IsCA:         isCA,
	}
}

func TestEvaluateSCTNotesWhenNotRequired(t *testing.T) {
	policy := ctPolicy{Required: false, Reason: "custom trust anchors were configured"}
	assessment := evaluateSCT("example.com:443", tls.ConnectionState{}, policy)
	check := assessment.Checks[len(assessment.Checks)-1]
	if check.State != checkreport.CheckNote {
		t.Fatalf("check.State = %q, want %q", check.State, checkreport.CheckNote)
	}
	if assessment.Finding != nil {
		t.Fatalf("finding = %#v, want nil", assessment.Finding)
	}
	if !strings.Contains(check.Message, "not required") {
		t.Fatalf("check.Message = %q, want non-required note", check.Message)
	}
}

func TestDetermineCTPolicyRequiresCTForSystemTrustedChains(t *testing.T) {
	policy := determineCTPolicy(DefaultConfig(), "system roots", nil, chainAssessment{
		TrustState:  chainTrustTrusted,
		Description: "certificate chain validated through 1 trust path(s)",
	})
	if !policy.Required {
		t.Fatalf("policy.Required = false, want true (%#v)", policy)
	}
}

func TestDetermineCTPolicySkipsCTForCustomTrustAnchors(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CAFile = "/tmp/custom-ca.pem"
	policy := determineCTPolicy(cfg, "system roots+custom-ca.pem", nil, chainAssessment{
		TrustState:  chainTrustTrusted,
		Description: "certificate chain validated through 1 trust path(s)",
	})
	if policy.Required {
		t.Fatalf("policy.Required = true, want false (%#v)", policy)
	}
	if !strings.Contains(policy.Reason, "custom trust anchors") {
		t.Fatalf("policy.Reason = %q, want custom trust anchors note", policy.Reason)
	}
}

func TestEvaluateLeafAndChainTrustedEmitsDetailedChecks(t *testing.T) {
	bundle := mustIssueServerCertificateBundle(t, []string{"example.com"})
	roots := x509.NewCertPool()
	roots.AddCert(bundle.RootCert)
	cfg := DefaultConfig()
	cfg.WarnExpiryDays = 0

	checks, findings, assessment := evaluateLeafAndChain(cfg, "example.com", "example.com:443", roots, []*x509.Certificate{bundle.LeafCert, bundle.RootCert})
	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none", findings)
	}
	if got, want := assessment.TrustState, chainTrustTrusted; got != want {
		t.Fatalf("assessment.TrustState = %q, want %q", got, want)
	}
	if got, want := findCheckByID(t, checks, "pki.chain.presented").State, checkreport.CheckPass; got != want {
		t.Fatalf("pki.chain.presented state = %q, want %q", got, want)
	}
	if got, want := findCheckByID(t, checks, "pki.chain.policy").State, checkreport.CheckPass; got != want {
		t.Fatalf("pki.chain.policy state = %q, want %q", got, want)
	}
	if got, want := findCheckByID(t, checks, "pki.chain.verify").State, checkreport.CheckPass; got != want {
		t.Fatalf("pki.chain.verify state = %q, want %q", got, want)
	}
	if got, want := findCheckByID(t, checks, "pki.chain").State, checkreport.CheckPass; got != want {
		t.Fatalf("pki.chain state = %q, want %q", got, want)
	}
	graphCheck := findCheckByID(t, checks, "pki.graph")
	if got, want := graphCheck.State, checkreport.CheckPass; got != want {
		t.Fatalf("pki.graph state = %q, want %q", got, want)
	}
	if got, want := len(graphCheck.Evidence), 1; got != want {
		t.Fatalf("len(pki.graph evidence) = %d, want %d", got, want)
	}
	if got, want := graphCheck.Evidence[0].Kind, "pki_graph"; got != want {
		t.Fatalf("pki.graph evidence kind = %q, want %q", got, want)
	}
	if len(graphCheck.Evidence[0].Items) < 3 {
		t.Fatalf("len(pki.graph items) = %d, want at least 3", len(graphCheck.Evidence[0].Items))
	}
	if !containsKV(graphCheck.Evidence[0].Attributes, "verified_path_count", "1") {
		t.Fatalf("pki.graph attributes = %#v, want verified_path_count=1", graphCheck.Evidence[0].Attributes)
	}
	if !containsKV(graphCheck.Evidence[0].Attributes, "scope", "primary_endpoint") {
		t.Fatalf("pki.graph attributes = %#v, want scope=primary_endpoint", graphCheck.Evidence[0].Attributes)
	}
	leafNode := findEvidenceItemByID(t, graphCheck.Evidence[0].Items, "cert:"+shortFingerprint(bundle.LeafCert.Raw))
	if !containsKV(leafNode.Attributes, "classification", "presented_and_verified") {
		t.Fatalf("leaf node attributes = %#v, want classification=presented_and_verified", leafNode.Attributes)
	}
}

func TestEvaluateLeafAndChainUntrustedRootWarningEmitsDetailedChecks(t *testing.T) {
	bundle := mustIssueServerCertificateBundle(t, []string{"example.com"})
	cfg := DefaultConfig()
	cfg.PolicyUntrustedRoot = pkix.UntrustedRootWarning
	cfg.WarnExpiryDays = 0

	checks, findings, assessment := evaluateLeafAndChain(cfg, "example.com", "example.com:443", x509.NewCertPool(), []*x509.Certificate{bundle.LeafCert, bundle.RootCert})
	if got, want := assessment.TrustState, chainTrustUntrusted; got != want {
		t.Fatalf("assessment.TrustState = %q, want %q", got, want)
	}
	if got, want := findCheckByID(t, checks, "pki.chain.policy").State, checkreport.CheckPass; got != want {
		t.Fatalf("pki.chain.policy state = %q, want %q", got, want)
	}
	if got, want := findCheckByID(t, checks, "pki.chain.verify").State, checkreport.CheckWarning; got != want {
		t.Fatalf("pki.chain.verify state = %q, want %q", got, want)
	}
	if got, want := findCheckByID(t, checks, "pki.chain").State, checkreport.CheckWarning; got != want {
		t.Fatalf("pki.chain state = %q, want %q", got, want)
	}
	found := false
	for _, finding := range findings {
		if finding.Code == "tls_untrusted_root_policy_degraded" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("findings = %#v, want tls_untrusted_root_policy_degraded", findings)
	}
}

func TestEvaluateLeafAndChainIncompleteChainEmitsDetailedChecks(t *testing.T) {
	bundle := mustIssueServerCertificateBundle(t, []string{"example.com"})
	cfg := DefaultConfig()
	cfg.WarnExpiryDays = 0

	checks, findings, assessment := evaluateLeafAndChain(cfg, "example.com", "example.com:443", x509.NewCertPool(), []*x509.Certificate{bundle.LeafCert})
	if got, want := assessment.TrustState, chainTrustInvalid; got != want {
		t.Fatalf("assessment.TrustState = %q, want %q", got, want)
	}
	if got, want := findCheckByID(t, checks, "pki.chain.presented").State, checkreport.CheckPass; got != want {
		t.Fatalf("pki.chain.presented state = %q, want %q", got, want)
	}
	if got, want := findCheckByID(t, checks, "pki.chain.verify").State, checkreport.CheckCritical; got != want {
		t.Fatalf("pki.chain.verify state = %q, want %q", got, want)
	}
	if got, want := findCheckByID(t, checks, "pki.chain").State, checkreport.CheckCritical; got != want {
		t.Fatalf("pki.chain state = %q, want %q", got, want)
	}
	found := false
	for _, finding := range findings {
		if finding.Code == "tls_chain_incomplete" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("findings = %#v, want tls_chain_incomplete", findings)
	}
	graphCheck := findCheckByID(t, checks, "pki.graph")
	if got, want := graphCheck.State, checkreport.CheckNote; got != want {
		t.Fatalf("pki.graph state = %q, want %q", got, want)
	}
	if !containsKV(graphCheck.Evidence[0].Attributes, "verified_path_count", "0") {
		t.Fatalf("pki.graph attributes = %#v, want verified_path_count=0", graphCheck.Evidence[0].Attributes)
	}
	if !containsKV(graphCheck.Evidence[0].Attributes, "presented_only_count", "1") {
		t.Fatalf("pki.graph attributes = %#v, want presented_only_count=1", graphCheck.Evidence[0].Attributes)
	}
}

func TestBuildPKIGraphEvidenceMarksPresentedTailAndVerifiedOnlyAnchor(t *testing.T) {
	leaf := syntheticPKIGraphCert("leaf.example", "issuer-a", false, 10)
	intermediate := syntheticPKIGraphCert("issuer-a", "root-a", true, 11)
	presentedTail := syntheticPKIGraphCert("old-root", "old-root", true, 12)
	verifiedAnchor := syntheticPKIGraphCert("new-root", "new-root", true, 13)

	graph := buildPKIGraphEvidence(
		[]*x509.Certificate{leaf, intermediate, presentedTail},
		[][]*x509.Certificate{{leaf, intermediate, verifiedAnchor}},
		chainTrustTrusted,
	)

	if !containsKV(graph.Attributes, "presented_tail_count", "1") {
		t.Fatalf("graph attributes = %#v, want presented_tail_count=1", graph.Attributes)
	}
	if !containsKV(graph.Attributes, "has_presented_tail", "true") {
		t.Fatalf("graph attributes = %#v, want has_presented_tail=true", graph.Attributes)
	}
	if !containsKV(graph.Attributes, "verified_only_count", "1") {
		t.Fatalf("graph attributes = %#v, want verified_only_count=1", graph.Attributes)
	}

	tailNode := findEvidenceItemByID(t, graph.Items, "cert:"+shortFingerprint(presentedTail.Raw))
	if !containsKV(tailNode.Attributes, "classification", "presented_only") {
		t.Fatalf("tail node attributes = %#v, want classification=presented_only", tailNode.Attributes)
	}
	if !containsKV(tailNode.Attributes, "presented_tail", "true") {
		t.Fatalf("tail node attributes = %#v, want presented_tail=true", tailNode.Attributes)
	}

	anchorNode := findEvidenceItemByID(t, graph.Items, "cert:"+shortFingerprint(verifiedAnchor.Raw))
	if !containsKV(anchorNode.Attributes, "classification", "verified_only") {
		t.Fatalf("anchor node attributes = %#v, want classification=verified_only", anchorNode.Attributes)
	}
	if !containsKV(anchorNode.Attributes, "is_trust_anchor", "true") {
		t.Fatalf("anchor node attributes = %#v, want is_trust_anchor=true", anchorNode.Attributes)
	}
}

func TestAggregateSummaryUsesExplicitHandshakeDuration(t *testing.T) {
	summary := aggregateSummary(checkreport.Report{}, "example.com:443", 128, 74, true)
	if got, want := summary, "certificate expires in 74 days, handshake=128ms"; got != want {
		t.Fatalf("aggregateSummary() = %q, want %q", got, want)
	}
}

func TestFormatDeprecatedProbeDetailedSuccessEmitsAtomicChecks(t *testing.T) {
	assessment := formatDeprecatedProbeDetailed("example.com:443", deprecatedProbeResult{
		Version: tls.VersionTLS10,
		Success: true,
	})

	if got, want := findCheckByID(t, assessment.Checks, "protocol.tls_1.0.policy").State, checkreport.CheckPass; got != want {
		t.Fatalf("protocol.tls_1.0.policy state = %q, want %q", got, want)
	}
	if got, want := findCheckByID(t, assessment.Checks, "protocol.tls_1.0.probe_errors").State, checkreport.CheckPass; got != want {
		t.Fatalf("protocol.tls_1.0.probe_errors state = %q, want %q", got, want)
	}
	if got, want := findCheckByID(t, assessment.Checks, "protocol.tls_1.0").State, checkreport.CheckCritical; got != want {
		t.Fatalf("protocol.tls_1.0 state = %q, want %q", got, want)
	}
}

func TestFormatDeprecatedProbeDetailedTimeoutKeepsTransportErrorsVisible(t *testing.T) {
	assessment := formatDeprecatedProbeDetailed("example.com:443", deprecatedProbeResult{
		Version: tls.VersionTLS11,
		Err:     context.DeadlineExceeded,
		Errors:  []string{"192.0.2.10:443: context deadline exceeded"},
	})

	if got, want := findCheckByID(t, assessment.Checks, "protocol.tls_1.1.policy").State, checkreport.CheckPass; got != want {
		t.Fatalf("protocol.tls_1.1.policy state = %q, want %q", got, want)
	}
	if got, want := findCheckByID(t, assessment.Checks, "protocol.tls_1.1.probe_errors").State, checkreport.CheckNote; got != want {
		t.Fatalf("protocol.tls_1.1.probe_errors state = %q, want %q", got, want)
	}
	if got, want := findCheckByID(t, assessment.Checks, "protocol.tls_1.1").State, checkreport.CheckNote; got != want {
		t.Fatalf("protocol.tls_1.1 state = %q, want %q", got, want)
	}
}

func TestResolveServiceAddressesFollowsCNAME(t *testing.T) {
	got, err := resolveServiceAddresses(context.Background(), DefaultConfig(), "www.wikipedia.org", cnameDNSResolver{})
	if err != nil {
		t.Fatalf("resolveServiceAddresses() error = %v", err)
	}
	if len(got.Endpoints) != 1 || got.Endpoints[0] != "185.15.59.224:443" {
		t.Fatalf("Endpoints = %#v, want [185.15.59.224:443]", got.Endpoints)
	}
}

func TestResolveServiceAddressesAutoPolicyFiltersUnavailableIPv6Family(t *testing.T) {
	origDetect := detectTransportFamilyCapabilities
	defer func() { detectTransportFamilyCapabilities = origDetect }()
	detectTransportFamilyCapabilities = func(_ context.Context, _ time.Duration) ipfamily.Capabilities {
		return ipfamily.Capabilities{IPv4: true, IPv6: false}
	}

	cfg := DefaultConfig()
	cfg.TransportFamilyPolicy = ipfamily.PolicyAuto
	got, err := resolveServiceAddresses(context.Background(), cfg, "example.test", dualAddressDNSResolver{})
	if err != nil {
		t.Fatalf("resolveServiceAddresses() error = %v", err)
	}
	if len(got.Endpoints) != 2 || got.Endpoints[0] != "127.0.0.1:443" || got.Endpoints[1] != "127.0.0.2:443" {
		t.Fatalf("Endpoints = %#v, want only IPv4 loopback endpoints", got.Endpoints)
	}
}

type dualAddressDNSResolver struct{}

func (dualAddressDNSResolver) Lookup(_ context.Context, qname string, qtype uint16) (dnsresolver.LookupResult, error) {
	switch qtype {
	case dns.TypeA:
		return dnsresolver.LookupResult{
			QName: dns.Fqdn(qname),
			QType: qtype,
			Records: []dns.RR{
				&dns.A{Hdr: dns.RR_Header{Name: dns.Fqdn(qname), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("127.0.0.1")},
				&dns.A{Hdr: dns.RR_Header{Name: dns.Fqdn(qname), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("127.0.0.2")},
			},
		}, nil
	case dns.TypeAAAA:
		return dnsresolver.LookupResult{
			QName: dns.Fqdn(qname),
			QType: qtype,
			Records: []dns.RR{
				&dns.AAAA{Hdr: dns.RR_Header{Name: dns.Fqdn(qname), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300}, AAAA: net.ParseIP("2001:db8::10")},
			},
		}, nil
	default:
		return dnsresolver.LookupResult{}, nil
	}
}

func (dualAddressDNSResolver) LookupEffectiveCAA(_ context.Context, qname string) (dnsresolver.EffectiveCAAResult, error) {
	return dnsresolver.EffectiveCAAResult{
		EffectiveName: dns.Fqdn(qname),
		Lookup: dnsresolver.LookupResult{
			QName: dns.Fqdn(qname),
			QType: dns.TypeCAA,
		},
	}, nil
}
