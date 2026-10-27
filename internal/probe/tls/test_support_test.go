package tlsprobe

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	x509pkix "crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/dnsresolver"
	"github.com/miekg/dns"
)

type issuedServerCertBundle struct {
	RootPEM  []byte
	RootCert *x509.Certificate
	RootKey  *rsa.PrivateKey
	LeafCert *x509.Certificate
	TLSCert  tls.Certificate
}

func mustIssueServerCertificate(t *testing.T, dnsNames []string) ([]byte, tls.Certificate) {
	t.Helper()

	bundle := mustIssueServerCertificateBundle(t, dnsNames)
	return bundle.RootPEM, bundle.TLSCert
}

func mustIssueServerCertificateBundle(t *testing.T, dnsNames []string) issuedServerCertBundle {
	return mustIssueServerCertificateBundleWithOCSP(t, dnsNames, nil)
}

func mustIssueServerCertificateBundleWithOCSP(t *testing.T, dnsNames []string, ocspServers []string) issuedServerCertBundle {
	t.Helper()

	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(root) error = %v", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: x509pkix.Name{
			CommonName: "check_tls test root",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("x509.CreateCertificate(root) error = %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("x509.ParseCertificate(root) error = %v", err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(leaf) error = %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: x509pkix.Name{
			CommonName: dnsNames[0],
		},
		DNSNames:    dnsNames,
		OCSPServer:  ocspServers,
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(180 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("x509.CreateCertificate(leaf) error = %v", err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	leafKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)})
	cert, err := tls.X509KeyPair(leafPEM, leafKeyPEM)
	if err != nil {
		t.Fatalf("tls.X509KeyPair() error = %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("x509.ParseCertificate(leaf) error = %v", err)
	}
	cert.Certificate = [][]byte{leafDER, rootDER}
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	return issuedServerCertBundle{
		RootPEM:  rootPEM,
		RootCert: rootCert,
		RootKey:  rootKey,
		LeafCert: leafCert,
		TLSCert:  cert,
	}
}

type fakeDNSResolver struct{}

func (fakeDNSResolver) Lookup(_ context.Context, qname string, qtype uint16) (dnsresolver.LookupResult, error) {
	switch qtype {
	case dns.TypeA:
		return dnsresolver.LookupResult{
			QName:    dns.Fqdn(qname),
			QType:    qtype,
			Zone:     dns.Fqdn(qname),
			Security: dnsresolver.SecuritySecure,
			Records: []dns.RR{
				&dns.A{Hdr: dns.RR_Header{Name: dns.Fqdn(qname), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("127.0.0.1")},
			},
			ValidationMessage: "stubbed secure address response",
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

func (fakeDNSResolver) LookupEffectiveCAA(_ context.Context, qname string) (dnsresolver.EffectiveCAAResult, error) {
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

type cnameDNSResolver struct{}

func (cnameDNSResolver) Lookup(_ context.Context, qname string, qtype uint16) (dnsresolver.LookupResult, error) {
	fqdn := dns.Fqdn(qname)
	switch {
	case fqdn == "www.wikipedia.org." && qtype == dns.TypeA:
		return dnsresolver.LookupResult{QName: fqdn, QType: qtype, Zone: "wikipedia.org.", Security: dnsresolver.SecurityInsecure}, nil
	case fqdn == "www.wikipedia.org." && qtype == dns.TypeAAAA:
		return dnsresolver.LookupResult{QName: fqdn, QType: qtype, Zone: "wikipedia.org.", Security: dnsresolver.SecurityInsecure}, nil
	case fqdn == "www.wikipedia.org." && qtype == dns.TypeCNAME:
		return dnsresolver.LookupResult{
			QName:    fqdn,
			QType:    qtype,
			Zone:     "wikipedia.org.",
			Security: dnsresolver.SecurityInsecure,
			Records: []dns.RR{
				&dns.CNAME{Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "dyna.wikimedia.org."},
			},
		}, nil
	case fqdn == "dyna.wikimedia.org." && qtype == dns.TypeA:
		return dnsresolver.LookupResult{
			QName:    fqdn,
			QType:    qtype,
			Zone:     "wikimedia.org.",
			Security: dnsresolver.SecurityInsecure,
			Records: []dns.RR{
				&dns.A{Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("185.15.59.224")},
			},
		}, nil
	default:
		return dnsresolver.LookupResult{QName: fqdn, QType: qtype, Zone: fqdn, Security: dnsresolver.SecurityInsecure}, nil
	}
}

func (cnameDNSResolver) LookupEffectiveCAA(_ context.Context, qname string) (dnsresolver.EffectiveCAAResult, error) {
	return dnsresolver.EffectiveCAAResult{EffectiveName: dns.Fqdn(qname), Lookup: dnsresolver.LookupResult{QName: dns.Fqdn(qname), QType: dns.TypeCAA, Zone: dns.Fqdn(qname), Security: dnsresolver.SecurityInsecure}}, nil
}
