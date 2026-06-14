package dnschain

import (
	"testing"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/miekg/dns"
)

func TestDNSKEYSetFingerprintOrderIndependent(t *testing.T) {
	k1, _ := dns.NewRR("example.com. 300 IN DNSKEY 257 3 13 AAAA")
	k2, _ := dns.NewRR("example.com. 300 IN DNSKEY 256 3 13 BBBB")

	a := dnskeySetFingerprint([]*dns.DNSKEY{k1.(*dns.DNSKEY), k2.(*dns.DNSKEY)})
	b := dnskeySetFingerprint([]*dns.DNSKEY{k2.(*dns.DNSKEY), k1.(*dns.DNSKEY)})
	if a != b {
		t.Fatalf("dnskeySetFingerprint() order-dependent: %q != %q", a, b)
	}
}

func TestDSSetFingerprintOrderIndependent(t *testing.T) {
	d1, _ := dns.NewRR("example.com. 300 IN DS 12345 13 2 AAAA")
	d2, _ := dns.NewRR("example.com. 300 IN DS 23456 13 2 BBBB")

	a := dsSetFingerprint([]*dns.DS{d1.(*dns.DS), d2.(*dns.DS)})
	b := dsSetFingerprint([]*dns.DS{d2.(*dns.DS), d1.(*dns.DS)})
	if a != b {
		t.Fatalf("dsSetFingerprint() order-dependent: %q != %q", a, b)
	}
}

func TestCheckStateFromFinding(t *testing.T) {
	findings := []checkreport.Finding{{Code: "x", Severity: checkreport.StatusWarning}}
	if got, want := checkStateFromFinding(findings, "x"), checkreport.CheckWarning; got != want {
		t.Fatalf("checkStateFromFinding() = %q, want %q", got, want)
	}
	if got, want := checkStateFromFinding(findings, "y"), checkreport.CheckPass; got != want {
		t.Fatalf("checkStateFromFinding() = %q, want %q", got, want)
	}
}
