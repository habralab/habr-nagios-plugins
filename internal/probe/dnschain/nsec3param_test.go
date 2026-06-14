package dnschain

import (
	"testing"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/miekg/dns"
)

func TestAssessNSEC3ParamPolicyPassesRecommendedSettings(t *testing.T) {
	rr, err := dns.NewRR("example.com. 300 IN NSEC3PARAM 1 0 0 -")
	if err != nil {
		t.Fatalf("dns.NewRR() error = %v", err)
	}
	param := rr.(*dns.NSEC3PARAM)

	got := assessNSEC3ParamPolicy([]*dns.NSEC3PARAM{param})
	if got.State != checkreport.CheckPass {
		t.Fatalf("State = %q, want pass", got.State)
	}
}

func TestAssessNSEC3ParamPolicyWarnsOnNonRecommendedSettings(t *testing.T) {
	rr, err := dns.NewRR("example.com. 300 IN NSEC3PARAM 1 1 10 ABCD")
	if err != nil {
		t.Fatalf("dns.NewRR() error = %v", err)
	}
	param := rr.(*dns.NSEC3PARAM)

	got := assessNSEC3ParamPolicy([]*dns.NSEC3PARAM{param})
	if got.State != checkreport.CheckWarning {
		t.Fatalf("State = %q, want warning", got.State)
	}
	if len(got.Evidence) == 0 {
		t.Fatal("Evidence = empty, want details")
	}
}

func TestAssessNSEC3ParamPolicyWarnsOnUnsupportedHash(t *testing.T) {
	rr, err := dns.NewRR("example.com. 300 IN NSEC3PARAM 2 0 0 -")
	if err != nil {
		t.Fatalf("dns.NewRR() error = %v", err)
	}
	param := rr.(*dns.NSEC3PARAM)

	got := assessNSEC3ParamPolicy([]*dns.NSEC3PARAM{param})
	if got.State != checkreport.CheckWarning {
		t.Fatalf("State = %q, want warning", got.State)
	}
}
