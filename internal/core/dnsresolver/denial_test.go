package dnsresolver

import (
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestValidateNoDSProofPatternNSECExact(t *testing.T) {
	rr, err := dns.NewRR("example.org. 300 IN NSEC zzz.example.org. NS RRSIG NSEC DNSKEY")
	if err != nil {
		t.Fatalf("dns.NewRR() error = %v", err)
	}

	state, _, err := validateNoDSProof("example.org.", []dns.RR{rr}, nil, time.Now().UTC())
	if err == nil {
		t.Fatalf("validateNoDSProof() error = nil, want signature validation failure with raw authority material")
	}

	if hasNSECDelegationNoDS("example.org.", denialProofMaterial{
		NSEC: []rrsetWithSigs{{Owner: "example.org.", RRs: []dns.RR{rr}}},
	}) != true {
		t.Fatalf("hasNSECDelegationNoDS() = false, want true")
	}
	if state != SecurityBogus {
		t.Fatalf("state = %q, want bogus on validation error", state)
	}
}

func TestHasNSEC3ClosestEncloserOptOutNoDS(t *testing.T) {
	closestHash := dns.HashName("com.", dns.SHA1, 0, "")
	closestRR, err := dns.NewRR(fmt.Sprintf("%s.com. 900 IN NSEC3 1 0 0 - %s NS SOA RRSIG DNSKEY NSEC3PARAM", closestHash, closestHash))
	if err != nil {
		t.Fatalf("dns.NewRR() closest error = %v", err)
	}
	coverRR, err := dns.NewRR("KN0TO3F2KVK78CO2CPJ8C034L3DCBQSG.com. 900 IN NSEC3 1 1 0 - KN0TQ91RPN63DBLTODCRV2O7NS32G62K NS DS RRSIG")
	if err != nil {
		t.Fatalf("dns.NewRR() cover error = %v", err)
	}

	if !hasNSEC3ClosestEncloserOptOutNoDS("neverssl.com.", denialProofMaterial{
		NSEC3: []rrsetWithSigs{
			{Owner: dns.Fqdn(closestHash + ".com."), RRs: []dns.RR{closestRR}},
			{Owner: "KN0TO3F2KVK78CO2CPJ8C034L3DCBQSG.com.", RRs: []dns.RR{coverRR}},
		},
	}) {
		t.Fatalf("hasNSEC3ClosestEncloserOptOutNoDS() = false, want true")
	}
}

func TestHasNSEC3NoDataPattern(t *testing.T) {
	rr, err := dns.NewRR("2t7b4g4vsa5smi47k61mv5bv1a22bojr.example. 300 IN NSEC3 1 1 12 aabbccdd 2vptu5timamqttgl4luu9kg21e0aor3s A RRSIG")
	if err != nil {
		t.Fatalf("dns.NewRR() error = %v", err)
	}

	if !hasNSEC3ExactNoData("ns1.example.", dns.TypeMX, denialProofMaterial{
		NSEC3: []rrsetWithSigs{{Owner: "2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.", RRs: []dns.RR{rr}}},
	}) {
		t.Fatalf("hasNSEC3ExactNoData() = false, want true")
	}
}

func TestHasNSEC3NameErrorPattern(t *testing.T) {
	closestRR, err := dns.NewRR("b4um86eghhds6nea196smvmlo4ors995.example. 300 IN NSEC3 1 1 12 aabbccdd gjeqe526plbf1g8mklp59enfd789njgi A RRSIG")
	if err != nil {
		t.Fatalf("dns.NewRR() closest error = %v", err)
	}
	nextCloserCoverRR, err := dns.NewRR("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 300 IN NSEC3 1 1 12 aabbccdd 2t7b4g4vsa5smi47k61mv5bv1a22bojr SOA NSEC3PARAM RRSIG")
	if err != nil {
		t.Fatalf("dns.NewRR() next closer cover error = %v", err)
	}
	wildcardCoverRR, err := dns.NewRR("35mthgpgcu1qg68fab165klnsnk3dpvl.example. 300 IN NSEC3 1 1 12 aabbccdd b4um86eghhds6nea196smvmlo4ors995 NS RRSIG")
	if err != nil {
		t.Fatalf("dns.NewRR() wildcard cover error = %v", err)
	}

	if !hasNSEC3NameError("c.x.w.example.", denialProofMaterial{
		NSEC3: []rrsetWithSigs{
			{Owner: "b4um86eghhds6nea196smvmlo4ors995.example.", RRs: []dns.RR{closestRR}},
			{Owner: "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.", RRs: []dns.RR{nextCloserCoverRR}},
			{Owner: "35mthgpgcu1qg68fab165klnsnk3dpvl.example.", RRs: []dns.RR{wildcardCoverRR}},
		},
	}) {
		t.Fatalf("hasNSEC3NameError() = false, want true")
	}
}

func TestHasNSEC3WildcardNoDataPattern(t *testing.T) {
	closestRR, err := dns.NewRR("k8udemvp1j2f7eg6jebps17vp3n8i58h.example. 300 IN NSEC3 1 1 12 aabbccdd kohar7mbb8dc2ce8a9qvl8hon4k53uhi")
	if err != nil {
		t.Fatalf("dns.NewRR() closest error = %v", err)
	}
	nextCloserCoverRR, err := dns.NewRR("q04jkcevqvmu85r014c7dkba38o0ji5r.example. 300 IN NSEC3 1 1 12 aabbccdd r53bq7cc2uvmubfu5ocmm6pers9tk9en A RRSIG")
	if err != nil {
		t.Fatalf("dns.NewRR() next closer cover error = %v", err)
	}
	wildcardRR, err := dns.NewRR("r53bq7cc2uvmubfu5ocmm6pers9tk9en.example. 300 IN NSEC3 1 1 12 aabbccdd t644ebqk9bibcna874givr6joj62mlhv MX RRSIG")
	if err != nil {
		t.Fatalf("dns.NewRR() wildcard error = %v", err)
	}

	if !hasNSEC3WildcardNoData("a.z.w.example.", dns.TypeAAAA, denialProofMaterial{
		NSEC3: []rrsetWithSigs{
			{Owner: "k8udemvp1j2f7eg6jebps17vp3n8i58h.example.", RRs: []dns.RR{closestRR}},
			{Owner: "q04jkcevqvmu85r014c7dkba38o0ji5r.example.", RRs: []dns.RR{nextCloserCoverRR}},
			{Owner: "r53bq7cc2uvmubfu5ocmm6pers9tk9en.example.", RRs: []dns.RR{wildcardRR}},
		},
	}) {
		t.Fatalf("hasNSEC3WildcardNoData() = false, want true")
	}
}
