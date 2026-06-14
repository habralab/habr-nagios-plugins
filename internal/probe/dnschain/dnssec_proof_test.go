package dnschain

import (
	"fmt"
	"testing"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/miekg/dns"
)

func TestAssessNoDSProofPatternNSECExact(t *testing.T) {
	rr, err := dns.NewRR("example.org. 300 IN NSEC zzz.example.org. NS RRSIG NSEC DNSKEY")
	if err != nil {
		t.Fatalf("dns.NewRR() error = %v", err)
	}

	proof, ok := assessNoDSProofPattern("example.org.", denialProofMaterial{
		NSEC: []rrsetWithSigs{{Owner: "example.org.", RRs: []dns.RR{rr}}},
	})
	if !ok {
		t.Fatalf("assessNoDSProofPattern() ok = false, want true")
	}
	if got, want := proof.State, checkreport.CheckPass; got != want {
		t.Fatalf("proof.State = %q, want %q", got, want)
	}
	if got, want := proof.Kind, noDSProofKindNSECExact; got != want {
		t.Fatalf("proof.Kind = %q, want %q", got, want)
	}
}

func TestAssessNoDSProofPatternNSEC3ExactRequiresDelegationSemantics(t *testing.T) {
	hash := dns.HashName("example.org.", dns.SHA1, 0, "")
	rr, err := dns.NewRR(fmt.Sprintf("%s.example.org. 300 IN NSEC3 1 0 0 - ABCDEFGHIJKLMNOPQRSTUVWX A RRSIG", hash))
	if err != nil {
		t.Fatalf("dns.NewRR() error = %v", err)
	}

	if _, ok := assessNoDSProofPattern("example.org.", denialProofMaterial{
		NSEC3: []rrsetWithSigs{{Owner: dns.Fqdn(hash + ".example.org."), RRs: []dns.RR{rr}}},
	}); ok {
		t.Fatalf("assessNoDSProofPattern() ok = true, want false")
	}
}

func TestAssessNoDSProofPatternNSEC3ClosestEncloserOptOut(t *testing.T) {
	closestHash := dns.HashName("com.", dns.SHA1, 0, "")
	closestRR, err := dns.NewRR(fmt.Sprintf("%s.com. 900 IN NSEC3 1 0 0 - %s NS SOA RRSIG DNSKEY NSEC3PARAM", closestHash, closestHash))
	if err != nil {
		t.Fatalf("dns.NewRR() closest error = %v", err)
	}
	coverRR, err := dns.NewRR("KN0TO3F2KVK78CO2CPJ8C034L3DCBQSG.com. 900 IN NSEC3 1 1 0 - KN0TQ91RPN63DBLTODCRV2O7NS32G62K NS DS RRSIG")
	if err != nil {
		t.Fatalf("dns.NewRR() cover error = %v", err)
	}

	proof, ok := assessNoDSProofPattern("neverssl.com.", denialProofMaterial{
		NSEC3: []rrsetWithSigs{
			{Owner: dns.Fqdn(closestHash + ".com."), RRs: []dns.RR{closestRR}},
			{Owner: "KN0TO3F2KVK78CO2CPJ8C034L3DCBQSG.com.", RRs: []dns.RR{coverRR}},
		},
	})
	if !ok {
		t.Fatalf("assessNoDSProofPattern() ok = false, want true")
	}
	if got, want := proof.State, checkreport.CheckPass; got != want {
		t.Fatalf("proof.State = %q, want %q", got, want)
	}
	if got, want := proof.Kind, noDSProofKindNSEC3ClosestEncloserOptOut; got != want {
		t.Fatalf("proof.Kind = %q, want %q", got, want)
	}
}

func TestAssessNoDSProofPatternNSEC3OptOutWithoutClosestEncloserDoesNotPass(t *testing.T) {
	rr, err := dns.NewRR("KN0TO3F2KVK78CO2CPJ8C034L3DCBQSG.com. 900 IN NSEC3 1 1 0 - KN0TQ91RPN63DBLTODCRV2O7NS32G62K NS DS RRSIG")
	if err != nil {
		t.Fatalf("dns.NewRR() error = %v", err)
	}

	if _, ok := assessNoDSProofPattern("neverssl.com.", denialProofMaterial{
		NSEC3: []rrsetWithSigs{{Owner: "KN0TO3F2KVK78CO2CPJ8C034L3DCBQSG.com.", RRs: []dns.RR{rr}}},
	}); ok {
		t.Fatalf("assessNoDSProofPattern() ok = true, want false")
	}
}

func TestAssessNSEC3NoDataPattern(t *testing.T) {
	rr, err := dns.NewRR("2t7b4g4vsa5smi47k61mv5bv1a22bojr.example. 300 IN NSEC3 1 1 12 aabbccdd 2vptu5timamqttgl4luu9kg21e0aor3s A RRSIG")
	if err != nil {
		t.Fatalf("dns.NewRR() error = %v", err)
	}

	proof, ok := assessNSEC3NoDataPattern("ns1.example.", dns.TypeMX, denialProofMaterial{
		NSEC3: []rrsetWithSigs{{Owner: "2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.", RRs: []dns.RR{rr}}},
	})
	if !ok {
		t.Fatalf("assessNSEC3NoDataPattern() ok = false, want true")
	}
	if got, want := proof.Kind, nsec3ProofKindNoData; got != want {
		t.Fatalf("proof.Kind = %q, want %q", got, want)
	}
}

func TestAssessNSEC3NameErrorPattern(t *testing.T) {
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

	proof, ok := assessNSEC3NameErrorPattern("c.x.w.example.", denialProofMaterial{
		NSEC3: []rrsetWithSigs{
			{Owner: "b4um86eghhds6nea196smvmlo4ors995.example.", RRs: []dns.RR{closestRR}},
			{Owner: "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.", RRs: []dns.RR{nextCloserCoverRR}},
			{Owner: "35mthgpgcu1qg68fab165klnsnk3dpvl.example.", RRs: []dns.RR{wildcardCoverRR}},
		},
	})
	if !ok {
		t.Fatalf("assessNSEC3NameErrorPattern() ok = false, want true")
	}
	if got, want := proof.Kind, nsec3ProofKindNameError; got != want {
		t.Fatalf("proof.Kind = %q, want %q", got, want)
	}
}

func TestAssessNSEC3WildcardNoDataPattern(t *testing.T) {
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

	proof, ok := assessNSEC3WildcardNoDataPattern("a.z.w.example.", dns.TypeAAAA, denialProofMaterial{
		NSEC3: []rrsetWithSigs{
			{Owner: "k8udemvp1j2f7eg6jebps17vp3n8i58h.example.", RRs: []dns.RR{closestRR}},
			{Owner: "q04jkcevqvmu85r014c7dkba38o0ji5r.example.", RRs: []dns.RR{nextCloserCoverRR}},
			{Owner: "r53bq7cc2uvmubfu5ocmm6pers9tk9en.example.", RRs: []dns.RR{wildcardRR}},
		},
	})
	if !ok {
		t.Fatalf("assessNSEC3WildcardNoDataPattern() ok = false, want true")
	}
	if got, want := proof.Kind, nsec3ProofKindWildcardNoData; got != want {
		t.Fatalf("proof.Kind = %q, want %q", got, want)
	}
}

func TestAssessDenialProofTTLPass(t *testing.T) {
	nsec3, err := dns.NewRR("CK0POJMG874LJREF7EFN8430QVIT8BSM.com. 900 IN NSEC3 1 1 0 - CK0Q3UDG8CEKKAE7RUKPGCT1DVSSH8LL NS SOA RRSIG DNSKEY NSEC3PARAM")
	if err != nil {
		t.Fatalf("dns.NewRR() nsec3 error = %v", err)
	}
	soa, err := dns.NewRR("com. 900 IN SOA a.gtld-servers.net. nstld.verisign-grs.com. 1 1800 900 604800 900")
	if err != nil {
		t.Fatalf("dns.NewRR() soa error = %v", err)
	}

	got := assessDenialProofTTL([]dns.RR{nsec3, soa})
	if got == nil {
		t.Fatal("assessDenialProofTTL() = nil, want assessment")
	}
	if got.State != checkreport.CheckPass {
		t.Fatalf("assessDenialProofTTL().State = %q, want pass", got.State)
	}
}

func TestAssessDenialProofTTLWarnsOnExcessiveTTL(t *testing.T) {
	nsec3, err := dns.NewRR("CK0POJMG874LJREF7EFN8430QVIT8BSM.com. 3600 IN NSEC3 1 1 0 - CK0Q3UDG8CEKKAE7RUKPGCT1DVSSH8LL NS SOA RRSIG DNSKEY NSEC3PARAM")
	if err != nil {
		t.Fatalf("dns.NewRR() nsec3 error = %v", err)
	}
	soa, err := dns.NewRR("com. 900 IN SOA a.gtld-servers.net. nstld.verisign-grs.com. 1 1800 900 604800 900")
	if err != nil {
		t.Fatalf("dns.NewRR() soa error = %v", err)
	}

	got := assessDenialProofTTL([]dns.RR{nsec3, soa})
	if got == nil {
		t.Fatal("assessDenialProofTTL() = nil, want assessment")
	}
	if got.State != checkreport.CheckWarning {
		t.Fatalf("assessDenialProofTTL().State = %q, want warning", got.State)
	}
}
