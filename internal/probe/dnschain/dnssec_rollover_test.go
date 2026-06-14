package dnschain

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestMatchingDNSKEYsAcceptsAnyMatchingDSDuringRollover(t *testing.T) {
	active := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
		PublicKey: "4Fh6vQ8a6wT1N0v0m7lB0G6d0w3Q0nK8uS3qY2K9b+g=",
	}
	stale := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
		PublicKey: "A1h6vQ8a6wT1N0v0m7lB0G6d0w3Q0nK8uS3qY2K9b+g=",
	}

	activeDS := active.ToDS(dns.SHA256)
	if activeDS == nil {
		t.Fatal("active.ToDS() = nil")
	}
	staleDS := stale.ToDS(dns.SHA256)
	if staleDS == nil {
		t.Fatal("stale.ToDS() = nil")
	}

	got := matchingDNSKEYs([]*dns.DS{staleDS, activeDS}, []*dns.DNSKEY{active})
	if len(got) != 1 {
		t.Fatalf("matchingDNSKEYs() len = %d, want 1", len(got))
	}
	if got[0].PublicKey != active.PublicKey {
		t.Fatalf("matchingDNSKEYs() matched unexpected key %q", got[0].PublicKey)
	}
}

func TestMatchingDNSKEYsReturnsAllMatchingKeys(t *testing.T) {
	keyA := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
		PublicKey: "4Fh6vQ8a6wT1N0v0m7lB0G6d0w3Q0nK8uS3qY2K9b+g=",
	}
	keyB := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
		PublicKey: "5Gh7wR9b7xU2O1w1n8mC1H7e1x4R1oL9vT4rZ3L0c+h=",
	}

	dsA := keyA.ToDS(dns.SHA256)
	if dsA == nil {
		t.Fatal("keyA.ToDS() = nil")
	}
	dsB := keyB.ToDS(dns.SHA256)
	if dsB == nil {
		t.Fatal("keyB.ToDS() = nil")
	}

	got := matchingDNSKEYs([]*dns.DS{dsA, dsB}, []*dns.DNSKEY{keyA, keyB})
	if len(got) != 2 {
		t.Fatalf("matchingDNSKEYs() len = %d, want 2", len(got))
	}
}

func TestAssessSecureEntryPointsReportsUnmatchedAndUnsignedDSSeparately(t *testing.T) {
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
		PublicKey: "4Fh6vQ8a6wT1N0v0m7lB0G6d0w3Q0nK8uS3qY2K9b+g=",
	}
	matching := key.ToDS(dns.SHA256)
	if matching == nil {
		t.Fatal("key.ToDS() = nil")
	}
	other := &dns.DS{
		Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 300},
		KeyTag:     12345,
		Algorithm:  dns.ECDSAP256SHA256,
		DigestType: dns.SHA256,
		Digest:     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}

	got := assessSecureEntryPoints([]*dns.DS{matching, other}, []*dns.DNSKEY{key}, nil, time.Now().UTC())
	if len(got) != 2 {
		t.Fatalf("assessSecureEntryPoints() len = %d, want 2", len(got))
	}
	for _, assessment := range got {
		if assessment.Signed {
			t.Fatalf("assessment.Signed = true, want false with nil signatures")
		}
	}
}

func TestAssessSecureEntryPointsAllAdvertisedDSCanBeSEPs(t *testing.T) {
	keyA, privA := newTestED25519DNSKEY(t, "example.com.")
	keyB, privB := newTestED25519DNSKEY(t, "example.com.")
	dsA := keyA.ToDS(dns.SHA256)
	dsB := keyB.ToDS(dns.SHA256)
	if dsA == nil || dsB == nil {
		t.Fatal("ToDS() returned nil")
	}

	rrset := []dns.RR{keyA, keyB}
	sigA := signDNSKEYRRSet(t, keyA, privA, rrset)
	sigB := signDNSKEYRRSet(t, keyB, privB, rrset)

	got := assessSecureEntryPoints([]*dns.DS{dsA, dsB}, []*dns.DNSKEY{keyA, keyB}, []*dns.RRSIG{sigA, sigB}, time.Now().UTC())
	if len(got) != 2 {
		t.Fatalf("assessSecureEntryPoints() len = %d, want 2", len(got))
	}
	for key, assessment := range got {
		if !assessment.Matched || !assessment.Signed {
			t.Fatalf("assessment for %s = %+v, want matched+signed", key, assessment)
		}
	}
}

func TestAssessSecureEntryPointsDetectsPartialSEPDuringRollover(t *testing.T) {
	keyA, privA := newTestED25519DNSKEY(t, "example.com.")
	keyB, _ := newTestED25519DNSKEY(t, "example.com.")
	dsA := keyA.ToDS(dns.SHA256)
	dsB := keyB.ToDS(dns.SHA256)
	if dsA == nil || dsB == nil {
		t.Fatal("ToDS() returned nil")
	}

	rrset := []dns.RR{keyA, keyB}
	sigA := signDNSKEYRRSet(t, keyA, privA, rrset)

	got := assessSecureEntryPoints([]*dns.DS{dsA, dsB}, []*dns.DNSKEY{keyA, keyB}, []*dns.RRSIG{sigA}, time.Now().UTC())
	if len(got) != 2 {
		t.Fatalf("assessSecureEntryPoints() len = %d, want 2", len(got))
	}

	signedCount := 0
	for _, assessment := range got {
		if assessment.Signed {
			signedCount++
		}
	}
	if signedCount != 1 {
		t.Fatalf("signedCount = %d, want 1", signedCount)
	}
}

func TestAssessSecureEntryPointsDetectsWrongRRSIGKeyTagLikeIncident(t *testing.T) {
	keyA, privA := newTestED25519DNSKEY(t, "example.com.")
	keyB, _ := newTestED25519DNSKEY(t, "example.com.")
	dsA := keyA.ToDS(dns.SHA256)
	dsB := keyB.ToDS(dns.SHA256)
	if dsA == nil || dsB == nil {
		t.Fatal("ToDS() returned nil")
	}

	rrset := []dns.RR{keyA, keyB}
	sigA := signDNSKEYRRSet(t, keyA, privA, rrset)
	// Corrupt the signer reference: signature bytes belong to keyA, key tag points to keyB.
	sigA.KeyTag = keyB.KeyTag()

	got := assessSecureEntryPoints([]*dns.DS{dsA, dsB}, []*dns.DNSKEY{keyA, keyB}, []*dns.RRSIG{sigA}, time.Now().UTC())
	signedCount := 0
	for _, assessment := range got {
		if assessment.Signed {
			signedCount++
		}
	}
	if signedCount != 0 {
		t.Fatalf("signedCount = %d, want 0 with mismatched RRSIG key tag", signedCount)
	}
}

func TestAssessSecureEntryPointsTreatsStaleDSAsEarlyWarningCondition(t *testing.T) {
	activeKey, activePriv := newTestED25519DNSKEY(t, "example.com.")
	staleKey, _ := newTestED25519DNSKEY(t, "example.com.")
	activeDS := activeKey.ToDS(dns.SHA256)
	staleDS := staleKey.ToDS(dns.SHA256)
	if activeDS == nil || staleDS == nil {
		t.Fatal("ToDS() returned nil")
	}

	rrset := []dns.RR{activeKey}
	activeSig := signDNSKEYRRSet(t, activeKey, activePriv, rrset)

	got := assessSecureEntryPoints([]*dns.DS{activeDS, staleDS}, []*dns.DNSKEY{activeKey}, []*dns.RRSIG{activeSig}, time.Now().UTC())
	if len(got) != 2 {
		t.Fatalf("assessSecureEntryPoints() len = %d, want 2", len(got))
	}

	var signedCount, matchedCount int
	for _, assessment := range got {
		if assessment.Matched {
			matchedCount++
		}
		if assessment.Signed {
			signedCount++
		}
	}
	if matchedCount != 1 {
		t.Fatalf("matchedCount = %d, want 1", matchedCount)
	}
	if signedCount != 1 {
		t.Fatalf("signedCount = %d, want 1", signedCount)
	}
}

func TestAssessSecureEntryPointAlgorithmsIgnoresStaleDSOfCoveredAlgorithm(t *testing.T) {
	activeKey, activePriv := newTestED25519DNSKEY(t, "example.com.")
	staleKey, _ := newTestED25519DNSKEY(t, "example.com.")
	activeDS := activeKey.ToDS(dns.SHA256)
	staleDS := staleKey.ToDS(dns.SHA256)
	if activeDS == nil || staleDS == nil {
		t.Fatal("ToDS() returned nil")
	}

	rrset := []dns.RR{activeKey}
	activeSig := signDNSKEYRRSet(t, activeKey, activePriv, rrset)

	got := assessSecureEntryPointAlgorithms([]*dns.DS{activeDS, staleDS}, []*dns.DNSKEY{activeKey}, []*dns.RRSIG{activeSig}, time.Now().UTC())
	if got.TotalAlgorithms != 1 {
		t.Fatalf("TotalAlgorithms = %d, want 1", got.TotalAlgorithms)
	}
	if got.SignedAlgorithms != 1 {
		t.Fatalf("SignedAlgorithms = %d, want 1", got.SignedAlgorithms)
	}
}

func TestAssessSecureEntryPointAlgorithmsDetectsMissingAlgorithmCoverage(t *testing.T) {
	key8, priv8 := newTestED25519DNSKEY(t, "example.com.")
	key13 := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
		PublicKey: "4Fh6vQ8a6wT1N0v0m7lB0G6d0w3Q0nK8uS3qY2K9b+g=",
	}
	ds8 := key8.ToDS(dns.SHA256)
	ds13 := key13.ToDS(dns.SHA256)
	if ds8 == nil || ds13 == nil {
		t.Fatal("ToDS() returned nil")
	}

	rrset := []dns.RR{key8, key13}
	sig8 := signDNSKEYRRSet(t, key8, priv8, rrset)

	got := assessSecureEntryPointAlgorithms([]*dns.DS{ds8, ds13}, []*dns.DNSKEY{key8, key13}, []*dns.RRSIG{sig8}, time.Now().UTC())
	if got.TotalAlgorithms != 2 {
		t.Fatalf("TotalAlgorithms = %d, want 2", got.TotalAlgorithms)
	}
	if got.SignedAlgorithms != 1 {
		t.Fatalf("SignedAlgorithms = %d, want 1", got.SignedAlgorithms)
	}
}

func TestSummarizeDSCoverageReportsStaleTailDS(t *testing.T) {
	activeKey, activePriv := newTestED25519DNSKEY(t, "example.com.")
	staleKey, _ := newTestED25519DNSKEY(t, "example.com.")
	activeDS := activeKey.ToDS(dns.SHA256)
	staleDS := staleKey.ToDS(dns.SHA256)
	if activeDS == nil || staleDS == nil {
		t.Fatal("ToDS() returned nil")
	}

	rrset := []dns.RR{activeKey}
	activeSig := signDNSKEYRRSet(t, activeKey, activePriv, rrset)

	got := summarizeDSCoverage([]*dns.DS{activeDS, staleDS}, []*dns.DNSKEY{activeKey}, []*dns.RRSIG{activeSig}, time.Now().UTC())
	if got.TotalDSCount != 2 {
		t.Fatalf("TotalDSCount = %d, want 2", got.TotalDSCount)
	}
	if got.MatchedDSCount != 1 {
		t.Fatalf("MatchedDSCount = %d, want 1", got.MatchedDSCount)
	}
	if len(got.UnmatchedDS) != 1 {
		t.Fatalf("len(UnmatchedDS) = %d, want 1", len(got.UnmatchedDS))
	}
	if len(got.UnsignedMatched) != 0 {
		t.Fatalf("len(UnsignedMatched) = %d, want 0", len(got.UnsignedMatched))
	}
}

func TestAssessCryptoPolicySurfacesNotRecommendedActiveDigests(t *testing.T) {
	key, priv := newTestED25519DNSKEY(t, "example.com.")
	ds := key.ToDS(dns.SHA1)
	if ds == nil {
		t.Fatal("key.ToDS(SHA1) = nil")
	}
	rrset := []dns.RR{key}
	sig := signDNSKEYRRSet(t, key, priv, rrset)

	got := assessCryptoPolicy([]*dns.DS{ds}, []*dns.DNSKEY{key}, []*dns.RRSIG{sig}, time.Now().UTC())
	if len(got.ActiveNotRecommendedDigestNames) == 0 {
		t.Fatal("ActiveNotRecommendedDigestNames = empty, want SHA1")
	}
}

func TestAssessCryptoPolicyIgnoresSHA1TailWhenSHA256IsPresent(t *testing.T) {
	key, priv := newTestED25519DNSKEY(t, "example.com.")
	dsSHA1 := key.ToDS(dns.SHA1)
	dsSHA256 := key.ToDS(dns.SHA256)
	if dsSHA1 == nil || dsSHA256 == nil {
		t.Fatal("key.ToDS() returned nil")
	}
	rrset := []dns.RR{key}
	sig := signDNSKEYRRSet(t, key, priv, rrset)

	got := assessCryptoPolicy([]*dns.DS{dsSHA1, dsSHA256}, []*dns.DNSKEY{key}, []*dns.RRSIG{sig}, time.Now().UTC())
	if len(got.ActiveNotRecommendedDigestNames) != 0 {
		t.Fatalf("ActiveNotRecommendedDigestNames = %v, want empty because SHA1 should be ignored", got.ActiveNotRecommendedDigestNames)
	}
	if len(got.IgnoredDigestNames) == 0 || got.IgnoredDigestNames[0] != "SHA1(1)" {
		t.Fatalf("IgnoredDigestNames = %v, want SHA1(1)", got.IgnoredDigestNames)
	}
}

func TestAssessCryptoPolicySurfacesPublishedUnsupportedAndPolicyAlgorithms(t *testing.T) {
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECCGOST,
		PublicKey: "AwEAAcJKoPU0D6w5Y1a2X9C7Pj8Ol7XH4n1Qh9wC9w2P1v2mA7r4e8Jx0s6d7V0q0rj8Q9X4w6b1R2m3N4k5L6p7Q8r9S0t1u2v3w4x5y6z7",
	}
	ds := &dns.DS{
		Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 300},
		KeyTag:     key.KeyTag(),
		Algorithm:  dns.ECCGOST,
		DigestType: dns.GOST94,
		Digest:     strings.Repeat("A", 64),
	}

	got := assessCryptoPolicy([]*dns.DS{ds}, []*dns.DNSKEY{key}, nil, time.Now().UTC())
	if len(got.PublishedMustNotAlgorithms) == 0 {
		t.Fatal("PublishedMustNotAlgorithms = empty, want ECC-GOST")
	}
	if len(got.PublishedUnsupportedAlgorithms) == 0 {
		t.Fatal("PublishedUnsupportedAlgorithms = empty, want ECC-GOST")
	}
	if len(got.PublishedMustNotDigests) == 0 {
		t.Fatal("PublishedMustNotDigests = empty, want GOST94")
	}
	if len(got.PublishedUnsupportedDigestNames) == 0 {
		t.Fatal("PublishedUnsupportedDigestNames = empty, want GOST94")
	}
}

func newTestED25519DNSKEY(t *testing.T, name string) (*dns.DNSKEY, ed25519.PrivateKey) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}

	return &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ED25519,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}, priv
}

func signDNSKEYRRSet(t *testing.T, signer *dns.DNSKEY, priv ed25519.PrivateKey, rrset []dns.RR) *dns.RRSIG {
	t.Helper()

	now := time.Now().UTC()
	sig := &dns.RRSIG{
		Hdr:        dns.RR_Header{Ttl: rrset[0].Header().Ttl},
		KeyTag:     signer.KeyTag(),
		SignerName: signer.Hdr.Name,
		Algorithm:  signer.Algorithm,
		Inception:  uint32(now.Add(-time.Hour).Unix()),
		Expiration: uint32(now.Add(time.Hour).Unix()),
	}
	if err := sig.Sign(priv, rrset); err != nil {
		t.Fatalf("sig.Sign() error = %v", err)
	}
	return sig
}
