package dnschain

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestOwnerEndpointStateCollectsTerminalAddressRecords(t *testing.T) {
	owner := "www.example.com."
	aMsg := new(dns.Msg)
	aMsg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(192, 0, 2, 10),
		},
	}
	aaaaMsg := new(dns.Msg)
	aaaaMsg.Answer = []dns.RR{
		&dns.AAAA{
			Hdr:  dns.RR_Header{Name: owner, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
			AAAA: net.ParseIP("2001:db8::1"),
		},
	}

	state := ownerEndpointState(owner, aMsg, aaaaMsg)
	if len(state.ARecords) != 1 || state.ARecords[0] != "192.0.2.10" {
		t.Fatalf("ARecords = %#v, want [192.0.2.10]", state.ARecords)
	}
	if len(state.AAAARecords) != 1 || state.AAAARecords[0] != "2001:db8::1" {
		t.Fatalf("AAAARecords = %#v, want [2001:db8::1]", state.AAAARecords)
	}
	if state.Fingerprint == "" {
		t.Fatal("Fingerprint is empty")
	}
}

func TestOwnerEndpointStateCollectsCNAMEWithoutTargetAddresses(t *testing.T) {
	owner := "www.example.com."
	target := "edge.example.net."
	aMsg := new(dns.Msg)
	aMsg.Answer = []dns.RR{
		&dns.CNAME{
			Hdr:    dns.RR_Header{Name: owner, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
			Target: target,
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: target, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(198, 51, 100, 5),
		},
	}

	state := ownerEndpointState(owner, aMsg)
	if len(state.CNAMETargets) != 1 || state.CNAMETargets[0] != target {
		t.Fatalf("CNAMETargets = %#v, want [%s]", state.CNAMETargets, target)
	}
	if len(state.ARecords) != 0 {
		t.Fatalf("ARecords = %#v, want none for terminal target data", state.ARecords)
	}
}

func TestMergeOwnerEndpointStatePreservesCNAMEAndTerminalAddress(t *testing.T) {
	base := ownerEndpointResult{
		CNAMETargets: []string{"habr.com."},
		Fingerprint:  "stub",
	}
	next := ownerEndpointResult{
		AddressOwner: "habr.com.",
		ARecords:     []string{"178.248.237.68"},
		Fingerprint:  "stub2",
	}

	merged := mergeOwnerEndpointState(base, next)
	if len(merged.CNAMETargets) != 1 || merged.CNAMETargets[0] != "habr.com." {
		t.Fatalf("CNAMETargets = %#v, want [habr.com.]", merged.CNAMETargets)
	}
	if merged.AddressOwner != "habr.com." {
		t.Fatalf("AddressOwner = %q, want habr.com.", merged.AddressOwner)
	}
	if len(merged.ARecords) != 1 || merged.ARecords[0] != "178.248.237.68" {
		t.Fatalf("ARecords = %#v, want [178.248.237.68]", merged.ARecords)
	}
	if merged.Fingerprint == "" {
		t.Fatal("Fingerprint is empty")
	}
}

func TestNextSameZoneCNAMETarget(t *testing.T) {
	target, ok := nextSameZoneCNAMETarget([]string{"edge.example.net.", "habr.com."}, "habr.com.", map[string]bool{})
	if !ok {
		t.Fatal("expected same-zone target to be found")
	}
	if target != "habr.com." {
		t.Fatalf("target = %q, want habr.com.", target)
	}
}
