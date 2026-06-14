package dnschain

import (
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestEmbeddedRootTrustAnchorsIncludeCurrentKSKs(t *testing.T) {
	anchors := mustLoadRootTrustAnchors(time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC))
	if len(anchors) == 0 {
		t.Fatalf("no anchors loaded")
	}

	want := map[uint16]bool{
		20326: false,
		38696: false,
	}
	for _, anchor := range anchors {
		if _, ok := want[anchor.KeyTag]; ok {
			want[anchor.KeyTag] = true
		}
	}
	for keyTag, found := range want {
		if !found {
			t.Fatalf("expected current root trust anchor with key tag %d", keyTag)
		}
	}
}

func TestTrustAnchorMaterialBuildsExpectedDNSKEYAndDS(t *testing.T) {
	anchors := mustLoadRootTrustAnchors(time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC))
	for _, anchor := range anchors {
		key := &dns.DNSKEY{
			Hdr:       dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
			Flags:     anchor.Flags,
			Protocol:  3,
			Algorithm: anchor.Algorithm,
			PublicKey: anchor.PublicKey,
		}
		if got, want := key.KeyTag(), anchor.KeyTag; got != want {
			t.Fatalf("KeyTag() = %d, want %d", got, want)
		}
		ds := key.ToDS(anchor.DigestType)
		if ds == nil {
			t.Fatalf("ToDS(%d) returned nil for key tag %d", anchor.DigestType, anchor.KeyTag)
		}
		if got, want := ds.Digest, anchor.Digest; !strings.EqualFold(got, want) {
			t.Fatalf("Digest = %q, want %q", got, want)
		}
	}
}
