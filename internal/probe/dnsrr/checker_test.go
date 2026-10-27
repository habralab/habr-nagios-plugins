package dnsrr

import (
	"strings"
	"testing"

	"github.com/habralab/habr-nagios-plugins/internal/core/dnsprobe"
	"github.com/miekg/dns"
)

func TestNormalizeTargetRequiresInputAndRRType(t *testing.T) {
	_, err := normalizeTarget(Config{})
	if err == nil || !strings.Contains(err.Error(), "either -H/--hostname or --zone is required") {
		t.Fatalf("normalizeTarget() error = %v, want missing target error", err)
	}

	_, err = normalizeTarget(Config{Hostname: "www.example.com"})
	if err == nil || !strings.Contains(err.Error(), "--rrtype is required") {
		t.Fatalf("normalizeTarget() error = %v, want missing rrtype error", err)
	}
}

func TestNormalizeTargetDerivesOwner(t *testing.T) {
	target, err := normalizeTarget(Config{Hostname: "www.example.com.", RRType: "A", Mode: dnsprobe.PresenceAny})
	if err != nil {
		t.Fatalf("normalizeTarget() error = %v", err)
	}
	if target.Owner != "www.example.com" {
		t.Fatalf("target.Owner = %q, want www.example.com", target.Owner)
	}
	if target.RRType != dns.TypeA {
		t.Fatalf("target.RRType = %d, want A", target.RRType)
	}
}

func TestNormalizeTargetRejectsMultipleMatchers(t *testing.T) {
	_, err := normalizeTarget(Config{
		Hostname:      "www.example.com",
		RRType:        "TXT",
		ExpectValue:   "a",
		ContainsValue: "b",
	})
	if err == nil || !strings.Contains(err.Error(), "only one of --expect-value, --contains, or --regex") {
		t.Fatalf("normalizeTarget() error = %v, want matcher exclusivity error", err)
	}
}
