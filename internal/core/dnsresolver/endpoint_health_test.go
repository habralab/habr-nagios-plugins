package dnsresolver

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestOrderNSAddrsByHealthPrefersKnownGoodBeforeUnknownAndBad(t *testing.T) {
	tracker := newEndpointHealthTracker()
	tracker.recordSuccess("192.0.2.2:53", 10*time.Millisecond)
	tracker.recordFailure("192.0.2.3:53", errors.New("i/o timeout"))

	ctx := withEndpointHealthTracker(context.Background(), tracker)
	got := orderNSAddrsByHealth(ctx, []nsAddr{
		{Name: "ns3.example.", Addr: "192.0.2.3:53"},
		{Name: "ns1.example.", Addr: "192.0.2.1:53"},
		{Name: "ns2.example.", Addr: "192.0.2.2:53"},
	})

	if len(got) != 3 {
		t.Fatalf("len(got) = %d, want 3", len(got))
	}
	if got[0].Addr != "192.0.2.2:53" {
		t.Fatalf("first addr = %q, want known-good endpoint", got[0].Addr)
	}
	if got[1].Addr != "192.0.2.1:53" {
		t.Fatalf("second addr = %q, want unknown endpoint", got[1].Addr)
	}
	if got[2].Addr != "192.0.2.3:53" {
		t.Fatalf("third addr = %q, want penalized endpoint", got[2].Addr)
	}
}

func TestOrderAuthoritativeServersByHealthPrefersLowerRTTWithinGoodEndpoints(t *testing.T) {
	tracker := newEndpointHealthTracker()
	tracker.recordSuccess("192.0.2.1:53", 40*time.Millisecond)
	tracker.recordSuccess("192.0.2.2:53", 10*time.Millisecond)

	ctx := withEndpointHealthTracker(context.Background(), tracker)
	got := orderAuthoritativeServersByHealth(ctx, []AuthoritativeServer{
		{Name: "ns1.example.", Endpoint: "192.0.2.1:53"},
		{Name: "ns2.example.", Endpoint: "192.0.2.2:53"},
	})

	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2", len(got))
	}
	if got[0].Endpoint != "192.0.2.2:53" {
		t.Fatalf("first endpoint = %q, want lower-RTT endpoint", got[0].Endpoint)
	}
}
