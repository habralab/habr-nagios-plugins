package dnsresolver

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestResolverLookupSingleflight(t *testing.T) {
	r := NewResolver(0)

	var iterativeCalls atomic.Int32
	var validateCalls atomic.Int32
	r.iterativeFn = func(_ context.Context, qname string, qtype uint16) (*iterativeResult, error) {
		iterativeCalls.Add(1)
		time.Sleep(20 * time.Millisecond)
		msg := &dns.Msg{
			Answer: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: dns.Fqdn(qname), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.IPv4(192, 0, 2, 10),
				},
			},
		}
		return &iterativeResult{
			Response: exchangeResult{Msg: msg},
			Hops: []delegationHop{{
				ToZone:       "example.com.",
				ChildServers: []nsAddr{{Name: "ns1.example.com.", Addr: "192.0.2.53:53"}},
			}},
		}, nil
	}
	r.validateFn = func(_ context.Context, zone string, _ []nsAddr) (SecurityState, []*dns.DNSKEY, string, error) {
		validateCalls.Add(1)
		time.Sleep(20 * time.Millisecond)
		return SecurityInsecure, nil, "unsigned delegation", nil
	}

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := r.Lookup(context.Background(), "www.example.com", dns.TypeA)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("Lookup() error = %v", err)
		}
	}
	if got := iterativeCalls.Load(); got != 1 {
		t.Fatalf("iterativeCalls = %d, want 1", got)
	}
	if got := validateCalls.Load(); got != 1 {
		t.Fatalf("validateCalls = %d, want 1", got)
	}
}

func TestResolverCachedZoneValidationSingleflight(t *testing.T) {
	r := NewResolver(0)

	var validateCalls atomic.Int32
	r.validateFn = func(_ context.Context, zone string, _ []nsAddr) (SecurityState, []*dns.DNSKEY, string, error) {
		validateCalls.Add(1)
		time.Sleep(20 * time.Millisecond)
		return SecurityInsecure, nil, "unsigned delegation", nil
	}

	servers := []nsAddr{{Name: "ns1.example.com.", Addr: "192.0.2.53:53"}}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _, err := r.cachedZoneValidation(context.Background(), "example.com.", servers)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("cachedZoneValidation() error = %v", err)
		}
	}
	if got := validateCalls.Load(); got != 1 {
		t.Fatalf("validateCalls = %d, want 1", got)
	}
}

func TestResolverResolveAuthoritativeSingleflight(t *testing.T) {
	r := NewResolver(0)

	var calls atomic.Int32
	origExchange := resolveExchangeFn
	defer func() { resolveExchangeFn = origExchange }()
	resolveExchangeFn = func(_ context.Context, server, qname string, qtype uint16, do bool) (*exchangeResult, error) {
		calls.Add(1)
		time.Sleep(20 * time.Millisecond)
		msg := &dns.Msg{MsgHdr: dns.MsgHdr{Authoritative: true}}
		msg.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: dns.Fqdn(qname), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.IPv4(192, 0, 2, 10),
			},
		}
		return &exchangeResult{
			Server:  nsAddr{Name: server, Addr: server},
			Network: "udp",
			Msg:     msg,
		}, nil
	}

	servers := []AuthoritativeServer{{Name: "ns1.example.com.", Endpoint: "192.0.2.53:53"}}
	opts := ResolveOptions{Fanout: FanoutAllAuthoritative, Consistency: ConsistencyObserve}

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := r.ResolveAuthoritative(context.Background(), "www.example.com", dns.TypeA, servers, opts)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("ResolveAuthoritative() error = %v", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("exchange calls = %d, want 1", got)
	}
}
