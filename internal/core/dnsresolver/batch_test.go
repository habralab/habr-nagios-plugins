package dnsresolver

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestResolverLookupBatchPreservesOrderAndErrors(t *testing.T) {
	r := NewResolver(0)
	r.iterativeFn = func(_ context.Context, qname string, qtype uint16) (*iterativeResult, error) {
		if qtype == dns.TypeAAAA {
			return nil, errors.New("no IPv6")
		}
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
	r.validateFn = func(_ context.Context, _ string, _ []nsAddr) (SecurityState, []*dns.DNSKEY, string, error) {
		return SecurityInsecure, nil, "unsigned delegation", nil
	}

	got := r.LookupBatch(context.Background(), []Question{
		{QName: "www.example.com", QType: dns.TypeA},
		{QName: "www.example.com", QType: dns.TypeAAAA},
	})
	if len(got) != 2 {
		t.Fatalf("len(LookupBatch) = %d, want 2", len(got))
	}
	if got[0].Err != nil || len(got[0].Result.Records) != 1 {
		t.Fatalf("LookupBatch first item = %#v, want A result", got[0])
	}
	if got[1].Err == nil {
		t.Fatalf("LookupBatch second item error = nil, want propagated error")
	}
}

func TestResolverResolveAuthoritativeBatchPreservesOrderAndErrors(t *testing.T) {
	r := NewResolver(0)
	origExchange := resolveExchangeFn
	defer func() { resolveExchangeFn = origExchange }()
	resolveExchangeFn = func(_ context.Context, server, qname string, qtype uint16, _ bool) (*exchangeResult, error) {
		if qtype == dns.TypeAAAA {
			return nil, errors.New("no IPv6")
		}
		msg := &dns.Msg{MsgHdr: dns.MsgHdr{Authoritative: true}}
		msg.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: dns.Fqdn(qname), Rrtype: qtype, Class: dns.ClassINET, Ttl: 300},
				A:   net.IPv4(192, 0, 2, 10),
			},
		}
		return &exchangeResult{
			Server:  nsAddr{Name: "ns1.example.com.", Addr: server},
			Network: "udp",
			Msg:     msg,
		}, nil
	}

	got := r.ResolveAuthoritativeBatch(context.Background(),
		[]AuthoritativeServer{{Name: "ns1.example.com.", Endpoint: "192.0.2.53:53"}},
		ResolveOptions{Fanout: FanoutAllAuthoritative, Consistency: ConsistencyObserve},
		[]Question{
			{QName: "www.example.com", QType: dns.TypeA},
			{QName: "www.example.com", QType: dns.TypeAAAA},
		},
	)
	if len(got) != 2 {
		t.Fatalf("len(ResolveAuthoritativeBatch) = %d, want 2", len(got))
	}
	if got[0].Err != nil || len(got[0].Result.Responses) != 1 {
		t.Fatalf("ResolveAuthoritativeBatch first item = %#v, want successful A result", got[0])
	}
	if got[1].Err != nil {
		t.Fatalf("ResolveAuthoritativeBatch second item error = %v, want per-endpoint transport error only", got[1].Err)
	}
	if len(got[1].Result.Responses) != 1 || got[1].Result.Responses[0].Error == "" {
		t.Fatalf("ResolveAuthoritativeBatch second item = %#v, want captured endpoint error", got[1])
	}
}
