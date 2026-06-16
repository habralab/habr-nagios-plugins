package dnsresolver

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestFilterNSAddrsByCapabilities(t *testing.T) {
	input := []nsAddr{
		{Name: "ns1.example.", Addr: "192.0.2.53:53"},
		{Name: "ns1.example.", Addr: "[2001:db8::53]:53"},
	}

	got := filterNSAddrsByCapabilities(input, resolverFamilyCapabilities{IPv4: true, IPv6: false})
	if len(got) != 1 || got[0].Addr != "192.0.2.53:53" {
		t.Fatalf("IPv4-only filter = %#v", got)
	}

	got = filterNSAddrsByCapabilities(input, resolverFamilyCapabilities{IPv4: false, IPv6: true})
	if len(got) != 1 || got[0].Addr != "[2001:db8::53]:53" {
		t.Fatalf("IPv6-only filter = %#v", got)
	}
}

func TestResolveAuthoritativeSkipsUnavailableIPv6Family(t *testing.T) {
	r := NewResolver(2)
	r.familyCaps.caps = resolverFamilyCapabilities{IPv4: true, IPv6: false}
	r.familyCaps.once.Do(func() {})

	origExchange := resolveExchangeFn
	defer func() { resolveExchangeFn = origExchange }()

	var called []string
	resolveExchangeFn = func(_ context.Context, server, qname string, qtype uint16, do bool) (*exchangeResult, error) {
		called = append(called, server)
		msg := &dns.Msg{MsgHdr: dns.MsgHdr{Authoritative: true}}
		msg.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: dns.Fqdn(qname), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(203, 0, 113, 10),
			},
		}
		return &exchangeResult{
			Server:  nsAddr{Name: server, Addr: server},
			Network: "udp",
			Msg:     msg,
		}, nil
	}

	servers := []AuthoritativeServer{
		{Name: "ns1.example.", Endpoint: "192.0.2.53:53"},
		{Name: "ns1.example.", Endpoint: "[2001:db8::53]:53"},
	}
	_, err := r.ResolveAuthoritative(context.Background(), "www.example.com", dns.TypeA, servers, ResolveOptions{
		Fanout:      FanoutAllAuthoritative,
		Consistency: ConsistencyObserve,
	})
	if err != nil {
		t.Fatalf("ResolveAuthoritative() error = %v", err)
	}
	if len(called) != 1 || called[0] != "192.0.2.53:53" {
		t.Fatalf("called endpoints = %#v, want only IPv4 endpoint", called)
	}
}
