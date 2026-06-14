package dnschain

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestMissingNSNames(t *testing.T) {
	got := missingNSNames(
		[]string{"ns1.example.net.", "ns2.example.net.", "ns3.example.net."},
		[]nsAddr{
			{Name: "ns1.example.net.", Addr: "192.0.2.1:53"},
			{Name: "ns2.example.net.", Addr: "192.0.2.2:53"},
		},
	)
	want := []string{"ns3.example.net."}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("missingNSNames() = %#v, want %#v", got, want)
	}
}

func TestCompleteReferralServersUsesGlueAndResolvedRemainder(t *testing.T) {
	resolver := func(_ context.Context, names []string) ([]nsAddr, error) {
		if len(names) != 1 || names[0] != "ns3.example.net." {
			t.Fatalf("resolver names = %#v, want only missing name", names)
		}
		return []nsAddr{{Name: "ns3.example.net.", Addr: "192.0.2.3:53"}}, nil
	}

	got, err := completeReferralServersWithResolver(context.Background(),
		[]string{"ns1.example.net.", "ns2.example.net.", "ns3.example.net."},
		[]nsAddr{
			{Name: "ns1.example.net.", Addr: "192.0.2.1:53"},
			{Name: "ns2.example.net.", Addr: "192.0.2.2:53"},
		},
		resolver,
	)
	if err != nil {
		t.Fatalf("completeReferralServersWithResolver() error = %v", err)
	}
	if gotLen := len(got); gotLen != 3 {
		t.Fatalf("completeReferralServersWithResolver() len = %d, want 3", gotLen)
	}
}

func TestZoneAncestry(t *testing.T) {
	got := zoneAncestry("in-addr.arpa.")
	want := []string{"arpa.", "in-addr.arpa."}
	if len(got) != len(want) {
		t.Fatalf("zoneAncestry() len = %d, want %d (%#v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("zoneAncestry()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestBuildZoneChainWithResolverHandlesAuthoritativeAnswerDelegation(t *testing.T) {
	rootServer := nsAddr{Name: "a.root-servers.net.", Addr: "198.41.0.4:53"}
	comServer := nsAddr{Name: "a.gtld-servers.net.", Addr: "192.0.2.10:53"}
	exampleServer := nsAddr{Name: "ns1.example.com.", Addr: "192.0.2.20:53"}

	query := func(_ context.Context, servers []nsAddr, qname string, qtype uint16, do bool) (*exchangeResult, error) {
		if qtype != dns.TypeNS || !do {
			t.Fatalf("unexpected query type/do: %d %t", qtype, do)
		}
		switch dns.Fqdn(qname) {
		case "com.":
			return &exchangeResult{
				Server: rootServer,
				Msg: &dns.Msg{
					MsgHdr: dns.MsgHdr{Authoritative: true},
					Answer: []dns.RR{
						&dns.NS{Hdr: dns.RR_Header{Name: "com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 172800}, Ns: "a.gtld-servers.net."},
					},
					Extra: []dns.RR{
						&dns.A{Hdr: dns.RR_Header{Name: "a.gtld-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 172800}, A: net.IPv4(192, 0, 2, 10)},
					},
				},
			}, nil
		case "example.com.":
			if len(servers) != 1 || servers[0].Addr != comServer.Addr {
				t.Fatalf("example.com. queried against %#v, want %#v", servers, []nsAddr{comServer})
			}
			return &exchangeResult{
				Server: comServer,
				Msg: &dns.Msg{
					Ns: []dns.RR{
						&dns.NS{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 172800}, Ns: "ns1.example.com."},
					},
					Extra: []dns.RR{
						&dns.A{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 172800}, A: net.IPv4(192, 0, 2, 20)},
					},
				},
			}, nil
		default:
			t.Fatalf("unexpected qname %q", qname)
			return nil, nil
		}
	}

	resolver := func(_ context.Context, names []string) ([]nsAddr, error) {
		t.Fatalf("resolver should not be called, got %v", names)
		return nil, nil
	}

	hops, err := buildZoneChainWithResolver(context.Background(), "example.com.", query, resolver)
	if err != nil {
		t.Fatalf("buildZoneChainWithResolver() error = %v", err)
	}
	if len(hops) != 2 {
		t.Fatalf("buildZoneChainWithResolver() len = %d, want 2", len(hops))
	}
	if hops[0].FromZone != "." || hops[0].ToZone != "com." {
		t.Fatalf("first hop = %#v, want . -> com.", hops[0])
	}
	if hops[1].FromZone != "com." || hops[1].ToZone != "example.com." {
		t.Fatalf("second hop = %#v, want com. -> example.com.", hops[1])
	}
	if len(hops[0].ChildServers) != 1 || hops[0].ChildServers[0].Addr != comServer.Addr {
		t.Fatalf("first hop child servers = %#v, want %#v", hops[0].ChildServers, []nsAddr{comServer})
	}
	if len(hops[1].ChildServers) != 1 || hops[1].ChildServers[0].Addr != exampleServer.Addr {
		t.Fatalf("second hop child servers = %#v, want %#v", hops[1].ChildServers, []nsAddr{exampleServer})
	}
}
