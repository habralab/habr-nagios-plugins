package dnsresolver

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

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

func TestCompleteReferralServersUsesGlueAndResolvesMissingRemainder(t *testing.T) {
	resolver := func(_ context.Context, names []string) ([]nsAddr, error) {
		if len(names) != 1 || names[0] != "ns3.example.net." {
			t.Fatalf("resolver names = %#v, want only missing name", names)
		}
		return []nsAddr{{Name: "ns3.example.net.", Addr: "192.0.2.3:53"}}, nil
	}

	got, err := completeReferralServersWithResolver(context.Background(),
		"example.com.",
		[]string{"ns1.example.net.", "ns2.example.net.", "ns3.example.net."},
		[]nsAddr{
			{Name: "ns1.example.net.", Addr: "192.0.2.1:53"},
			{Name: "ns2.example.net.", Addr: "192.0.2.2:53"},
		},
		resolver,
		defaultExecutionPolicy(),
	)
	if err != nil {
		t.Fatalf("completeReferralServersWithResolver() error = %v", err)
	}
	if gotLen := len(got); gotLen != 3 {
		t.Fatalf("completeReferralServersWithResolver() len = %d, want 3", gotLen)
	}
}

func TestCompleteReferralServersResolvesOutOfBailiwickNamesWhenGlueIsAbsent(t *testing.T) {
	resolver := func(_ context.Context, names []string) ([]nsAddr, error) {
		if len(names) != 1 || names[0] != "ns3.example.net." {
			t.Fatalf("resolver names = %#v, want only missing name", names)
		}
		return []nsAddr{{Name: "ns3.example.net.", Addr: "192.0.2.3:53"}}, nil
	}

	got, err := completeReferralServersWithResolver(context.Background(),
		"example.com.",
		[]string{"ns3.example.net."},
		nil,
		resolver,
		defaultExecutionPolicy(),
	)
	if err != nil {
		t.Fatalf("completeReferralServersWithResolver() error = %v", err)
	}
	if gotLen := len(got); gotLen != 1 {
		t.Fatalf("completeReferralServersWithResolver() len = %d, want 1", gotLen)
	}
}

func TestCompleteReferralServersSkipsInBailiwickNamesWithoutGlue(t *testing.T) {
	resolver := func(_ context.Context, names []string) ([]nsAddr, error) {
		if len(names) != 1 || names[0] != "dns2.easydns.net." {
			t.Fatalf("resolver names = %#v, want only out-of-bailiwick remainder", names)
		}
		return []nsAddr{{Name: "dns2.easydns.net.", Addr: "192.0.2.53:53"}}, nil
	}

	got, err := completeReferralServersWithResolver(context.Background(),
		"easydns.com.",
		[]string{"dns1.easydns.com.", "dns2.easydns.net."},
		nil,
		resolver,
		defaultExecutionPolicy(),
	)
	if err != nil {
		t.Fatalf("completeReferralServersWithResolver() error = %v", err)
	}
	if len(got) != 1 || got[0].Name != "dns2.easydns.net." {
		t.Fatalf("completeReferralServersWithResolver() = %#v, want dns2.easydns.net only", got)
	}
}

func TestCompleteReferralServersFailsWhenOnlyInBailiwickNamesLackGlue(t *testing.T) {
	resolver := func(_ context.Context, names []string) ([]nsAddr, error) {
		t.Fatalf("resolver should not be called for in-bailiwick-only referral, got %v", names)
		return nil, nil
	}

	_, err := completeReferralServersWithResolver(context.Background(),
		"example.com.",
		[]string{"ns1.example.com.", "ns2.example.com."},
		nil,
		resolver,
		defaultExecutionPolicy(),
	)
	if err == nil {
		t.Fatal("completeReferralServersWithResolver() error = nil, want glue/bootstrap error")
	}
	if !strings.Contains(err.Error(), "missing glue for in-bailiwick name servers") {
		t.Fatalf("error = %q, want missing glue message", err)
	}
}

func TestAcceptedGlueAddrsPolicy(t *testing.T) {
	nsNames := []string{"ns1.example.com.", "ns2.example.net."}
	glue := []nsAddr{
		{Name: "ns1.example.com.", Addr: "192.0.2.1:53"},
		{Name: "ns2.example.net.", Addr: "192.0.2.2:53"},
	}

	gotStrict := acceptedGlueAddrs("example.com.", nsNames, glue, glueAcceptanceStrict)
	if len(gotStrict) != 1 || gotStrict[0].Name != "ns1.example.com." {
		t.Fatalf("strict accepted glue = %#v, want only in-bailiwick glue", gotStrict)
	}

	gotNormal := acceptedGlueAddrs("example.com.", nsNames, glue, glueAcceptanceNormal)
	if len(gotNormal) != 1 || gotNormal[0].Name != "ns1.example.com." {
		t.Fatalf("normal accepted glue = %#v, want only in-bailiwick glue", gotNormal)
	}

	gotPermissive := acceptedGlueAddrs("example.com.", nsNames, glue, glueAcceptancePermissive)
	if len(gotPermissive) != 2 {
		t.Fatalf("permissive accepted glue len = %d, want 2 (%#v)", len(gotPermissive), gotPermissive)
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

func TestBuildZoneChainWithResolverUsesBestEffortResolverSemantics(t *testing.T) {
	rootServer := nsAddr{Name: "a.root-servers.net.", Addr: "198.41.0.4:53"}
	comServer := nsAddr{Name: "a.gtld-servers.net.", Addr: "192.0.2.10:53"}
	exampleServer := nsAddr{Name: "ns2.example.net.", Addr: "192.0.2.21:53"}

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
			return &exchangeResult{
				Server: comServer,
				Msg: &dns.Msg{
					Ns: []dns.RR{
						&dns.NS{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 172800}, Ns: "ns1.example.net."},
						&dns.NS{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 172800}, Ns: "ns2.example.net."},
					},
				},
			}, nil
		default:
			t.Fatalf("unexpected qname %q", qname)
			return nil, nil
		}
	}

	resolver := func(_ context.Context, names []string) ([]nsAddr, error) {
		if len(names) != 2 {
			t.Fatalf("resolver names = %#v, want both out-of-bailiwick names", names)
		}
		return []nsAddr{{Name: "ns2.example.net.", Addr: exampleServer.Addr}}, nil
	}

	hops, err := buildZoneChainWithResolver(context.Background(), "example.com.", query, resolver)
	if err != nil {
		t.Fatalf("buildZoneChainWithResolver() error = %v", err)
	}
	if len(hops) != 2 {
		t.Fatalf("buildZoneChainWithResolver() len = %d, want 2", len(hops))
	}
	if len(hops[1].ChildServers) != 1 || hops[1].ChildServers[0].Addr != exampleServer.Addr {
		t.Fatalf("second hop child servers = %#v, want %#v", hops[1].ChildServers, []nsAddr{exampleServer})
	}
}

func TestQueryAnyWithExchangerReturnsFirstSuccess(t *testing.T) {
	exchanger := func(ctx context.Context, server, qname string, qtype uint16, do bool) (*exchangeResult, error) {
		switch server {
		case "192.0.2.1:53", "192.0.2.3:53":
			<-ctx.Done()
			return nil, ctx.Err()
		case "192.0.2.2:53":
			msg := &dns.Msg{MsgHdr: dns.MsgHdr{Authoritative: true}}
			msg.Answer = []dns.RR{
				&dns.A{Hdr: dns.RR_Header{Name: dns.Fqdn(qname), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(203, 0, 113, 10)},
			}
			return &exchangeResult{Server: nsAddr{Name: "ns2.example.", Addr: server}, Network: "udp", Msg: msg}, nil
		default:
			return nil, errors.New("unexpected server")
		}
	}

	servers := []nsAddr{
		{Name: "ns1.example.", Addr: "192.0.2.1:53"},
		{Name: "ns2.example.", Addr: "192.0.2.2:53"},
		{Name: "ns3.example.", Addr: "192.0.2.3:53"},
	}

	started := time.Now()
	got, err := queryAnyWithExchanger(context.Background(), servers, "www.example.com.", dns.TypeA, true, exchanger)
	if err != nil {
		t.Fatalf("queryAnyWithExchanger() error = %v", err)
	}
	if got.Server.Addr != "192.0.2.2:53" {
		t.Fatalf("server = %q, want 192.0.2.2:53", got.Server.Addr)
	}
	if elapsed := time.Since(started); elapsed > 200*time.Millisecond {
		t.Fatalf("queryAnyWithExchanger() took %s, want early return", elapsed)
	}
}

func TestResolveNameServersBestEffortWithResolverStopsAtQuorum(t *testing.T) {
	addrResolver := func(ctx context.Context, name string) ([]string, error) {
		switch dns.Fqdn(name) {
		case "ns1.example.net.":
			time.Sleep(20 * time.Millisecond)
			return []string{"192.0.2.1:53"}, nil
		case "ns2.example.net.":
			time.Sleep(20 * time.Millisecond)
			return []string{"192.0.2.2:53"}, nil
		case "ns3.example.net.":
			<-ctx.Done()
			return nil, ctx.Err()
		default:
			return nil, errors.New("unexpected name")
		}
	}

	started := time.Now()
	got, err := resolveNameServersBestEffortWithResolver(context.Background(),
		[]string{"ns1.example.net.", "ns2.example.net.", "ns3.example.net."},
		2,
		addrResolver,
	)
	if err != nil {
		t.Fatalf("resolveNameServersBestEffortWithResolver() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2 (%#v)", len(got), got)
	}
	if elapsed := time.Since(started); elapsed > 200*time.Millisecond {
		t.Fatalf("resolveNameServersBestEffortWithResolver() took %s, want early return", elapsed)
	}
}
