package dnsresolver

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestResolverLookupCachesPerQNameAndType(t *testing.T) {
	r := NewResolver(0)

	iterativeCalls := 0
	validateCalls := 0
	r.iterativeFn = func(_ context.Context, qname string, qtype uint16) (*iterativeResult, error) {
		iterativeCalls++
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
	r.validateFn = func(_ context.Context, zone string, servers []nsAddr) (SecurityState, []*dns.DNSKEY, string, error) {
		validateCalls++
		if zone != "example.com." {
			t.Fatalf("zone = %q, want example.com.", zone)
		}
		return SecurityInsecure, nil, "unsigned delegation", nil
	}

	first, err := r.Lookup(context.Background(), "www.example.com", dns.TypeA)
	if err != nil {
		t.Fatalf("first Lookup() error = %v", err)
	}
	second, err := r.Lookup(context.Background(), "www.example.com", dns.TypeA)
	if err != nil {
		t.Fatalf("second Lookup() error = %v", err)
	}
	if first.Security != SecurityInsecure || second.Security != SecurityInsecure {
		t.Fatalf("security = %q / %q, want insecure", first.Security, second.Security)
	}
	if iterativeCalls != 1 {
		t.Fatalf("iterativeCalls = %d, want 1", iterativeCalls)
	}
	if validateCalls != 1 {
		t.Fatalf("validateCalls = %d, want 1", validateCalls)
	}
}

func TestResolverLookupReusesAuthorityDiscoveryAcrossRRTypes(t *testing.T) {
	r := NewResolver(0)

	iterativeCalls := 0
	validateCalls := 0
	r.iterativeFn = func(_ context.Context, qname string, qtype uint16) (*iterativeResult, error) {
		iterativeCalls++
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
		validateCalls++
		if zone != "example.com." {
			t.Fatalf("zone = %q, want example.com.", zone)
		}
		return SecurityInsecure, nil, "unsigned delegation", nil
	}

	origExchange := resolveExchangeFn
	defer func() { resolveExchangeFn = origExchange }()
	resolveExchangeFn = func(_ context.Context, server, qname string, qtype uint16, do bool) (*exchangeResult, error) {
		msg := &dns.Msg{MsgHdr: dns.MsgHdr{Authoritative: true}}
		if qtype == dns.TypeAAAA {
			msg.Answer = []dns.RR{
				&dns.AAAA{
					Hdr:  dns.RR_Header{Name: dns.Fqdn(qname), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
					AAAA: net.ParseIP("2001:db8::10"),
				},
			}
		}
		return &exchangeResult{
			Server:  nsAddr{Name: "ns1.example.com.", Addr: server},
			Network: "udp",
			Msg:     msg,
		}, nil
	}

	if _, err := r.Lookup(context.Background(), "www.example.com", dns.TypeA); err != nil {
		t.Fatalf("A Lookup() error = %v", err)
	}
	got, err := r.Lookup(context.Background(), "www.example.com", dns.TypeAAAA)
	if err != nil {
		t.Fatalf("AAAA Lookup() error = %v", err)
	}
	if iterativeCalls != 1 {
		t.Fatalf("iterativeCalls = %d, want 1 shared authority discovery", iterativeCalls)
	}
	if validateCalls != 1 {
		t.Fatalf("validateCalls = %d, want 1 shared zone validation", validateCalls)
	}
	if len(got.Records) != 1 {
		t.Fatalf("len(AAAA records) = %d, want 1", len(got.Records))
	}
	if _, ok := got.Records[0].(*dns.AAAA); !ok {
		t.Fatalf("AAAA record = %T, want *dns.AAAA", got.Records[0])
	}
}

func TestResolverLookupReusesAuthorityAcrossOwnersWithinSameZone(t *testing.T) {
	r := NewResolver(0)

	iterativeCalls := 0
	validateCalls := 0
	r.iterativeFn = func(_ context.Context, qname string, qtype uint16) (*iterativeResult, error) {
		iterativeCalls++
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
		validateCalls++
		if zone != "example.com." {
			t.Fatalf("zone = %q, want example.com.", zone)
		}
		return SecurityInsecure, nil, "unsigned delegation", nil
	}

	origExchange := resolveExchangeFn
	defer func() { resolveExchangeFn = origExchange }()
	resolveExchangeFn = func(_ context.Context, server, qname string, qtype uint16, do bool) (*exchangeResult, error) {
		msg := &dns.Msg{MsgHdr: dns.MsgHdr{Authoritative: true}}
		msg.Answer = []dns.RR{
			&dns.CAA{
				Hdr:   dns.RR_Header{Name: dns.Fqdn(qname), Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: 300},
				Flag:  0,
				Tag:   "issue",
				Value: "letsencrypt.org",
			},
		}
		return &exchangeResult{
			Server:  nsAddr{Name: "ns1.example.com.", Addr: server},
			Network: "udp",
			Msg:     msg,
		}, nil
	}

	if _, err := r.Lookup(context.Background(), "www.example.com", dns.TypeA); err != nil {
		t.Fatalf("A Lookup() error = %v", err)
	}
	got, err := r.Lookup(context.Background(), "_443._tcp.www.example.com", dns.TypeCAA)
	if err != nil {
		t.Fatalf("CAA Lookup() error = %v", err)
	}
	if iterativeCalls != 1 {
		t.Fatalf("iterativeCalls = %d, want 1 shared zone authority discovery", iterativeCalls)
	}
	if validateCalls != 1 {
		t.Fatalf("validateCalls = %d, want 1 shared zone validation", validateCalls)
	}
	if len(got.Records) != 1 {
		t.Fatalf("len(CAA records) = %d, want 1", len(got.Records))
	}
	if _, ok := got.Records[0].(*dns.CAA); !ok {
		t.Fatalf("CAA record = %T, want *dns.CAA", got.Records[0])
	}
}

func TestResolverLookupEffectiveCAAUsesLookupCache(t *testing.T) {
	r := NewResolver(0)
	lookups := 0
	r.iterativeFn = func(_ context.Context, qname string, qtype uint16) (*iterativeResult, error) {
		lookups++
		return &iterativeResult{
			Response: exchangeResult{Msg: &dns.Msg{}},
			Hops: []delegationHop{{
				ToZone:       dns.Fqdn(qname),
				ChildServers: []nsAddr{{Name: "ns1.example.com.", Addr: "192.0.2.53:53"}},
			}},
		}, nil
	}
	r.validateFn = func(_ context.Context, _ string, _ []nsAddr) (SecurityState, []*dns.DNSKEY, string, error) {
		return SecurityInsecure, nil, "unsigned delegation", nil
	}

	_, err := r.LookupEffectiveCAA(context.Background(), "www.example.com")
	if err != nil {
		t.Fatalf("first LookupEffectiveCAA() error = %v", err)
	}
	_, err = r.LookupEffectiveCAA(context.Background(), "www.example.com")
	if err != nil {
		t.Fatalf("second LookupEffectiveCAA() error = %v", err)
	}
	if lookups != 4 {
		t.Fatalf("lookups = %d, want 4 cached walks for www.example.com., example.com., com., .", lookups)
	}
}

func TestResolverResolveAllAuthoritativeCollectsResponsesAndConsistency(t *testing.T) {
	r := NewResolver(0)
	r.iterativeFn = func(_ context.Context, qname string, qtype uint16) (*iterativeResult, error) {
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
				ToZone: "example.com.",
				ChildServers: []nsAddr{
					{Name: "ns1.example.com.", Addr: "192.0.2.53:53"},
					{Name: "ns2.example.com.", Addr: "192.0.2.54:53"},
				},
			}},
		}, nil
	}
	r.validateFn = func(_ context.Context, _ string, _ []nsAddr) (SecurityState, []*dns.DNSKEY, string, error) {
		return SecurityInsecure, nil, "unsigned delegation", nil
	}

	origExchange := resolveExchangeFn
	defer func() { resolveExchangeFn = origExchange }()
	resolveExchangeFn = func(_ context.Context, server, qname string, qtype uint16, do bool) (*exchangeResult, error) {
		ip := "192.0.2.10"
		if server == "192.0.2.54:53" {
			ip = "192.0.2.11"
		}
		msg := &dns.Msg{MsgHdr: dns.MsgHdr{Authoritative: true}}
		msg.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: dns.Fqdn(qname), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP(ip).To4(),
			},
		}
		return &exchangeResult{
			Server:  nsAddr{Name: server, Addr: server},
			Network: "udp",
			Msg:     msg,
		}, nil
	}

	got, err := r.Resolve(context.Background(), "www.example.com", dns.TypeA, ResolveOptions{
		Fanout:      FanoutAllAuthoritative,
		Consistency: ConsistencyObserve,
	})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got.Lookup.Zone != "www.example.com." {
		t.Fatalf("zone = %q, want www.example.com.", got.Lookup.Zone)
	}
	if len(got.Responses) != 2 {
		t.Fatalf("responses = %d, want 2", len(got.Responses))
	}
	if got.Consistency.ComparableCount != 2 {
		t.Fatalf("comparable = %d, want 2", got.Consistency.ComparableCount)
	}
	if got.Consistency.Consistent {
		t.Fatalf("consistency unexpectedly true")
	}
	if len(got.Consistency.Mismatches) != 1 || got.Consistency.Mismatches[0] != "192.0.2.54:53" {
		t.Fatalf("mismatches = %#v, want [192.0.2.54:53]", got.Consistency.Mismatches)
	}
}

func TestResolverResolveAllAuthoritativeReusesCachedAuthority(t *testing.T) {
	r := NewResolver(0)
	iterativeCalls := 0
	r.iterativeFn = func(_ context.Context, qname string, qtype uint16) (*iterativeResult, error) {
		iterativeCalls++
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
				ToZone: "example.com.",
				ChildServers: []nsAddr{
					{Name: "ns1.example.com.", Addr: "192.0.2.53:53"},
					{Name: "ns2.example.com.", Addr: "192.0.2.54:53"},
				},
			}},
		}, nil
	}
	r.validateFn = func(_ context.Context, _ string, _ []nsAddr) (SecurityState, []*dns.DNSKEY, string, error) {
		return SecurityInsecure, nil, "unsigned delegation", nil
	}

	origExchange := resolveExchangeFn
	defer func() { resolveExchangeFn = origExchange }()
	resolveExchangeFn = func(_ context.Context, server, qname string, qtype uint16, do bool) (*exchangeResult, error) {
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

	if _, err := r.Lookup(context.Background(), "www.example.com", dns.TypeA); err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
	if _, err := r.Resolve(context.Background(), "www.example.com", dns.TypeA, ResolveOptions{
		Fanout:      FanoutAllAuthoritative,
		Consistency: ConsistencyObserve,
	}); err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if iterativeCalls != 1 {
		t.Fatalf("iterativeCalls = %d, want cached authority reuse", iterativeCalls)
	}
}

func TestResolverResolveAuthoritativeCachesByServerSet(t *testing.T) {
	r := NewResolver(0)
	calls := 0

	origExchange := resolveExchangeFn
	defer func() { resolveExchangeFn = origExchange }()
	resolveExchangeFn = func(_ context.Context, server, qname string, qtype uint16, do bool) (*exchangeResult, error) {
		calls++
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

	serversA := []AuthoritativeServer{{Name: "ns1.example.com.", Endpoint: "192.0.2.53:53"}}
	serversB := []AuthoritativeServer{{Name: "ns2.example.com.", Endpoint: "192.0.2.54:53"}}

	_, err := r.ResolveAuthoritative(context.Background(), "www.example.com", dns.TypeA, serversA, ResolveOptions{
		Fanout:      FanoutAllAuthoritative,
		Consistency: ConsistencyObserve,
	})
	if err != nil {
		t.Fatalf("first ResolveAuthoritative() error = %v", err)
	}
	_, err = r.ResolveAuthoritative(context.Background(), "www.example.com", dns.TypeA, serversA, ResolveOptions{
		Fanout:      FanoutAllAuthoritative,
		Consistency: ConsistencyObserve,
	})
	if err != nil {
		t.Fatalf("second ResolveAuthoritative() error = %v", err)
	}
	if calls != 1 {
		t.Fatalf("calls after repeated same plan = %d, want 1", calls)
	}

	_, err = r.ResolveAuthoritative(context.Background(), "www.example.com", dns.TypeA, serversB, ResolveOptions{
		Fanout:      FanoutAllAuthoritative,
		Consistency: ConsistencyObserve,
	})
	if err != nil {
		t.Fatalf("third ResolveAuthoritative() error = %v", err)
	}
	if calls != 2 {
		t.Fatalf("calls after different server set = %d, want 2", calls)
	}
}

func TestResolveCacheKeyNormalizesAuthoritativeServerOrder(t *testing.T) {
	opts := ResolveOptions{Fanout: FanoutAllAuthoritative, Consistency: ConsistencyObserve}
	serversA := []AuthoritativeServer{
		{Name: "ns2.example.com.", Endpoint: "192.0.2.54:53"},
		{Name: "ns1.example.com.", Endpoint: "192.0.2.53:53"},
	}
	serversB := []AuthoritativeServer{
		{Name: "ns1.example.com.", Endpoint: "192.0.2.53:53"},
		{Name: "ns2.example.com.", Endpoint: "192.0.2.54:53"},
	}
	gotA := resolveCacheKey("www.example.com.", dns.TypeA, serversA, opts)
	gotB := resolveCacheKey("www.example.com.", dns.TypeA, serversB, opts)
	if gotA != gotB {
		t.Fatalf("resolveCacheKey() order-sensitive:\nA=%q\nB=%q", gotA, gotB)
	}
}

func TestResolverLookupUsesSOAOwnerAsFinalZone(t *testing.T) {
	r := NewResolver(0)
	r.iterativeFn = func(_ context.Context, qname string, qtype uint16) (*iterativeResult, error) {
		msg := &dns.Msg{
			Ns: []dns.RR{
				&dns.SOA{
					Hdr:     dns.RR_Header{Name: "www.cloudflare.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 1800},
					Ns:      "jule.ns.cloudflare.com.",
					Mbox:    "dns.cloudflare.com.",
					Serial:  1,
					Refresh: 10000,
					Retry:   2400,
					Expire:  604800,
					Minttl:  1800,
				},
			},
		}
		return &iterativeResult{
			Response: exchangeResult{Msg: msg},
			Hops: []delegationHop{{
				ToZone:       "cloudflare.com.",
				ChildServers: []nsAddr{{Name: "ns1.cloudflare.com.", Addr: "192.0.2.53:53"}},
			}},
		}, nil
	}
	r.validateFn = func(_ context.Context, zone string, _ []nsAddr) (SecurityState, []*dns.DNSKEY, string, error) {
		if zone != "www.cloudflare.com." {
			t.Fatalf("zone = %q, want www.cloudflare.com.", zone)
		}
		return SecuritySecure, nil, "stub", nil
	}

	_, err := r.Lookup(context.Background(), "_443._tcp.www.cloudflare.com.", dns.TypeTLSA)
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
}

func TestCachedDeepestSecureValidationPrefersDeepestSecureAncestor(t *testing.T) {
	r := NewResolver(0)

	rootKey := &dns.DNSKEY{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET}}
	comKey := &dns.DNSKEY{Hdr: dns.RR_Header{Name: "com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET}}
	r.storeValidation(".", validationResult{
		Security: SecuritySecure,
		Keys:     []*dns.DNSKEY{rootKey},
		Message:  "root secure",
	})
	r.storeValidation("com.", validationResult{
		Security: SecuritySecure,
		Keys:     []*dns.DNSKEY{comKey},
		Message:  "com secure",
	})
	r.storeValidation("example.com.", validationResult{
		Security: SecurityBogus,
		Message:  "example bogus",
	})

	zone, keys, msg, ok := r.cachedDeepestSecureValidation("www.example.com.")
	if !ok {
		t.Fatal("cachedDeepestSecureValidation() = not found, want cached secure ancestor")
	}
	if got, want := zone, "com."; got != want {
		t.Fatalf("zone = %q, want %q", got, want)
	}
	if len(keys) != 1 || dns.Fqdn(keys[0].Header().Name) != "com." {
		t.Fatalf("keys = %#v, want cached com DNSKEY", keys)
	}
	if got, want := msg, "com secure"; got != want {
		t.Fatalf("message = %q, want %q", got, want)
	}
}
