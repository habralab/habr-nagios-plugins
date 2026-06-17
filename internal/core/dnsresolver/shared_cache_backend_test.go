package dnsresolver

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/sharedcache"
	"github.com/miekg/dns"
)

type testSharedCacheBackend struct {
	mu     sync.Mutex
	values map[string][]byte
	ttls   map[string]time.Duration
	getErr error
	setErr error
}

func newTestSharedCacheBackend() *testSharedCacheBackend {
	return &testSharedCacheBackend{
		values: map[string][]byte{},
		ttls:   map[string]time.Duration{},
	}
}

func (b *testSharedCacheBackend) Get(_ context.Context, key string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.getErr != nil {
		return nil, b.getErr
	}
	value, ok := b.values[key]
	if !ok {
		return nil, sharedcache.ErrNotFound
	}
	return append([]byte(nil), value...), nil
}

func (b *testSharedCacheBackend) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.setErr != nil {
		return b.setErr
	}
	b.values[key] = append([]byte(nil), value...)
	b.ttls[key] = ttl
	return nil
}

func TestResolverLookupLoadsFromSharedCache(t *testing.T) {
	r := NewResolver(0)
	backend := newTestSharedCacheBackend()
	r.SetSharedCacheBackend(backend)

	data, err := marshalLookupArtifact(LookupResult{
		QName:             "www.example.com.",
		QType:             dns.TypeA,
		Zone:              "example.com.",
		Records:           []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.IPv4(192, 0, 2, 10)}},
		Security:          SecurityInsecure,
		ValidationMessage: "unsigned delegation",
		CacheTTL:          5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("marshalLookupArtifact() error = %v", err)
	}
	backend.values[sharedCacheLookupKey("www.example.com.", dns.TypeA)] = data

	iterativeCalls := 0
	r.iterativeFn = func(_ context.Context, _ string, _ uint16) (*iterativeResult, error) {
		iterativeCalls++
		return nil, errors.New("iterative path should not run on shared-cache hit")
	}

	got, err := r.Lookup(context.Background(), "www.example.com", dns.TypeA)
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
	if iterativeCalls != 0 {
		t.Fatalf("iterativeCalls = %d, want 0", iterativeCalls)
	}
	if len(got.Records) != 1 || got.Zone != "example.com." {
		t.Fatalf("Lookup() = %#v, want shared cached result", got)
	}
}

func TestResolverLookupStoresSharedCache(t *testing.T) {
	r := NewResolver(0)
	backend := newTestSharedCacheBackend()
	r.SetSharedCacheBackend(backend)

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
				ToZone:       "example.com.",
				ChildServers: []nsAddr{{Name: "ns1.example.com.", Addr: "192.0.2.53:53"}},
				CacheTTL:     2 * time.Hour,
			}},
		}, nil
	}
	r.validateFn = func(_ context.Context, _ string, _ []nsAddr) (SecurityState, []*dns.DNSKEY, string, error) {
		return SecurityInsecure, nil, "unsigned delegation", nil
	}

	if _, err := r.Lookup(context.Background(), "www.example.com", dns.TypeA); err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
	key := sharedCacheLookupKey("www.example.com.", dns.TypeA)
	if _, ok := backend.values[key]; !ok {
		t.Fatalf("shared lookup cache missing key %q", key)
	}
	if got, want := backend.ttls[key], 5*time.Minute; got != want {
		t.Fatalf("shared lookup TTL = %v, want %v", got, want)
	}
}

func TestResolverResolveAuthoritativeLoadsFromSharedCache(t *testing.T) {
	r := NewResolver(0)
	backend := newTestSharedCacheBackend()
	r.SetSharedCacheBackend(backend)

	servers := []AuthoritativeServer{{Name: "ns1.example.com.", Endpoint: "192.0.2.53:53"}}
	opts := ResolveOptions{Fanout: FanoutAllAuthoritative, Consistency: ConsistencyObserve}
	cacheKey := resolveCacheKey("www.example.com.", dns.TypeA, servers, opts)

	data, err := marshalResolveArtifact(ResolveResult{
		Lookup: LookupResult{
			QName:             "www.example.com.",
			QType:             dns.TypeA,
			Zone:              "example.com.",
			Records:           []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.IPv4(192, 0, 2, 10)}},
			Security:          SecurityInsecure,
			ValidationMessage: "unsigned delegation",
			CacheTTL:          5 * time.Minute,
		},
		Zone:        "example.com.",
		Nameservers: []string{"ns1.example.com."},
		Endpoints:   []string{"192.0.2.53:53"},
		Responses: []EndpointResponse{{
			ServerName:    "ns1.example.com.",
			Endpoint:      "192.0.2.53:53",
			Network:       "udp",
			Authoritative: true,
			Records:       []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.IPv4(192, 0, 2, 10)}},
		}},
		Consistency: ConsistencyAssessment{Mode: ConsistencyObserve, ComparableCount: 1, Consistent: true},
	})
	if err != nil {
		t.Fatalf("marshalResolveArtifact() error = %v", err)
	}
	backend.values[sharedCacheResolveKey(cacheKey)] = data

	calls := 0
	origExchange := resolveExchangeFn
	defer func() { resolveExchangeFn = origExchange }()
	resolveExchangeFn = func(_ context.Context, _, _ string, _ uint16, _ bool) (*exchangeResult, error) {
		calls++
		return nil, errors.New("wire path should not run on shared resolve hit")
	}

	got, err := r.ResolveAuthoritative(context.Background(), "www.example.com", dns.TypeA, servers, opts)
	if err != nil {
		t.Fatalf("ResolveAuthoritative() error = %v", err)
	}
	if calls != 0 {
		t.Fatalf("resolveExchangeFn calls = %d, want 0", calls)
	}
	if got.Zone != "example.com." || len(got.Responses) != 1 {
		t.Fatalf("ResolveAuthoritative() = %#v, want shared cached result", got)
	}
}

func TestResolverResolveAuthoritativeStoresSharedCache(t *testing.T) {
	r := NewResolver(0)
	backend := newTestSharedCacheBackend()
	r.SetSharedCacheBackend(backend)

	servers := []AuthoritativeServer{{Name: "ns1.example.com.", Endpoint: "192.0.2.53:53"}}
	opts := ResolveOptions{Fanout: FanoutAllAuthoritative, Consistency: ConsistencyObserve}

	origExchange := resolveExchangeFn
	defer func() { resolveExchangeFn = origExchange }()
	resolveExchangeFn = func(_ context.Context, server, qname string, qtype uint16, _ bool) (*exchangeResult, error) {
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

	got, err := r.ResolveAuthoritative(context.Background(), "www.example.com", dns.TypeA, servers, opts)
	if err != nil {
		t.Fatalf("ResolveAuthoritative() error = %v", err)
	}
	cacheKey := resolveCacheKey("www.example.com.", dns.TypeA, servers, opts)
	key := sharedCacheResolveKey(cacheKey)
	if _, ok := backend.values[key]; !ok {
		t.Fatalf("shared resolve cache missing key %q", key)
	}
	if want := resolveResultTTL(got); backend.ttls[key] != want {
		t.Fatalf("shared resolve TTL = %v, want %v", backend.ttls[key], want)
	}
}

func TestResolverZoneChainLoadsFromSharedCache(t *testing.T) {
	r := NewResolver(0)
	backend := newTestSharedCacheBackend()
	r.SetSharedCacheBackend(backend)

	data, err := marshalZoneChainArtifact([]delegationHop{{
		FromZone:      "com.",
		ToZone:        "example.com.",
		ParentServer:  nsAddr{Name: "a.gtld-servers.net.", Addr: "192.0.2.1:53"},
		ParentServers: []nsAddr{{Name: "a.gtld-servers.net.", Addr: "192.0.2.1:53"}},
		ChildNS:       []string{"ns1.example.com."},
		ChildServers:  []nsAddr{{Name: "ns1.example.com.", Addr: "192.0.2.53:53"}},
		CacheTTL:      2 * time.Hour,
	}})
	if err != nil {
		t.Fatalf("marshalZoneChainArtifact() error = %v", err)
	}
	backend.values[sharedCacheDelegationKey("example.com.")] = data

	hops, err := r.ZoneChain(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("ZoneChain() error = %v", err)
	}
	if len(hops) != 1 || hops[0].ToZone != "example.com." || hops[0].CacheTTL != 2*time.Hour {
		t.Fatalf("ZoneChain() = %#v, want shared cached hop", hops)
	}
}

func TestResolverStoreSharedZoneChainStoresAncestorVariants(t *testing.T) {
	r := NewResolver(0)
	backend := newTestSharedCacheBackend()
	r.SetSharedCacheBackend(backend)

	hops := []delegationHop{
		{
			FromZone:      ".",
			ToZone:        "com.",
			ParentServer:  nsAddr{Name: "a.root-servers.net.", Addr: "192.0.2.10:53"},
			ParentServers: []nsAddr{{Name: "a.root-servers.net.", Addr: "192.0.2.10:53"}},
			ChildNS:       []string{"a.gtld-servers.net."},
			ChildServers:  []nsAddr{{Name: "a.gtld-servers.net.", Addr: "192.0.2.20:53"}},
			CacheTTL:      48 * time.Hour,
		},
		{
			FromZone:      "com.",
			ToZone:        "example.com.",
			ParentServer:  nsAddr{Name: "a.gtld-servers.net.", Addr: "192.0.2.20:53"},
			ParentServers: []nsAddr{{Name: "a.gtld-servers.net.", Addr: "192.0.2.20:53"}},
			ChildNS:       []string{"ns1.example.com."},
			ChildServers:  []nsAddr{{Name: "ns1.example.com.", Addr: "192.0.2.53:53"}},
			CacheTTL:      12 * time.Hour,
		},
	}

	r.storeSharedZoneChain(context.Background(), "example.com.", hops)

	if _, ok := backend.values[sharedCacheDelegationKey("com.")]; !ok {
		t.Fatalf("shared delegation cache missing key %q", sharedCacheDelegationKey("com."))
	}
	if _, ok := backend.values[sharedCacheDelegationKey("example.com.")]; !ok {
		t.Fatalf("shared delegation cache missing key %q", sharedCacheDelegationKey("example.com."))
	}
	if got, want := backend.ttls[sharedCacheDelegationKey("com.")], 48*time.Hour; got != want {
		t.Fatalf("shared com delegation TTL = %v, want %v", got, want)
	}
	if got, want := backend.ttls[sharedCacheDelegationKey("example.com.")], 12*time.Hour; got != want {
		t.Fatalf("shared example.com delegation TTL = %v, want %v", got, want)
	}
}

func TestResolverLoadSharedAuthorityReusesAncestorVariant(t *testing.T) {
	r := NewResolver(0)
	backend := newTestSharedCacheBackend()
	r.SetSharedCacheBackend(backend)

	value := authorityResult{
		Zone: "com.",
		Servers: []nsAddr{
			{Name: "a.gtld-servers.net.", Addr: "192.0.2.20:53"},
		},
		Hops: []delegationHop{{
			FromZone:      ".",
			ToZone:        "com.",
			ParentServer:  nsAddr{Name: "a.root-servers.net.", Addr: "192.0.2.10:53"},
			ParentServers: []nsAddr{{Name: "a.root-servers.net.", Addr: "192.0.2.10:53"}},
			ChildNS:       []string{"a.gtld-servers.net."},
			ChildServers:  []nsAddr{{Name: "a.gtld-servers.net.", Addr: "192.0.2.20:53"}},
			CacheTTL:      48 * time.Hour,
		}},
		CacheTTL: 48 * time.Hour,
	}
	data, err := marshalAuthorityArtifact(value)
	if err != nil {
		t.Fatalf("marshalAuthorityArtifact() error = %v", err)
	}
	backend.values[sharedCacheAuthorityKey("com.")] = data

	got, ok := r.loadSharedAuthority(context.Background(), "www.example.com.")
	if !ok {
		t.Fatalf("loadSharedAuthority() = miss, want ancestor shared authority reuse")
	}
	if got.Zone != "com." {
		t.Fatalf("shared authority zone = %q, want com.", got.Zone)
	}
	if len(got.Servers) != 1 || got.Servers[0].Addr != "192.0.2.20:53" {
		t.Fatalf("shared authority servers = %#v, want cached com authority", got.Servers)
	}
}

func TestResolverStoreSharedAuthorityCompactsDelegationHops(t *testing.T) {
	r := NewResolver(0)
	backend := newTestSharedCacheBackend()
	r.SetSharedCacheBackend(backend)

	value := authorityResult{
		Zone: "example.com.",
		Servers: []nsAddr{
			{Name: "ns1.example.com.", Addr: "192.0.2.53:53"},
		},
		Hops: []delegationHop{
			{
				FromZone:      ".",
				ToZone:        "com.",
				ParentServer:  nsAddr{Name: "a.root-servers.net.", Addr: "192.0.2.10:53"},
				ParentServers: []nsAddr{{Name: "a.root-servers.net.", Addr: "192.0.2.10:53"}},
				ChildNS:       []string{"a.gtld-servers.net."},
				ChildServers:  []nsAddr{{Name: "a.gtld-servers.net.", Addr: "192.0.2.20:53"}},
				CacheTTL:      48 * time.Hour,
			},
			{
				FromZone:      "com.",
				ToZone:        "example.com.",
				ParentServer:  nsAddr{Name: "a.gtld-servers.net.", Addr: "192.0.2.20:53"},
				ParentServers: []nsAddr{{Name: "a.gtld-servers.net.", Addr: "192.0.2.20:53"}},
				ChildNS:       []string{"ns1.example.com."},
				ChildServers:  []nsAddr{{Name: "ns1.example.com.", Addr: "192.0.2.53:53"}},
				CacheTTL:      12 * time.Hour,
			},
		},
		CacheTTL: 12 * time.Hour,
	}

	r.storeSharedAuthority(context.Background(), "www.example.com.", value)

	data := backend.values[sharedCacheAuthorityKey("www.example.com.")]
	stored, _, err := unmarshalAuthorityArtifact(data)
	if err != nil {
		t.Fatalf("unmarshalAuthorityArtifact() error = %v", err)
	}
	if len(stored.Hops) != 0 {
		t.Fatalf("shared authority hops = %#v, want compact payload without delegation duplication", stored.Hops)
	}
	if stored.Zone != "example.com." || len(stored.Servers) != 1 {
		t.Fatalf("shared authority payload = %#v, want compact authority metadata", stored)
	}
}

func TestResolverCachedZoneValidationStoresSharedValidationWithTTL(t *testing.T) {
	r := NewResolver(0)
	backend := newTestSharedCacheBackend()
	r.SetSharedCacheBackend(backend)

	r.validateFn = func(_ context.Context, zone string, _ []nsAddr) (SecurityState, []*dns.DNSKEY, string, error) {
		r.storeValidation(zone, validationResult{
			Security: SecuritySecure,
			Keys: []*dns.DNSKEY{{
				Hdr:       dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 600},
				Flags:     257,
				Protocol:  3,
				Algorithm: 8,
				PublicKey: "AwEAAc2Vw9Qx7S3f",
			}},
			Message:  "validated",
			CacheTTL: 10 * time.Minute,
		})
		return SecuritySecure, nil, "validated", nil
	}

	security, _, message, err := r.cachedZoneValidation(context.Background(), "example.com.", nil)
	if err != nil {
		t.Fatalf("cachedZoneValidation() error = %v", err)
	}
	if security != SecuritySecure || message != "validated" {
		t.Fatalf("cachedZoneValidation() = (%q, %q), want secure/validated", security, message)
	}

	key := sharedCacheValidationKey("example.com.")
	if _, ok := backend.values[key]; !ok {
		t.Fatalf("shared validation cache missing key %q", key)
	}
	if got, want := backend.ttls[key], 10*time.Minute; got != want {
		t.Fatalf("shared validation TTL = %v, want %v", got, want)
	}
}
