package dnsresolver

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/sharedcache"
	"github.com/miekg/dns"
)

func TestMarshalAndUnmarshalAuthorityArtifact(t *testing.T) {
	value := authorityResult{
		Zone: "example.com.",
		Servers: []nsAddr{
			{Name: "ns1.example.com.", Addr: "192.0.2.53:53"},
		},
		Hops: []delegationHop{{
			FromZone:      "com.",
			ToZone:        "example.com.",
			ParentServer:  nsAddr{Name: "a.gtld-servers.net.", Addr: "192.0.2.1:53"},
			ParentServers: []nsAddr{{Name: "a.gtld-servers.net.", Addr: "192.0.2.1:53"}},
			ChildNS:       []string{"ns1.example.com."},
			ChildServers:  []nsAddr{{Name: "ns1.example.com.", Addr: "192.0.2.53:53"}},
			CacheTTL:      2 * time.Hour,
		}},
		CacheTTL: 2 * time.Hour,
	}

	data, err := marshalAuthorityArtifact(value)
	if err != nil {
		t.Fatalf("marshalAuthorityArtifact() error = %v", err)
	}
	got, env, err := unmarshalAuthorityArtifact(data)
	if err != nil {
		t.Fatalf("unmarshalAuthorityArtifact() error = %v", err)
	}
	if env.ArtifactKind != sharedCacheArtifactAuthority {
		t.Fatalf("env.ArtifactKind = %q, want %q", env.ArtifactKind, sharedCacheArtifactAuthority)
	}
	if got.Zone != value.Zone || got.CacheTTL != value.CacheTTL {
		t.Fatalf("authority roundtrip = %#v, want zone %q ttl %v", got, value.Zone, value.CacheTTL)
	}
	if len(got.Servers) != 1 || got.Servers[0].Addr != "192.0.2.53:53" {
		t.Fatalf("servers = %#v, want cached server", got.Servers)
	}
	if len(got.Hops) != 1 || got.Hops[0].CacheTTL != 2*time.Hour {
		t.Fatalf("hops = %#v, want preserved hop ttl", got.Hops)
	}
}

func TestMarshalAndUnmarshalLookupArtifact(t *testing.T) {
	record := &dns.TXT{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
		Txt: []string{"v=spf1 -all"},
	}
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
		TypeCovered: dns.TypeTXT,
		Algorithm:   8,
		Labels:      2,
		OrigTtl:     300,
		Expiration:  4294967295,
		Inception:   1,
		KeyTag:      12345,
		SignerName:  "example.com.",
		Signature:   "AA==",
	}
	value := LookupResult{
		QName:               "example.com.",
		QType:               dns.TypeTXT,
		Zone:                "example.com.",
		Records:             []dns.RR{record},
		Signatures:          []*dns.RRSIG{sig},
		Security:            SecuritySecure,
		AuthenticatedNoData: false,
		ValidationMessage:   "ok",
		CacheTTL:            5 * time.Minute,
	}

	data, err := marshalLookupArtifact(value)
	if err != nil {
		t.Fatalf("marshalLookupArtifact() error = %v", err)
	}
	got, env, err := unmarshalLookupArtifact(data)
	if err != nil {
		t.Fatalf("unmarshalLookupArtifact() error = %v", err)
	}
	if env.ArtifactKind != sharedCacheArtifactLookup {
		t.Fatalf("env.ArtifactKind = %q, want %q", env.ArtifactKind, sharedCacheArtifactLookup)
	}
	if got.CacheTTL != value.CacheTTL || got.Security != value.Security {
		t.Fatalf("lookup roundtrip = %#v, want ttl %v security %q", got, value.CacheTTL, value.Security)
	}
	if len(got.Records) != 1 || got.Records[0].String() != record.String() {
		t.Fatalf("records = %#v, want %q", got.Records, record.String())
	}
	if len(got.Signatures) != 1 || got.Signatures[0].String() != sig.String() {
		t.Fatalf("signatures = %#v, want %q", got.Signatures, sig.String())
	}
}

func TestMarshalAndUnmarshalResolveArtifact(t *testing.T) {
	record := &dns.TXT{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
		Txt: []string{"v=spf1 -all"},
	}
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
		TypeCovered: dns.TypeTXT,
		Algorithm:   8,
		Labels:      2,
		OrigTtl:     300,
		Expiration:  4294967295,
		Inception:   1,
		KeyTag:      12345,
		SignerName:  "example.com.",
		Signature:   "AA==",
	}
	value := ResolveResult{
		Lookup: LookupResult{
			QName:             "example.com.",
			QType:             dns.TypeTXT,
			Zone:              "example.com.",
			Records:           []dns.RR{record},
			Signatures:        []*dns.RRSIG{sig},
			Security:          SecuritySecure,
			ValidationMessage: "ok",
			CacheTTL:          5 * time.Minute,
		},
		Zone:        "example.com.",
		Nameservers: []string{"ns1.example.com."},
		Endpoints:   []string{"192.0.2.53:53"},
		Responses: []EndpointResponse{{
			ServerName:     "ns1.example.com.",
			Endpoint:       "192.0.2.53:53",
			Network:        "udp",
			RTT:            42 * time.Millisecond,
			RCode:          dns.RcodeSuccess,
			Authoritative:  true,
			Records:        []dns.RR{record},
			Signatures:     []*dns.RRSIG{sig},
			RawAnswerCount: 2,
		}},
		Consistency: ConsistencyAssessment{
			Mode:            ConsistencyObserve,
			ComparableCount: 1,
			Consistent:      true,
			Baseline:        record.String(),
		},
	}

	data, err := marshalResolveArtifact(value)
	if err != nil {
		t.Fatalf("marshalResolveArtifact() error = %v", err)
	}
	got, env, err := unmarshalResolveArtifact(data)
	if err != nil {
		t.Fatalf("unmarshalResolveArtifact() error = %v", err)
	}
	if env.ArtifactKind != sharedCacheArtifactResolve {
		t.Fatalf("env.ArtifactKind = %q, want %q", env.ArtifactKind, sharedCacheArtifactResolve)
	}
	if got.Lookup.CacheTTL != 5*time.Minute {
		t.Fatalf("resolve lookup CacheTTL = %v, want %v", got.Lookup.CacheTTL, 5*time.Minute)
	}
	if got.Zone != value.Zone || len(got.Responses) != 1 {
		t.Fatalf("resolve roundtrip = %#v, want zone/responses preserved", got)
	}
	if got.Responses[0].Endpoint != "192.0.2.53:53" || got.Responses[0].RTT != 42*time.Millisecond {
		t.Fatalf("resolve response = %#v, want endpoint/rtt preserved", got.Responses[0])
	}
	if got.Consistency.Mode != ConsistencyObserve || !got.Consistency.Consistent {
		t.Fatalf("resolve consistency = %#v, want observe/consistent", got.Consistency)
	}
}

func TestMarshalAndUnmarshalValidationArtifact(t *testing.T) {
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 600},
		Flags:     257,
		Protocol:  3,
		Algorithm: 8,
		PublicKey: "AwEAAc2Vw9Qx7S3f",
	}
	value := validationResult{
		Security: SecuritySecure,
		Keys:     []*dns.DNSKEY{key},
		Message:  "chain validated",
		CacheTTL: 10 * time.Minute,
	}

	data, err := marshalValidationArtifact(value)
	if err != nil {
		t.Fatalf("marshalValidationArtifact() error = %v", err)
	}
	got, env, err := unmarshalValidationArtifact(data)
	if err != nil {
		t.Fatalf("unmarshalValidationArtifact() error = %v", err)
	}
	if env.ArtifactKind != sharedCacheArtifactValidation {
		t.Fatalf("env.ArtifactKind = %q, want %q", env.ArtifactKind, sharedCacheArtifactValidation)
	}
	if got.CacheTTL != value.CacheTTL || got.Message != value.Message {
		t.Fatalf("validation roundtrip = %#v, want ttl %v message %q", got, value.CacheTTL, value.Message)
	}
	if len(got.Keys) != 1 || got.Keys[0].String() != key.String() {
		t.Fatalf("keys = %#v, want %q", got.Keys, key.String())
	}
}

func TestZoneChainTTLUsesLowestHopTTL(t *testing.T) {
	hops := []delegationHop{
		{ToZone: "com.", CacheTTL: 48 * time.Hour},
		{ToZone: "example.com.", CacheTTL: 12 * time.Hour},
	}
	if got, want := zoneChainTTL(hops), 12*time.Hour; got != want {
		t.Fatalf("zoneChainTTL() = %v, want %v", got, want)
	}
}

func TestReferralTTLUsesMinimumAcrossDelegationAndGlue(t *testing.T) {
	msg := &dns.Msg{
		Ns: []dns.RR{
			&dns.NS{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}, Ns: "ns1.example.com."},
		},
		Extra: []dns.RR{
			&dns.A{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 900}, A: []byte{192, 0, 2, 53}},
		},
	}
	if got, want := referralTTL(msg, "example.com.", []string{"ns1.example.com."}), 15*time.Minute; got != want {
		t.Fatalf("referralTTL() = %v, want %v", got, want)
	}
}

func TestMarshalDelegationArtifactUsesCompactEndpointShape(t *testing.T) {
	data, err := marshalZoneChainArtifact([]delegationHop{{
		FromZone:      "com.",
		ToZone:        "example.com.",
		ParentServer:  nsAddr{Name: "a.gtld-servers.net.", Addr: "192.0.2.1:53"},
		ParentServers: []nsAddr{{Name: "a.gtld-servers.net.", Addr: "192.0.2.1:53"}},
		ChildNS:       []string{"ns1.example.com."},
		ChildServers:  []nsAddr{{Name: "ns1.example.com.", Addr: "192.0.2.53:5300"}},
		CacheTTL:      2 * time.Hour,
	}})
	if err != nil {
		t.Fatalf("marshalZoneChainArtifact() error = %v", err)
	}

	var env sharedcache.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("json.Unmarshal(envelope) error = %v", err)
	}
	if env.ArtifactKind != sharedCacheArtifactDelegation {
		t.Fatalf("env.ArtifactKind = %q, want %q", env.ArtifactKind, sharedCacheArtifactDelegation)
	}

	var payload map[string]any
	if err := json.Unmarshal(env.Payload, &payload); err != nil {
		t.Fatalf("json.Unmarshal(payload) error = %v", err)
	}
	if _, ok := payload["cache_ttl_seconds"]; ok {
		t.Fatal("payload unexpectedly duplicated top-level cache TTL")
	}

	hops, ok := payload["hops"].([]any)
	if !ok || len(hops) != 1 {
		t.Fatalf("payload hops = %#v, want one hop", payload["hops"])
	}
	hop, ok := hops[0].(map[string]any)
	if !ok {
		t.Fatalf("payload hop = %#v, want object", hops[0])
	}
	parent, ok := hop["parent_server"].(map[string]any)
	if !ok {
		t.Fatalf("parent_server = %#v, want object", hop["parent_server"])
	}
	if _, ok := parent["addr"]; ok {
		t.Fatal("parent_server unexpectedly used legacy addr field")
	}
	if got, want := parent["address"], "192.0.2.1"; got != want {
		t.Fatalf("parent_server.address = %#v, want %q", got, want)
	}
	if _, ok := parent["port"]; ok {
		t.Fatal("parent_server unexpectedly emitted default port")
	}
	children, ok := hop["child_servers"].([]any)
	if !ok || len(children) != 1 {
		t.Fatalf("child_servers = %#v, want one child", hop["child_servers"])
	}
	child, ok := children[0].(map[string]any)
	if !ok {
		t.Fatalf("child_server = %#v, want object", children[0])
	}
	if got, want := child["address"], "192.0.2.53"; got != want {
		t.Fatalf("child_server.address = %#v, want %q", got, want)
	}
	if got, want := child["port"], float64(5300); got != want {
		t.Fatalf("child_server.port = %#v, want %v", got, want)
	}
}

func TestMarshalAuthorityArtifactOmitsRedundantHopsAndPayloadTTL(t *testing.T) {
	data, err := marshalAuthorityArtifact(authorityResult{
		Zone: "example.com.",
		Servers: []nsAddr{
			{Name: "ns1.example.com.", Addr: "192.0.2.53:53"},
		},
		CacheTTL: 30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("marshalAuthorityArtifact() error = %v", err)
	}

	var env sharedcache.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("json.Unmarshal(envelope) error = %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(env.Payload, &payload); err != nil {
		t.Fatalf("json.Unmarshal(payload) error = %v", err)
	}
	if _, ok := payload["cache_ttl_seconds"]; ok {
		t.Fatal("authority payload unexpectedly duplicated top-level cache TTL")
	}
	if _, ok := payload["hops"]; ok {
		t.Fatal("authority payload unexpectedly emitted empty hops")
	}
}
