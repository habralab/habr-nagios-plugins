package dnsresolver

import (
	"testing"

	"github.com/miekg/dns"
)

func TestSharedCacheAuthorityKey(t *testing.T) {
	got := sharedCacheAuthorityKey("www.example.com")
	want := "dnsresolver:v1:authority:www.example.com."
	if got != want {
		t.Fatalf("sharedCacheAuthorityKey() = %q, want %q", got, want)
	}
}

func TestSharedCacheDelegationKey(t *testing.T) {
	got := sharedCacheDelegationKey("example.com")
	want := "dnsresolver:v1:delegation:example.com."
	if got != want {
		t.Fatalf("sharedCacheDelegationKey() = %q, want %q", got, want)
	}
}

func TestSharedCacheLookupKey(t *testing.T) {
	got := sharedCacheLookupKey("_443._tcp.www.example.com", dns.TypeTLSA)
	want := "dnsresolver:v1:lookup:_443._tcp.www.example.com.:52"
	if got != want {
		t.Fatalf("sharedCacheLookupKey() = %q, want %q", got, want)
	}
}

func TestSharedCacheResolveKey(t *testing.T) {
	got := sharedCacheResolveKey("www.example.com.|A|all_authoritative|observe|ns1.example.com.@192.0.2.53:53")
	want := "dnsresolver:v1:resolve:www.example.com.%7CA%7Call_authoritative%7Cobserve%7Cns1.example.com.@192.0.2.53:53"
	if got != want {
		t.Fatalf("sharedCacheResolveKey() = %q, want %q", got, want)
	}
}

func TestSharedCacheValidationKey(t *testing.T) {
	got := sharedCacheValidationKey("example.com")
	want := "dnsresolver:v1:validation:example.com."
	if got != want {
		t.Fatalf("sharedCacheValidationKey() = %q, want %q", got, want)
	}
}
