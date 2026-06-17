package httpx

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/habralab/habr-nagios-plugins/internal/core/dnsresolver"
)

type fakeDNSResolver struct {
	lookup func(context.Context, string, uint16) (dnsresolver.LookupResult, error)
}

func (f fakeDNSResolver) Lookup(ctx context.Context, qname string, qtype uint16) (dnsresolver.LookupResult, error) {
	return f.lookup(ctx, qname, qtype)
}

func TestResolverDialContextResolvesHostnameViaResolver(t *testing.T) {
	t.Parallel()

	var dialed string
	dialContext := resolverDialContext(
		fakeDNSResolver{
			lookup: func(_ context.Context, qname string, qtype uint16) (dnsresolver.LookupResult, error) {
				if qname != "example.test." {
					return dnsresolver.LookupResult{}, fmt.Errorf("unexpected qname %q", qname)
				}
				if qtype != dns.TypeA {
					return dnsresolver.LookupResult{}, nil
				}
				return dnsresolver.LookupResult{
					Records: []dns.RR{&dns.A{
						Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   net.IPv4(203, 0, 113, 10),
					}},
				}, nil
			},
		},
		defaultDNSLookupTimeout,
		func(_ context.Context, network string, address string) (net.Conn, error) {
			dialed = network + " " + address
			left, right := net.Pipe()
			_ = right.Close()
			return left, nil
		},
	)

	conn, err := dialContext(context.Background(), "tcp", "example.test:443")
	if err != nil {
		t.Fatalf("resolver dial: %v", err)
	}
	_ = conn.Close()

	if dialed != "tcp 203.0.113.10:443" {
		t.Fatalf("unexpected dial target %q", dialed)
	}
}

func TestResolverDialContextPreservesIPLiteral(t *testing.T) {
	t.Parallel()

	var dialed string
	dialContext := resolverDialContext(
		fakeDNSResolver{
			lookup: func(_ context.Context, qname string, qtype uint16) (dnsresolver.LookupResult, error) {
				return dnsresolver.LookupResult{}, fmt.Errorf("unexpected lookup %s %d", qname, qtype)
			},
		},
		defaultDNSLookupTimeout,
		func(_ context.Context, network string, address string) (net.Conn, error) {
			dialed = network + " " + address
			left, right := net.Pipe()
			_ = right.Close()
			return left, nil
		},
	)

	conn, err := dialContext(context.Background(), "tcp", "198.51.100.2:80")
	if err != nil {
		t.Fatalf("literal dial: %v", err)
	}
	_ = conn.Close()

	if dialed != "tcp 198.51.100.2:80" {
		t.Fatalf("unexpected literal dial target %q", dialed)
	}
}

func TestNewResolverDialContextUsesBundledResolverWithCacheBackend(t *testing.T) {
	t.Parallel()

	originalResolver := newBundledResolver
	originalDial := newDialContext
	t.Cleanup(func() {
		newBundledResolver = originalResolver
		newDialContext = originalDial
	})

	var gotTimeout time.Duration
	var gotCacheBackend string
	newBundledResolver = func(timeout time.Duration, cacheBackend string) DNSResolver {
		gotTimeout = timeout
		gotCacheBackend = cacheBackend
		return fakeDNSResolver{
			lookup: func(_ context.Context, qname string, qtype uint16) (dnsresolver.LookupResult, error) {
				if qname != "example.test." {
					return dnsresolver.LookupResult{}, fmt.Errorf("unexpected qname %q", qname)
				}
				if qtype != dns.TypeA {
					return dnsresolver.LookupResult{}, nil
				}
				return dnsresolver.LookupResult{
					Records: []dns.RR{&dns.A{
						Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   net.IPv4(203, 0, 113, 11),
					}},
				}, nil
			},
		}
	}

	var dialed string
	newDialContext = func(timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
		if timeout != defaultDialTimeout {
			t.Fatalf("unexpected dial timeout %s", timeout)
		}
		return func(_ context.Context, network string, address string) (net.Conn, error) {
			dialed = network + " " + address
			left, right := net.Pipe()
			_ = right.Close()
			return left, nil
		}
	}
	dialContext := newResolverDialContext(10*time.Second, Options{
		DNSLookupTimeout: 7 * time.Second,
		CacheBackend:     "redis://127.0.0.1:6379/2",
	})
	conn, err := dialContext(context.Background(), "tcp", "example.test:443")
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	_ = conn.Close()

	if gotTimeout != 7*time.Second {
		t.Fatalf("unexpected lookup timeout %s", gotTimeout)
	}
	if gotCacheBackend != "redis://127.0.0.1:6379/2" {
		t.Fatalf("unexpected cache backend %q", gotCacheBackend)
	}
	if dialed != "tcp 203.0.113.11:443" {
		t.Fatalf("unexpected dial target %q", dialed)
	}
}
