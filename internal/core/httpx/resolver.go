package httpx

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/habralab/habr-nagios-plugins/internal/core/dnsresolver"
)

const (
	defaultDNSLookupTimeout = 5 * time.Second
	defaultDialTimeout      = 5 * time.Second
)

var newBundledResolver = func(timeout time.Duration, cacheBackend string) DNSResolver {
	resolver := dnsresolver.NewResolver(timeout)
	resolver.ConfigureSharedCacheBackendDSN(cacheBackend)
	return resolver
}

var newDialContext = func(timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	return (&net.Dialer{Timeout: timeout}).DialContext
}

type DNSResolver interface {
	Lookup(context.Context, string, uint16) (dnsresolver.LookupResult, error)
}

func newResolverDialContext(clientTimeout time.Duration, opts Options) func(context.Context, string, string) (net.Conn, error) {
	resolver := opts.DNSResolver
	if resolver == nil {
		resolver = newBundledResolver(effectiveDNSLookupTimeout(opts), opts.CacheBackend)
	}
	if opts.ResolverObserver != nil {
		opts.ResolverObserver(resolver)
	}
	return resolverDialContext(resolver, effectiveDNSLookupTimeout(opts), newDialContext(effectiveDialTimeout(clientTimeout)))
}

func resolverDialContext(resolver DNSResolver, lookupTimeout time.Duration, dialFn func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network string, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if net.ParseIP(host) != nil {
			return dialFn(ctx, network, address)
		}

		ips, err := lookupHostIPs(ctx, resolver, host, lookupTimeout)
		if err != nil {
			return nil, err
		}
		var lastErr error
		for _, ip := range ips {
			conn, dialErr := dialFn(ctx, network, net.JoinHostPort(ip.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, fmt.Errorf("no usable addresses for %s", address)
	}
}

func lookupHostIPs(ctx context.Context, resolver DNSResolver, host string, timeout time.Duration) ([]net.IP, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var ips []net.IP
	var errs []error
	var statuses []string
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		result, err := resolver.Lookup(lookupCtx, dns.Fqdn(host), qtype)
		if err != nil {
			errs = append(errs, err)
			statuses = append(statuses, rrtypeLabel(qtype)+": lookup error: "+err.Error())
			continue
		}
		for _, rr := range result.Records {
			switch v := rr.(type) {
			case *dns.A:
				ips = append(ips, append(net.IP(nil), v.A...))
			case *dns.AAAA:
				ips = append(ips, append(net.IP(nil), v.AAAA...))
			}
		}
		if len(result.Records) == 0 {
			status := rrtypeLabel(qtype) + ": no data"
			if result.ValidationMessage != "" {
				status += " (" + result.ValidationMessage + ")"
			}
			statuses = append(statuses, status)
		}
	}
	if len(ips) > 0 {
		return ips, nil
	}
	if len(errs) == 0 {
		return nil, fmt.Errorf("no A or AAAA records for %s: %s", strconv.Quote(host), strings.Join(statuses, "; "))
	}
	return nil, fmt.Errorf("DNS lookup failed for %s: %s", strconv.Quote(host), strings.Join(statuses, "; "))
}

func effectiveDNSLookupTimeout(opts Options) time.Duration {
	if opts.DNSLookupTimeout > 0 {
		return opts.DNSLookupTimeout
	}
	return defaultDNSLookupTimeout
}

func effectiveDialTimeout(clientTimeout time.Duration) time.Duration {
	if clientTimeout <= 0 {
		return defaultDialTimeout
	}
	if clientTimeout < defaultDialTimeout {
		return clientTimeout
	}
	return defaultDialTimeout
}

func rrtypeLabel(qtype uint16) string {
	if label, ok := dns.TypeToString[qtype]; ok {
		return label
	}
	return strconv.Itoa(int(qtype))
}
