package dnsresolver

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type resolverFamilyCapabilities struct {
	IPv4 bool
	IPv6 bool
}

type familyConstraintContextKey struct{}

var resolverFamilyProbeFn = detectResolverFamilyCapabilities

func withResolverFamilyConstraints(ctx context.Context, caps resolverFamilyCapabilities) context.Context {
	return context.WithValue(ctx, familyConstraintContextKey{}, caps)
}

func resolverFamilyConstraintsFromContext(ctx context.Context) (resolverFamilyCapabilities, bool) {
	caps, ok := ctx.Value(familyConstraintContextKey{}).(resolverFamilyCapabilities)
	return caps, ok
}

func detectResolverFamilyCapabilities(ctx context.Context, timeout time.Duration) resolverFamilyCapabilities {
	if timeout <= 0 {
		timeout = defaultDNSQueryTimeout
	}
	if timeout > 1500*time.Millisecond {
		timeout = 1500 * time.Millisecond
	}
	ctx = withDNSQueryTimeout(ctx, timeout)
	return resolverFamilyCapabilities{
		IPv4: probeDNSFamily(ctx, false),
		IPv6: probeDNSFamily(ctx, true),
	}
}

func probeDNSFamily(ctx context.Context, wantIPv6 bool) bool {
	var candidates []nsAddr
	for _, server := range rootHintsAny {
		ip := hostIP(server.Addr)
		if ip == nil {
			continue
		}
		isIPv6 := ip.To4() == nil
		if isIPv6 != wantIPv6 {
			continue
		}
		candidates = append(candidates, server)
		if len(candidates) >= 3 {
			break
		}
	}
	for _, candidate := range candidates {
		res, err := exchangeDNS(ctx, candidate.Addr, ".", dns.TypeNS, false)
		if err != nil {
			continue
		}
		if res != nil && res.Msg != nil {
			return true
		}
	}
	return false
}

func hostIP(endpoint string) net.IP {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

func filterNSAddrsByCapabilities(values []nsAddr, caps resolverFamilyCapabilities) []nsAddr {
	if caps.IPv4 == caps.IPv6 {
		return append([]nsAddr(nil), values...)
	}
	var out []nsAddr
	var sawIP bool
	for _, value := range values {
		ip := hostIP(value.Addr)
		if ip == nil {
			out = append(out, value)
			continue
		}
		sawIP = true
		isIPv6 := ip.To4() == nil
		if isIPv6 && caps.IPv6 {
			out = append(out, value)
		}
		if !isIPv6 && caps.IPv4 {
			out = append(out, value)
		}
	}
	if len(out) == 0 && !sawIP {
		return append([]nsAddr(nil), values...)
	}
	return out
}

func filterAuthoritativeServersByCapabilities(values []AuthoritativeServer, caps resolverFamilyCapabilities) []AuthoritativeServer {
	if caps.IPv4 == caps.IPv6 {
		return append([]AuthoritativeServer(nil), values...)
	}
	var out []AuthoritativeServer
	var sawIP bool
	for _, value := range values {
		ip := hostIP(value.Endpoint)
		if ip == nil {
			out = append(out, value)
			continue
		}
		sawIP = true
		isIPv6 := ip.To4() == nil
		if isIPv6 && caps.IPv6 {
			out = append(out, value)
		}
		if !isIPv6 && caps.IPv4 {
			out = append(out, value)
		}
	}
	if len(out) == 0 && !sawIP {
		return append([]AuthoritativeServer(nil), values...)
	}
	return out
}

type familyCapabilityCache struct {
	once sync.Once
	caps resolverFamilyCapabilities
}
