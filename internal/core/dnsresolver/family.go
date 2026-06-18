package dnsresolver

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/ipfamily"
)

type resolverFamilyCapabilities = ipfamily.Capabilities

type familyConstraintContextKey struct{}

var resolverFamilyProbeFn = ipfamily.DetectCapabilities

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
	return resolverFamilyProbeFn(ctx, timeout)
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
