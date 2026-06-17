package dnsresolver

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

type ServerAddr struct {
	Name string
	Addr string
}

type DelegationHopInfo struct {
	FromZone      string
	ToZone        string
	ParentServer  ServerAddr
	ParentServers []ServerAddr
	ChildNS       []string
	ChildServers  []ServerAddr
	CacheTTL      time.Duration
}

type RootTrustResult struct {
	Server        ServerAddr
	Matched       int
	Missing       int
	ValidatedKeys []*dns.DNSKEY
}

func RootTrustAnchorCount() int {
	return len(rootTrustAnchors)
}

func (r *Resolver) DiscoverEnclosingZone(ctx context.Context, qname string) (string, []DelegationHopInfo, error) {
	ctx = withResolverFamilyConstraints(ctx, r.familyCapabilities(ctx))
	ctx = withEndpointHealthTracker(ctx, r.endpointHealth)
	if cached, ok := r.cachedAuthority(qname); ok {
		if len(cached.Hops) == 0 {
			return cached.Zone, nil, nil
		}
		return cached.Zone, exportedDelegationHops(cached.Hops), nil
	}
	if cached, ok := r.loadSharedAuthority(ctx, qname); ok {
		if len(cached.Hops) == 0 {
			return cached.Zone, nil, nil
		}
		return cached.Zone, exportedDelegationHops(cached.Hops), nil
	}
	iter, err := r.iterativeFn(withDNSQueryTimeout(ctx, r.QueryTimeout), dns.Fqdn(qname), dns.TypeNS)
	if err != nil {
		return "", nil, err
	}
	r.recordLiveResolution()
	r.appendCacheTrace("live_resolution", "authority", dns.Fqdn(qname), "discover enclosing zone")
	if len(iter.Hops) == 0 {
		return "", nil, fmt.Errorf("no delegation hops discovered for %s", dns.Fqdn(qname))
	}
	zone := iter.Hops[len(iter.Hops)-1].ToZone
	r.storeAuthority(qname, authorityResult{
		Zone:     zone,
		Servers:  cloneNSAddrs(iter.Hops[len(iter.Hops)-1].ChildServers),
		Hops:     cloneDelegationHops(iter.Hops),
		CacheTTL: authorityResultTTL(iter.Hops),
	})
	r.storeZoneChain(zone, iter.Hops)
	r.storeSharedAuthority(ctx, qname, authorityResult{
		Zone:     zone,
		Servers:  cloneNSAddrs(iter.Hops[len(iter.Hops)-1].ChildServers),
		Hops:     cloneDelegationHops(iter.Hops),
		CacheTTL: authorityResultTTL(iter.Hops),
	})
	r.storeSharedZoneChain(ctx, zone, iter.Hops)
	return zone, exportedDelegationHops(iter.Hops), nil
}

func (r *Resolver) ZoneChain(ctx context.Context, zone string) ([]DelegationHopInfo, error) {
	ctx = withResolverFamilyConstraints(ctx, r.familyCapabilities(ctx))
	ctx = withEndpointHealthTracker(ctx, r.endpointHealth)
	if cached, ok := r.cachedZoneChain(zone); ok {
		return exportedDelegationHops(cached), nil
	}
	if cached, ok := r.loadSharedZoneChain(ctx, zone); ok {
		return exportedDelegationHops(cached), nil
	}
	hops, err := buildZoneChain(withDNSQueryTimeout(ctx, r.QueryTimeout), zone)
	if err != nil {
		return nil, err
	}
	r.recordLiveResolution()
	r.appendCacheTrace("live_resolution", "delegation", dns.Fqdn(zone), "")
	r.storeZoneChain(zone, hops)
	r.storeSharedZoneChain(ctx, zone, hops)
	return exportedDelegationHops(hops), nil
}

func (r *Resolver) ProbeRootTrust(ctx context.Context) (RootTrustResult, error) {
	ctx = withResolverFamilyConstraints(ctx, r.familyCapabilities(ctx))
	ctx = withEndpointHealthTracker(ctx, r.endpointHealth)
	now := time.Now().UTC()
	res, err := queryAny(withDNSQueryTimeout(ctx, r.QueryTimeout), rootHintsAny, ".", dns.TypeDNSKEY, true)
	if err != nil {
		return RootTrustResult{}, err
	}
	keys, sigs := splitDNSKEYAnswer(res.Msg.Answer, ".")
	matched, missing, anchoredKeys := countRootTrustAnchorMatches(keys)
	if matched == 0 {
		return RootTrustResult{}, fmt.Errorf("none of the embedded root trust anchors matched the published root DNSKEY RRset")
	}
	if len(sigs) == 0 {
		return RootTrustResult{}, fmt.Errorf("root DNSKEY RRset had no RRSIG records")
	}
	if err := verifyRRSetWithDNSKEYs(anchoredKeys, sigs, dnskeysToRRs(keys), now); err != nil {
		return RootTrustResult{}, fmt.Errorf("root DNSKEY RRset signature validation failed: %w", err)
	}
	return RootTrustResult{
		Server:        ServerAddr{Name: res.Server.Name, Addr: res.Server.Addr},
		Matched:       matched,
		Missing:       missing,
		ValidatedKeys: append([]*dns.DNSKEY(nil), keys...),
	}, nil
}

func exportedDelegationHops(values []delegationHop) []DelegationHopInfo {
	out := make([]DelegationHopInfo, 0, len(values))
	for _, value := range values {
		out = append(out, DelegationHopInfo{
			FromZone:      value.FromZone,
			ToZone:        value.ToZone,
			ParentServer:  exportedServer(value.ParentServer),
			ParentServers: exportedServers(value.ParentServers),
			ChildNS:       append([]string(nil), value.ChildNS...),
			ChildServers:  exportedServers(value.ChildServers),
			CacheTTL:      value.CacheTTL,
		})
	}
	return out
}

func exportedServer(value nsAddr) ServerAddr {
	return ServerAddr(value)
}

func exportedServers(values []nsAddr) []ServerAddr {
	out := make([]ServerAddr, 0, len(values))
	for _, value := range values {
		out = append(out, exportedServer(value))
	}
	return out
}

func AuthoritativeServersFromAddrs(values []ServerAddr) []AuthoritativeServer {
	out := make([]AuthoritativeServer, 0, len(values))
	for _, value := range values {
		out = append(out, AuthoritativeServer{Name: value.Name, Endpoint: value.Addr})
	}
	return UniqueAuthoritativeServers(out)
}

func UniqueAuthoritativeServers(values []AuthoritativeServer) []AuthoritativeServer {
	return uniqueAuthoritativeServers(values)
}

func (r *Resolver) ResolveHostEndpoints(ctx context.Context, host string) ([]AuthoritativeServer, error) {
	var out []AuthoritativeServer
	for _, item := range r.LookupBatch(ctx, []Question{
		{QName: host, QType: dns.TypeA},
		{QName: host, QType: dns.TypeAAAA},
	}) {
		if item.Err != nil {
			continue
		}
		for _, rr := range item.Result.Records {
			switch v := rr.(type) {
			case *dns.A:
				out = append(out, AuthoritativeServer{Name: dns.Fqdn(host), Endpoint: net.JoinHostPort(v.A.String(), "53")})
			case *dns.AAAA:
				out = append(out, AuthoritativeServer{Name: dns.Fqdn(host), Endpoint: net.JoinHostPort(v.AAAA.String(), "53")})
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no A or AAAA records were found")
	}
	return UniqueAuthoritativeServers(out), nil
}
