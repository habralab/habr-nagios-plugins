package dnsprobe

import (
	"context"
	"fmt"
	"strings"

	"github.com/habralab/habr-nagios-plugins/internal/core/dnsresolver"
	"github.com/miekg/dns"
)

type AuthorityDiscoveryInput struct {
	Owner        string
	ExplicitZone string
}

type AuthorityDiscovery struct {
	Owner         string
	Zone          string
	ParentZone    string
	DelegationNS  []string
	ParentServers []dnsresolver.ServerAddr
	ChildServers  []dnsresolver.ServerAddr
	Hops          []dnsresolver.DelegationHopInfo
}

type FormalMasterDiscovery struct {
	Name      string
	Endpoints []dnsresolver.AuthoritativeServer
}

func DiscoverAuthority(ctx context.Context, resolver *dnsresolver.Resolver, input AuthorityDiscoveryInput) (*AuthorityDiscovery, error) {
	owner := dns.Fqdn(strings.TrimSpace(input.Owner))
	zone := dns.Fqdn(strings.TrimSpace(input.ExplicitZone))
	var hops []dnsresolver.DelegationHopInfo
	var err error

	if zone == "." {
		zone = ""
	}
	if zone == "" {
		zone, hops, err = resolver.DiscoverEnclosingZone(ctx, owner)
		if err != nil {
			return nil, fmt.Errorf("enclosing zone discovery failed for %s: %w", owner, err)
		}
	}
	if len(hops) == 0 {
		hops, err = resolver.ZoneChain(ctx, zone)
		if err != nil {
			return nil, fmt.Errorf("zone discovery failed for %s: %w", zone, err)
		}
	}
	if len(hops) == 0 {
		return nil, fmt.Errorf("no authoritative delegation hops discovered for %s", zone)
	}
	last := hops[len(hops)-1]
	return &AuthorityDiscovery{
		Owner:         owner,
		Zone:          last.ToZone,
		ParentZone:    last.FromZone,
		DelegationNS:  append([]string(nil), last.ChildNS...),
		ParentServers: append([]dnsresolver.ServerAddr(nil), last.ParentServers...),
		ChildServers:  append([]dnsresolver.ServerAddr(nil), last.ChildServers...),
		Hops:          append([]dnsresolver.DelegationHopInfo(nil), hops...),
	}, nil
}

func DiscoverFormalMaster(ctx context.Context, resolver *dnsresolver.Resolver, zone string, servers []dnsresolver.AuthoritativeServer) (*FormalMasterDiscovery, error) {
	resolved, err := resolver.ResolveAuthoritative(ctx, zone, dns.TypeSOA, servers, dnsresolver.ResolveOptions{
		Fanout:      dnsresolver.FanoutAllAuthoritative,
		Consistency: dnsresolver.ConsistencyObserve,
	})
	if err != nil {
		return nil, fmt.Errorf("SOA lookup for master discovery failed: %w", err)
	}
	var mname string
	for _, response := range resolved.Responses {
		for _, rr := range response.Records {
			if soa, ok := rr.(*dns.SOA); ok {
				mname = dns.Fqdn(soa.Ns)
				break
			}
		}
		if mname != "" {
			break
		}
	}
	if mname == "" {
		return nil, fmt.Errorf("formal master could not be determined because no authoritative SOA answer was available")
	}
	endpoints, err := resolver.ResolveHostEndpoints(ctx, mname)
	if err != nil || len(endpoints) == 0 {
		msg := fmt.Sprintf("formal master %s could not be resolved to usable A/AAAA endpoints", mname)
		if err != nil {
			msg = fmt.Sprintf("%s: %v", msg, err)
		}
		return nil, fmt.Errorf("%s", msg)
	}
	return &FormalMasterDiscovery{
		Name:      mname,
		Endpoints: endpoints,
	}, nil
}
