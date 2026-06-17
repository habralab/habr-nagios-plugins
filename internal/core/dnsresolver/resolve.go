package dnsresolver

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var resolveExchangeFn = exchangeDNS

type FanoutMode string

const (
	FanoutFirstResponse    FanoutMode = "first_response"
	FanoutAllAuthoritative FanoutMode = "all_authoritative"
)

type ConsistencyMode string

const (
	ConsistencyIgnore  ConsistencyMode = "ignore"
	ConsistencyObserve ConsistencyMode = "observe"
	ConsistencyRequire ConsistencyMode = "require"
)

type ResolveOptions struct {
	Fanout      FanoutMode
	Consistency ConsistencyMode
}

type ResolveResult struct {
	Lookup      LookupResult
	Zone        string
	Nameservers []string
	Endpoints   []string
	Responses   []EndpointResponse
	Consistency ConsistencyAssessment
}

type AuthoritativeServer struct {
	Name     string
	Endpoint string
}

type EndpointResponse struct {
	ServerName     string
	Endpoint       string
	Network        string
	RTT            time.Duration
	RCode          int
	Authoritative  bool
	Error          string
	Records        []dns.RR
	Signatures     []*dns.RRSIG
	Authority      []dns.RR
	Additional     []dns.RR
	RawAnswerCount int
}

type ConsistencyAssessment struct {
	Mode            ConsistencyMode
	ComparableCount int
	Consistent      bool
	Baseline        string
	Mismatches      []string
}

func DefaultResolveOptions() ResolveOptions {
	return ResolveOptions{
		Fanout:      FanoutFirstResponse,
		Consistency: ConsistencyIgnore,
	}
}

// Resolve executes the resolver using a policy-driven plan.
// Lookup remains the small DNS-like API; Resolve is the richer execution API
// for probes that need fanout, consistency observation, or per-endpoint material.
func (r *Resolver) Resolve(ctx context.Context, qname string, qtype uint16, opts ResolveOptions) (ResolveResult, error) {
	ctx = withResolverFamilyConstraints(ctx, r.familyCapabilities(ctx))
	ctx = withEndpointHealthTracker(ctx, r.endpointHealth)
	if opts.Fanout == "" {
		opts.Fanout = FanoutFirstResponse
	}
	if opts.Consistency == "" {
		opts.Consistency = ConsistencyIgnore
	}

	lookup, err := r.Lookup(ctx, qname, qtype)
	if err != nil {
		return ResolveResult{}, err
	}
	result := ResolveResult{
		Lookup: lookup,
		Zone:   lookup.Zone,
	}
	if opts.Fanout != FanoutAllAuthoritative {
		return result, nil
	}

	if cached, ok := r.cachedAuthority(qname); ok {
		return r.ResolveAuthoritative(ctx, qname, qtype, authoritativeServersFromNSAddrs(cached.Servers), opts)
	}

	iter, err := r.iterativeFn(withDNSQueryTimeout(ctx, r.QueryTimeout), dns.Fqdn(qname), qtype)
	if err != nil {
		return result, err
	}
	zone, servers := finalAuthority(iter)
	r.storeAuthority(qname, authorityResult{
		Zone:    zone,
		Servers: cloneNSAddrs(servers),
		Hops:    cloneDelegationHops(iter.Hops),
	})
	r.storeZoneChain(zone, iter.Hops)
	return r.ResolveAuthoritative(ctx, qname, qtype, authoritativeServersFromNSAddrs(servers), opts)
}

func (r *Resolver) ResolveAuthoritative(ctx context.Context, qname string, qtype uint16, servers []AuthoritativeServer, opts ResolveOptions) (ResolveResult, error) {
	ctx = withResolverFamilyConstraints(ctx, r.familyCapabilities(ctx))
	ctx = withEndpointHealthTracker(ctx, r.endpointHealth)
	if opts.Fanout == "" {
		opts.Fanout = FanoutFirstResponse
	}
	if opts.Consistency == "" {
		opts.Consistency = ConsistencyIgnore
	}
	servers = filterAuthoritativeServersByCapabilities(servers, r.familyCapabilities(ctx))
	servers = orderAuthoritativeServersByHealth(ctx, servers)
	cacheKey := resolveCacheKey(dns.Fqdn(qname), qtype, servers, opts)
	r.mu.Lock()
	if cached, ok := r.resolveCache[cacheKey]; ok {
		r.mu.Unlock()
		r.recordLocalHit()
		r.appendCacheTrace("local_hit", "resolve", fmt.Sprintf("%s %s", dns.Fqdn(qname), rrtypeName(qtype)), "")
		return cached, nil
	}
	r.mu.Unlock()
	if cached, ok := r.loadSharedResolve(ctx, cacheKey, qname, qtype); ok {
		return cached, nil
	}

	return r.resolveFlights.do(ctx, cacheKey, cloneResolveResult, func(callCtx context.Context) (ResolveResult, error) {
		r.mu.Lock()
		if cached, ok := r.resolveCache[cacheKey]; ok {
			r.mu.Unlock()
			r.recordLocalHit()
			r.appendCacheTrace("local_hit", "resolve", fmt.Sprintf("%s %s", dns.Fqdn(qname), rrtypeName(qtype)), "")
			return cloneResolveResult(cached), nil
		}
		r.mu.Unlock()
		if cached, ok := r.loadSharedResolve(callCtx, cacheKey, qname, qtype); ok {
			return cached, nil
		}

		result := ResolveResult{
			Lookup: LookupResult{
				QName: dns.Fqdn(qname),
				QType: qtype,
				Zone:  dns.Fqdn(qname),
			},
			Zone:        dns.Fqdn(qname),
			Nameservers: namesFromAuthoritativeServers(servers),
			Endpoints:   endpointsFromAuthoritativeServers(servers),
		}
		if len(servers) == 0 {
			r.storeResolve(cacheKey, result)
			return result, nil
		}
		r.recordLiveResolution()
		r.appendCacheTrace("live_resolution", "resolve", fmt.Sprintf("%s %s", dns.Fqdn(qname), rrtypeName(qtype)), string(opts.Fanout))
		var baseline string
		for _, server := range uniqueAuthoritativeServers(servers) {
			endpoint := EndpointResponse{
				ServerName: dns.Fqdn(server.Name),
				Endpoint:   server.Endpoint,
			}
			res, err := resolveExchangeFn(callCtx, server.Endpoint, qname, qtype, true)
			if err != nil {
				if tracker, ok := endpointHealthTrackerFromContext(callCtx); ok {
					tracker.recordFailure(server.Endpoint, err)
				}
				endpoint.Error = err.Error()
				result.Responses = append(result.Responses, endpoint)
				continue
			}
			if tracker, ok := endpointHealthTrackerFromContext(callCtx); ok {
				tracker.recordSuccess(server.Endpoint, res.RTT)
			}
			endpoint.Network = res.Network
			endpoint.RTT = res.RTT
			endpoint.RCode = res.Msg.Rcode
			endpoint.Authoritative = res.Msg != nil && res.Msg.Authoritative
			endpoint.RawAnswerCount = len(res.Msg.Answer)
			endpoint.Authority = append([]dns.RR(nil), res.Msg.Ns...)
			endpoint.Additional = append([]dns.RR(nil), res.Msg.Extra...)
			if endpoint.Authoritative {
				endpoint.Records, endpoint.Signatures = splitAnswerRRset(res.Msg.Answer, qname, qtype)
				fp := rrsetFingerprint(endpoint.Records)
				if fp != "" && opts.Consistency != ConsistencyIgnore {
					result.Consistency.ComparableCount++
					if baseline == "" {
						baseline = fp
					} else if baseline != fp {
						result.Consistency.Mismatches = append(result.Consistency.Mismatches, server.Endpoint)
					}
				}
			}
			result.Responses = append(result.Responses, endpoint)
		}

		if opts.Consistency != ConsistencyIgnore {
			result.Consistency.Mode = opts.Consistency
			result.Consistency.Baseline = baseline
			result.Consistency.Consistent = len(result.Consistency.Mismatches) == 0
		}
		for _, response := range result.Responses {
			if response.Authoritative {
				result.Lookup.Records = append([]dns.RR(nil), response.Records...)
				result.Lookup.Signatures = append([]*dns.RRSIG(nil), response.Signatures...)
				result.Lookup.CacheTTL = lookupResultTTL(response.Records, response.Signatures, response.Authority)
				break
			}
		}
		r.storeResolve(cacheKey, result)
		r.storeSharedResolve(callCtx, cacheKey, result)
		return result, nil
	})
}

func authoritativeServersFromNSAddrs(values []nsAddr) []AuthoritativeServer {
	out := make([]AuthoritativeServer, 0, len(values))
	for _, value := range values {
		out = append(out, AuthoritativeServer{Name: value.Name, Endpoint: value.Addr})
	}
	return out
}

func namesFromAuthoritativeServers(values []AuthoritativeServer) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		name := dns.Fqdn(value.Name)
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func endpointsFromAuthoritativeServers(values []AuthoritativeServer) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		if seen[value.Endpoint] {
			continue
		}
		seen[value.Endpoint] = true
		out = append(out, value.Endpoint)
	}
	sort.Strings(out)
	return out
}

func uniqueAuthoritativeServers(values []AuthoritativeServer) []AuthoritativeServer {
	seen := map[string]bool{}
	var out []AuthoritativeServer
	for _, value := range values {
		key := dns.Fqdn(value.Name) + "|" + value.Endpoint
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, AuthoritativeServer{
			Name:     dns.Fqdn(value.Name),
			Endpoint: value.Endpoint,
		})
	}
	return out
}

func rrsetFingerprint(rrs []dns.RR) string {
	if len(rrs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		parts = append(parts, rr.String())
	}
	sort.Strings(parts)
	return strings.Join(parts, "\n")
}

func cloneResolveResult(value ResolveResult) ResolveResult {
	out := ResolveResult{
		Lookup:      cloneLookupResult(value.Lookup),
		Zone:        value.Zone,
		Nameservers: append([]string(nil), value.Nameservers...),
		Endpoints:   append([]string(nil), value.Endpoints...),
		Consistency: ConsistencyAssessment{
			Mode:            value.Consistency.Mode,
			ComparableCount: value.Consistency.ComparableCount,
			Consistent:      value.Consistency.Consistent,
			Baseline:        value.Consistency.Baseline,
			Mismatches:      append([]string(nil), value.Consistency.Mismatches...),
		},
	}
	out.Responses = make([]EndpointResponse, 0, len(value.Responses))
	for _, response := range value.Responses {
		out.Responses = append(out.Responses, EndpointResponse{
			ServerName:     response.ServerName,
			Endpoint:       response.Endpoint,
			Network:        response.Network,
			RTT:            response.RTT,
			RCode:          response.RCode,
			Authoritative:  response.Authoritative,
			Error:          response.Error,
			Records:        append([]dns.RR(nil), response.Records...),
			Signatures:     append([]*dns.RRSIG(nil), response.Signatures...),
			Authority:      append([]dns.RR(nil), response.Authority...),
			Additional:     append([]dns.RR(nil), response.Additional...),
			RawAnswerCount: response.RawAnswerCount,
		})
	}
	return out
}

func (r *Resolver) storeResolve(cacheKey string, result ResolveResult) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resolveCache[cacheKey] = result
}

func resolveCacheKey(qname string, qtype uint16, servers []AuthoritativeServer, opts ResolveOptions) string {
	parts := make([]string, 0, len(servers))
	for _, server := range uniqueAuthoritativeServers(servers) {
		parts = append(parts, dns.Fqdn(server.Name)+"@"+server.Endpoint)
	}
	sort.Strings(parts)
	return qname + "|" + rrtypeName(qtype) + "|" + string(opts.Fanout) + "|" + string(opts.Consistency) + "|" + strings.Join(parts, ",")
}
