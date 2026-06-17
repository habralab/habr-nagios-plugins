package dnsresolver

import (
	"context"
	"fmt"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/sharedcache"
	"github.com/miekg/dns"
)

func (r *Resolver) SetSharedCacheBackend(backend sharedcache.Backend) {
	if backend == nil {
		backend = sharedcache.NoopBackend{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sharedCache = backend
	if _, ok := backend.(sharedcache.NoopBackend); ok {
		r.sharedCacheDesc = sharedcache.BackendDescriptor{
			Kind:        "internal",
			External:    false,
			Supported:   true,
			Description: "per-run internal cache only; external shared cache backend is disabled",
		}
		return
	}
	r.sharedCacheDesc = sharedcache.BackendDescriptor{
		Kind:        "custom",
		External:    true,
		Supported:   true,
		Description: "custom shared cache backend",
	}
}

func (r *Resolver) SetSharedCacheBackendWithDescriptor(backend sharedcache.Backend, descriptor sharedcache.BackendDescriptor) {
	if backend == nil {
		backend = sharedcache.NoopBackend{}
	}
	if descriptor.Kind == "" {
		descriptor = sharedcache.BackendDescriptor{
			Kind:        "internal",
			External:    false,
			Supported:   true,
			Description: "per-run internal cache only; external shared cache backend descriptor was not provided",
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sharedCache = backend
	r.sharedCacheDesc = descriptor
}

func (r *Resolver) SharedCacheDescriptor() sharedcache.BackendDescriptor {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sharedCacheDesc
}

func (r *Resolver) ConfigureSharedCacheBackendDSN(dsn string) sharedcache.BackendDescriptor {
	timeout := 500 * time.Millisecond
	if r.QueryTimeout > 0 && r.QueryTimeout < timeout {
		timeout = r.QueryTimeout
	}
	backend, descriptor, err := sharedcache.NewBackendWithDescriptorFromDSN(dsn, timeout)
	if err != nil {
		r.SetSharedCacheBackendWithDescriptor(sharedcache.NoopBackend{}, descriptor)
		return descriptor
	}
	r.SetSharedCacheBackendWithDescriptor(backend, descriptor)
	return descriptor
}

func (r *Resolver) sharedCacheBackend() sharedcache.Backend {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sharedCache == nil {
		return sharedcache.NoopBackend{}
	}
	return r.sharedCache
}

func (r *Resolver) sharedCacheEnabled() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sharedCacheDesc.External
}

func (r *Resolver) loadSharedLookup(ctx context.Context, qname string, qtype uint16) (LookupResult, bool) {
	enabled := r.sharedCacheEnabled()
	data, err := r.sharedCacheBackend().Get(ctx, sharedCacheLookupKey(qname, qtype))
	if err != nil {
		if enabled {
			r.recordSharedMiss()
			r.appendCacheTrace("shared_miss", "lookup", fmt.Sprintf("%s %s", dns.Fqdn(qname), rrtypeName(qtype)), err.Error())
		}
		return LookupResult{}, false
	}
	lookup, _, err := unmarshalLookupArtifact(data)
	if err != nil {
		if enabled {
			r.recordSharedMiss()
			r.appendCacheTrace("shared_miss", "lookup", fmt.Sprintf("%s %s", dns.Fqdn(qname), rrtypeName(qtype)), "artifact decode failed")
		}
		return LookupResult{}, false
	}
	if enabled {
		r.recordSharedHit()
		r.appendCacheTrace("shared_hit", "lookup", fmt.Sprintf("%s %s", dns.Fqdn(qname), rrtypeName(qtype)), "")
	}
	r.storeLookup(lookupCacheKey(qname, qtype), lookup)
	return lookup, true
}

func (r *Resolver) loadSharedResolve(ctx context.Context, resolveKey, qname string, qtype uint16) (ResolveResult, bool) {
	enabled := r.sharedCacheEnabled()
	data, err := r.sharedCacheBackend().Get(ctx, sharedCacheResolveKey(resolveKey))
	if err != nil {
		if enabled {
			r.recordSharedMiss()
			r.appendCacheTrace("shared_miss", "resolve", fmt.Sprintf("%s %s", dns.Fqdn(qname), rrtypeName(qtype)), err.Error())
		}
		return ResolveResult{}, false
	}
	value, _, err := unmarshalResolveArtifact(data)
	if err != nil {
		if enabled {
			r.recordSharedMiss()
			r.appendCacheTrace("shared_miss", "resolve", fmt.Sprintf("%s %s", dns.Fqdn(qname), rrtypeName(qtype)), "artifact decode failed")
		}
		return ResolveResult{}, false
	}
	if enabled {
		r.recordSharedHit()
		r.appendCacheTrace("shared_hit", "resolve", fmt.Sprintf("%s %s", dns.Fqdn(qname), rrtypeName(qtype)), "")
	}
	r.storeResolve(resolveKey, value)
	return value, true
}

func (r *Resolver) storeSharedLookup(ctx context.Context, value LookupResult) {
	if value.CacheTTL <= 0 {
		return
	}
	if !r.sharedCacheEnabled() {
		return
	}
	data, err := marshalLookupArtifact(value)
	if err != nil {
		return
	}
	if err := r.sharedCacheBackend().Set(ctx, sharedCacheLookupKey(value.QName, value.QType), data, value.CacheTTL); err == nil {
		r.recordSharedWrite()
		r.appendCacheTrace("shared_write", "lookup", fmt.Sprintf("%s %s", value.QName, rrtypeName(value.QType)), value.CacheTTL.String())
	}
}

func (r *Resolver) storeSharedResolve(ctx context.Context, resolveKey string, value ResolveResult) {
	if !r.sharedCacheEnabled() {
		return
	}
	ttl := resolveResultTTL(value)
	if ttl <= 0 {
		return
	}
	data, err := marshalResolveArtifact(value)
	if err != nil {
		return
	}
	if err := r.sharedCacheBackend().Set(ctx, sharedCacheResolveKey(resolveKey), data, ttl); err == nil {
		r.recordSharedWrite()
		r.appendCacheTrace("shared_write", "resolve", fmt.Sprintf("%s %s", value.Lookup.QName, rrtypeName(value.Lookup.QType)), ttl.String())
	}
}

func (r *Resolver) loadSharedValidation(ctx context.Context, zone string) (validationResult, bool) {
	enabled := r.sharedCacheEnabled()
	data, err := r.sharedCacheBackend().Get(ctx, sharedCacheValidationKey(zone))
	if err != nil {
		if enabled {
			r.recordSharedMiss()
			r.appendCacheTrace("shared_miss", "validation", dns.Fqdn(zone), err.Error())
		}
		return validationResult{}, false
	}
	value, _, err := unmarshalValidationArtifact(data)
	if err != nil {
		if enabled {
			r.recordSharedMiss()
			r.appendCacheTrace("shared_miss", "validation", dns.Fqdn(zone), "artifact decode failed")
		}
		return validationResult{}, false
	}
	if enabled {
		r.recordSharedHit()
		r.appendCacheTrace("shared_hit", "validation", dns.Fqdn(zone), "")
	}
	r.storeValidation(zone, value)
	return value, true
}

func (r *Resolver) storeSharedValidation(ctx context.Context, zone string, value validationResult) {
	if value.CacheTTL <= 0 {
		return
	}
	if !r.sharedCacheEnabled() {
		return
	}
	data, err := marshalValidationArtifact(value)
	if err != nil {
		return
	}
	if err := r.sharedCacheBackend().Set(ctx, sharedCacheValidationKey(zone), data, value.CacheTTL); err == nil {
		r.recordSharedWrite()
		r.appendCacheTrace("shared_write", "validation", dns.Fqdn(zone), value.CacheTTL.String())
	}
}

func (r *Resolver) loadSharedAuthority(ctx context.Context, qname string) (authorityResult, bool) {
	enabled := r.sharedCacheEnabled()
	for _, candidate := range sharedAuthorityLookupCandidates(qname) {
		data, err := r.sharedCacheBackend().Get(ctx, sharedCacheAuthorityKey(candidate))
		if err != nil {
			if enabled {
				r.recordSharedMiss()
				r.appendCacheTrace("shared_miss", "authority", dns.Fqdn(candidate), err.Error())
			}
			continue
		}
		value, _, err := unmarshalAuthorityArtifact(data)
		if err != nil {
			if enabled {
				r.recordSharedMiss()
				r.appendCacheTrace("shared_miss", "authority", dns.Fqdn(candidate), "artifact decode failed")
			}
			continue
		}
		if enabled {
			r.recordSharedHit()
			detail := ""
			if dns.Fqdn(candidate) != dns.Fqdn(qname) {
				detail = "ancestor authority reused"
			}
			r.appendCacheTrace("shared_hit", "authority", dns.Fqdn(candidate), detail)
		}
		r.storeAuthority(qname, value)
		if value.Zone != "" {
			if len(value.Hops) > 0 {
				r.storeZoneChain(value.Zone, value.Hops)
			} else if hops, ok := r.loadSharedZoneChain(ctx, value.Zone); ok {
				value.Hops = hops
				r.storeAuthority(qname, value)
			}
		}
		return value, true
	}
	return authorityResult{}, false
}

func (r *Resolver) storeSharedAuthority(ctx context.Context, qname string, value authorityResult) {
	if !r.sharedCacheEnabled() {
		return
	}
	storeSharedAuthorityArtifact(ctx, r, qname, value)
	for _, zone := range sharedAuthorityVariantZones(value.Zone, value.Hops) {
		variant, ok := authorityResultForZone(zone, value.Hops)
		if !ok {
			continue
		}
		storeSharedAuthorityArtifact(ctx, r, zone, variant)
	}
}

func (r *Resolver) loadSharedZoneChain(ctx context.Context, zone string) ([]delegationHop, bool) {
	enabled := r.sharedCacheEnabled()
	data, err := r.sharedCacheBackend().Get(ctx, sharedCacheDelegationKey(zone))
	if err != nil {
		if enabled {
			r.recordSharedMiss()
			r.appendCacheTrace("shared_miss", "delegation", dns.Fqdn(zone), err.Error())
		}
		return nil, false
	}
	value, _, err := unmarshalZoneChainArtifact(data)
	if err != nil {
		if enabled {
			r.recordSharedMiss()
			r.appendCacheTrace("shared_miss", "delegation", dns.Fqdn(zone), "artifact decode failed")
		}
		return nil, false
	}
	if enabled {
		r.recordSharedHit()
		r.appendCacheTrace("shared_hit", "delegation", dns.Fqdn(zone), "")
	}
	r.storeZoneChain(zone, value)
	return value, true
}

func (r *Resolver) storeSharedZoneChain(ctx context.Context, zone string, hops []delegationHop) {
	if !r.sharedCacheEnabled() {
		return
	}
	for _, variant := range sharedZoneChainVariants(zone, hops) {
		ttl := zoneChainTTL(variant.Hops)
		if ttl <= 0 {
			continue
		}
		data, err := marshalZoneChainArtifact(variant.Hops)
		if err != nil {
			continue
		}
		if err := r.sharedCacheBackend().Set(ctx, sharedCacheDelegationKey(variant.Zone), data, ttl); err == nil {
			r.recordSharedWrite()
			r.appendCacheTrace("shared_write", "delegation", dns.Fqdn(variant.Zone), ttl.String())
		}
	}
}

func storeSharedAuthorityArtifact(ctx context.Context, r *Resolver, key string, value authorityResult) {
	if value.CacheTTL <= 0 {
		return
	}
	data, err := marshalAuthorityArtifact(compactSharedAuthorityValue(value))
	if err != nil {
		return
	}
	if err := r.sharedCacheBackend().Set(ctx, sharedCacheAuthorityKey(key), data, value.CacheTTL); err == nil {
		r.recordSharedWrite()
		r.appendCacheTrace("shared_write", "authority", dns.Fqdn(key), value.CacheTTL.String())
	}
}

func compactSharedAuthorityValue(value authorityResult) authorityResult {
	return authorityResult{
		Zone:     dns.Fqdn(value.Zone),
		Servers:  cloneNSAddrs(value.Servers),
		Hops:     nil,
		CacheTTL: value.CacheTTL,
	}
}

func sharedAuthorityLookupCandidates(qname string) []string {
	fqdn := dns.Fqdn(qname)
	seen := map[string]bool{fqdn: true}
	out := []string{fqdn}
	ancestors := ancestorZonesInclusive(fqdn)
	for i := len(ancestors) - 1; i >= 0; i-- {
		candidate := dns.Fqdn(ancestors[i])
		if candidate == "." || seen[candidate] {
			continue
		}
		seen[candidate] = true
		out = append(out, candidate)
	}
	return out
}

func sharedAuthorityVariantZones(zone string, hops []delegationHop) []string {
	fqdn := dns.Fqdn(zone)
	if fqdn == "" || fqdn == "." || len(hops) == 0 {
		return nil
	}
	seen := map[string]bool{fqdn: true}
	var out []string
	for _, hop := range hops {
		candidate := dns.Fqdn(hop.ToZone)
		if candidate == "." || seen[candidate] {
			continue
		}
		seen[candidate] = true
		out = append(out, candidate)
	}
	return out
}

type sharedZoneChainVariant struct {
	Zone string
	Hops []delegationHop
}

func sharedZoneChainVariants(zone string, hops []delegationHop) []sharedZoneChainVariant {
	fqdn := dns.Fqdn(zone)
	if fqdn == "" || fqdn == "." || len(hops) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []sharedZoneChainVariant
	for i := range hops {
		candidate := dns.Fqdn(hops[i].ToZone)
		if candidate == "." || seen[candidate] {
			continue
		}
		seen[candidate] = true
		out = append(out, sharedZoneChainVariant{
			Zone: candidate,
			Hops: cloneDelegationHops(hops[:i+1]),
		})
	}
	return out
}
