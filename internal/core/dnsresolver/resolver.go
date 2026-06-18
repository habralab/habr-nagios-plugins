package dnsresolver

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/ipfamily"
	"github.com/habralab/habr-nagios-plugins/internal/core/sharedcache"
	"github.com/miekg/dns"
)

type SecurityState string

const (
	SecuritySecure        SecurityState = "secure"
	SecurityInsecure      SecurityState = "insecure"
	SecurityBogus         SecurityState = "bogus"
	SecurityIndeterminate SecurityState = "indeterminate"
)

type LookupResult struct {
	QName               string
	QType               uint16
	Zone                string
	Records             []dns.RR
	Signatures          []*dns.RRSIG
	Security            SecurityState
	AuthenticatedNoData bool
	ValidationMessage   string
	CacheTTL            time.Duration
}

type EffectiveCAAResult struct {
	EffectiveName string
	Lookup        LookupResult
}

type CacheStats struct {
	LocalHits       int64 `json:"local_hits"`
	SharedHits      int64 `json:"shared_hits"`
	SharedMisses    int64 `json:"shared_misses"`
	LiveResolutions int64 `json:"live_resolutions"`
	SharedWrites    int64 `json:"shared_writes"`
}

func (s CacheStats) TotalHits() int64 {
	return s.LocalHits + s.SharedHits
}

func (s CacheStats) TotalLookups() int64 {
	return s.TotalHits() + s.LiveResolutions
}

func (s CacheStats) HitRatio() float64 {
	total := s.TotalLookups()
	if total == 0 {
		return 0
	}
	return float64(s.TotalHits()) / float64(total)
}

type resolverCacheStats struct {
	localHits       atomic.Int64
	sharedHits      atomic.Int64
	sharedMisses    atomic.Int64
	liveResolutions atomic.Int64
	sharedWrites    atomic.Int64
}

type CacheTrace struct {
	Action   string `json:"action"`
	Artifact string `json:"artifact"`
	Subject  string `json:"subject"`
	Detail   string `json:"detail,omitempty"`
}

type Resolver struct {
	QueryTimeout    time.Duration
	mu              sync.Mutex
	lookupCache     map[string]LookupResult
	resolveCache    map[string]ResolveResult
	validateCache   map[string]validationResult
	authorityCache  map[string]authorityResult
	zoneChainCache  map[string][]delegationHop
	lookupFlights   *flightGroup[LookupResult]
	resolveFlights  *flightGroup[ResolveResult]
	validateFlights *flightGroup[validationResult]
	sharedCache     sharedcache.Backend
	sharedCacheDesc sharedcache.BackendDescriptor
	familyPolicy    ipfamily.Policy
	hostAddrCache   *hostAddressCache
	execPolicy      executionPolicy
	endpointHealth  *endpointHealthTracker
	familyCaps      familyCapabilityCache
	cacheStats      resolverCacheStats
	cacheTraceMu    sync.Mutex
	cacheTrace      []CacheTrace
	iterativeFn     func(context.Context, string, uint16) (*iterativeResult, error)
	validateFn      func(context.Context, string, []nsAddr) (SecurityState, []*dns.DNSKEY, string, error)
}

var buildZoneChainFn = buildZoneChain

// NewResolver creates a per-session authoritative DNS/DNSSEC resolver.
// Its caches are scoped to this resolver instance so a single probe run can
// reuse repeated lookups and zone validations without sharing state across runs.
func NewResolver(queryTimeout time.Duration) *Resolver {
	r := &Resolver{
		QueryTimeout:    queryTimeout,
		lookupCache:     map[string]LookupResult{},
		resolveCache:    map[string]ResolveResult{},
		validateCache:   map[string]validationResult{},
		authorityCache:  map[string]authorityResult{},
		zoneChainCache:  map[string][]delegationHop{},
		lookupFlights:   newFlightGroup[LookupResult](),
		resolveFlights:  newFlightGroup[ResolveResult](),
		validateFlights: newFlightGroup[validationResult](),
		sharedCache:     sharedcache.NoopBackend{},
		sharedCacheDesc: sharedcache.BackendDescriptor{
			Kind:        "internal",
			External:    false,
			Supported:   true,
			Description: "per-run internal cache only; no external shared cache backend is configured",
		},
		familyPolicy:   ipfamily.PolicyAuto,
		hostAddrCache:  newHostAddressCache(),
		execPolicy:     defaultExecutionPolicy(),
		endpointHealth: newEndpointHealthTracker(),
	}
	r.iterativeFn = func(ctx context.Context, qname string, qtype uint16) (*iterativeResult, error) {
		return resolveIterative(ctx, qname, qtype)
	}
	r.validateFn = r.validateZoneChain
	return r
}

func (r *Resolver) familyCapabilities(ctx context.Context) resolverFamilyCapabilities {
	if !r.familyPolicy.RequiresDetection() {
		return r.familyPolicy.EffectiveCapabilities(resolverFamilyCapabilities{})
	}
	if r.QueryTimeout == 0 {
		return resolverFamilyCapabilities{IPv4: true, IPv6: true}
	}
	r.familyCaps.once.Do(func() {
		r.familyCaps.caps = resolverFamilyProbeFn(ctx, r.QueryTimeout)
	})
	return r.familyPolicy.EffectiveCapabilities(r.familyCaps.caps)
}

func (r *Resolver) SetTransportFamilyPolicy(policy ipfamily.Policy) {
	if policy == "" {
		policy = ipfamily.PolicyAuto
	}
	r.familyPolicy = policy
}

func (r *Resolver) TransportFamilyPolicy() ipfamily.Policy {
	if r.familyPolicy == "" {
		return ipfamily.PolicyAuto
	}
	return r.familyPolicy
}

type validationResult struct {
	Security SecurityState
	Keys     []*dns.DNSKEY
	Message  string
	CacheTTL time.Duration
}

type authorityResult struct {
	Zone     string
	Servers  []nsAddr
	Hops     []delegationHop
	CacheTTL time.Duration
}

func (r *Resolver) Lookup(ctx context.Context, qname string, qtype uint16) (LookupResult, error) {
	ctx = withDNSQueryTimeout(ctx, r.QueryTimeout)
	ctx = withResolverFamilyConstraints(ctx, r.familyCapabilities(ctx))
	ctx = withHostAddressCache(ctx, r.hostAddrCache)
	ctx = withEndpointHealthTracker(ctx, r.endpointHealth)
	fqdn := dns.Fqdn(qname)
	cacheKey := lookupCacheKey(fqdn, qtype)

	r.mu.Lock()
	if cached, ok := r.lookupCache[cacheKey]; ok {
		r.mu.Unlock()
		r.recordLocalHit()
		r.appendCacheTrace("local_hit", "lookup", fmt.Sprintf("%s %s", fqdn, rrtypeName(qtype)), "")
		return cached, nil
	}
	r.mu.Unlock()
	if cached, ok := r.loadSharedLookup(ctx, fqdn, qtype); ok {
		return cached, nil
	}

	return r.lookupFlights.do(ctx, cacheKey, cloneLookupResult, func(callCtx context.Context) (LookupResult, error) {
		r.mu.Lock()
		if cached, ok := r.lookupCache[cacheKey]; ok {
			r.mu.Unlock()
			r.recordLocalHit()
			r.appendCacheTrace("local_hit", "lookup", fmt.Sprintf("%s %s", fqdn, rrtypeName(qtype)), "")
			return cloneLookupResult(cached), nil
		}
		r.mu.Unlock()
		if cached, ok := r.loadSharedLookup(callCtx, fqdn, qtype); ok {
			return cached, nil
		}

		r.recordLiveResolution()
		r.appendCacheTrace("live_resolution", "lookup", fmt.Sprintf("%s %s", fqdn, rrtypeName(qtype)), "")
		iter, authority, err := r.lookupWithAuthority(callCtx, fqdn, qtype)
		if err != nil {
			return LookupResult{}, err
		}

		zone, servers := authority.Zone, authority.Servers
		result := LookupResult{
			QName: fqdn,
			QType: qtype,
			Zone:  zone,
		}

		secureState, trustedKeys, validationMessage, err := r.cachedZoneValidation(callCtx, zone, servers)
		if err != nil {
			return result, err
		}

		records, sigs := splitAnswerRRset(iter.Response.Msg.Answer, fqdn, qtype)
		result.Records = records
		result.Signatures = sigs
		result.CacheTTL = lookupResultTTL(records, sigs, iter.Response.Msg.Ns)

		switch secureState {
		case SecuritySecure:
			if len(records) > 0 {
				if len(sigs) == 0 {
					result.Security = SecurityBogus
					result.ValidationMessage = fmt.Sprintf("secure DNSSEC chain reached %s, but the %s RRset was returned without RRSIG coverage", fqdn, rrtypeName(qtype))
					return result, nil
				}
				if err := verifyRRSetWithDNSKEYs(trustedKeys, sigs, records, time.Now().UTC()); err != nil {
					result.Security = SecurityBogus
					result.ValidationMessage = fmt.Sprintf("secure DNSSEC chain reached %s, but %s RRset signature validation failed: %v", fqdn, rrtypeName(qtype), err)
					return result, nil
				}
				result.Security = SecuritySecure
				result.ValidationMessage = fmt.Sprintf("DNSSEC chain to %s validated successfully and the %s RRset signatures verified", zone, rrtypeName(qtype))
				r.storeLookup(cacheKey, result)
				r.storeSharedLookup(callCtx, result)
				return result, nil
			}

			ok, message, err := validateNoDataProof(fqdn, qtype, iter.Response.Msg.Ns, trustedKeys, time.Now().UTC())
			if err != nil {
				result.Security = SecurityBogus
				result.ValidationMessage = fmt.Sprintf("secure DNSSEC chain reached %s, but denial proof validation failed: %v", zone, err)
				return result, nil
			}
			if ok {
				result.Security = SecuritySecure
				result.AuthenticatedNoData = true
				result.ValidationMessage = message
				r.storeLookup(cacheKey, result)
				r.storeSharedLookup(callCtx, result)
				return result, nil
			}

			result.Security = SecurityIndeterminate
			result.ValidationMessage = message
			r.storeLookup(cacheKey, result)
			r.storeSharedLookup(callCtx, result)
			return result, nil

		case SecurityInsecure:
			result.Security = SecurityInsecure
			result.ValidationMessage = validationMessage
			r.storeLookup(cacheKey, result)
			r.storeSharedLookup(callCtx, result)
			return result, nil

		case SecurityBogus:
			result.Security = SecurityBogus
			result.ValidationMessage = validationMessage
			r.storeLookup(cacheKey, result)
			r.storeSharedLookup(callCtx, result)
			return result, nil

		default:
			result.Security = SecurityIndeterminate
			result.ValidationMessage = validationMessage
			r.storeLookup(cacheKey, result)
			r.storeSharedLookup(callCtx, result)
			return result, nil
		}
	})
}

func (r *Resolver) lookupWithAuthority(ctx context.Context, fqdn string, qtype uint16) (*iterativeResult, authorityResult, error) {
	if cached, ok := r.cachedAuthority(fqdn); ok {
		res, err := queryAny(ctx, cached.Servers, fqdn, qtype, true)
		if err != nil {
			return nil, authorityResult{}, err
		}
		cached = r.refineAuthorityFromMessage(ctx, fqdn, cached, res.Msg)
		return &iterativeResult{
			Response: *res,
			Hops:     cloneDelegationHops(cached.Hops),
		}, cached, nil
	}
	if cached, ok := r.loadSharedAuthority(ctx, fqdn); ok {
		res, err := queryAny(ctx, cached.Servers, fqdn, qtype, true)
		if err != nil {
			return nil, authorityResult{}, err
		}
		cached = r.refineAuthorityFromMessage(ctx, fqdn, cached, res.Msg)
		return &iterativeResult{
			Response: *res,
			Hops:     cloneDelegationHops(cached.Hops),
		}, cached, nil
	}

	iter, err := r.iterativeFn(ctx, fqdn, qtype)
	if err != nil {
		return nil, authorityResult{}, err
	}
	zone, servers := finalAuthority(iter)
	authority := authorityResult{
		Zone:     zone,
		Servers:  cloneNSAddrs(servers),
		Hops:     cloneDelegationHops(iter.Hops),
		CacheTTL: authorityResultTTL(iter.Hops),
	}
	r.storeAuthority(fqdn, authority)
	r.storeZoneChain(zone, iter.Hops)
	r.storeSharedAuthority(ctx, fqdn, authority)
	r.storeSharedZoneChain(ctx, zone, iter.Hops)
	return iter, authority, nil
}

func (r *Resolver) refineAuthorityFromMessage(ctx context.Context, qname string, authority authorityResult, msg *dns.Msg) authorityResult {
	effectiveZone := authoritativeZoneFromMessage(msg)
	if effectiveZone == "" {
		return authority
	}
	effectiveZone = dns.Fqdn(effectiveZone)
	currentZone := dns.Fqdn(authority.Zone)
	fqdn := dns.Fqdn(qname)
	if !dns.IsSubDomain(effectiveZone, fqdn) {
		return authority
	}
	if currentZone != "" && dns.CountLabel(effectiveZone) <= dns.CountLabel(currentZone) {
		return authority
	}

	refined := authority
	refined.Zone = effectiveZone
	if exact, ok := authorityResultForZone(effectiveZone, authority.Hops); ok {
		refined = exact
	} else if hops, err := buildZoneChainFn(ctx, effectiveZone); err == nil {
		if exact, ok := authorityResultForZone(effectiveZone, hops); ok {
			refined = exact
		} else {
			refined.Hops = cloneDelegationHops(hops)
			refined.CacheTTL = zoneChainTTL(hops)
		}
	}
	r.storeAuthority(fqdn, refined)
	r.storeZoneChain(effectiveZone, refined.Hops)
	return refined
}

func (r *Resolver) LookupEffectiveCAA(ctx context.Context, qname string) (EffectiveCAAResult, error) {
	ctx = withResolverFamilyConstraints(ctx, r.familyCapabilities(ctx))
	ctx = withHostAddressCache(ctx, r.hostAddrCache)
	ctx = withEndpointHealthTracker(ctx, r.endpointHealth)
	current := dns.Fqdn(qname)
	for {
		lookup, err := r.Lookup(ctx, current, dns.TypeCAA)
		if err != nil {
			return EffectiveCAAResult{}, err
		}
		if len(lookup.Records) > 0 || current == "." {
			return EffectiveCAAResult{EffectiveName: current, Lookup: lookup}, nil
		}
		next := parentName(current)
		if next == current {
			return EffectiveCAAResult{EffectiveName: current, Lookup: lookup}, nil
		}
		current = next
	}
}

func (r *Resolver) cachedZoneValidation(ctx context.Context, zone string, finalServers []nsAddr) (SecurityState, []*dns.DNSKEY, string, error) {
	ctx = withResolverFamilyConstraints(ctx, r.familyCapabilities(ctx))
	ctx = withHostAddressCache(ctx, r.hostAddrCache)
	ctx = withEndpointHealthTracker(ctx, r.endpointHealth)
	zone = dns.Fqdn(zone)

	r.mu.Lock()
	if cached, ok := r.validateCache[zone]; ok {
		r.mu.Unlock()
		r.recordLocalHit()
		r.appendCacheTrace("local_hit", "validation", zone, "")
		return cached.Security, append([]*dns.DNSKEY(nil), cached.Keys...), cached.Message, nil
	}
	r.mu.Unlock()
	if cached, ok := r.loadSharedValidation(ctx, zone); ok {
		return cached.Security, append([]*dns.DNSKEY(nil), cached.Keys...), cached.Message, nil
	}

	cached, err := r.validateFlights.do(ctx, zone, cloneValidationResult, func(callCtx context.Context) (validationResult, error) {
		r.mu.Lock()
		if cached, ok := r.validateCache[zone]; ok {
			r.mu.Unlock()
			r.recordLocalHit()
			r.appendCacheTrace("local_hit", "validation", zone, "")
			return cloneValidationResult(cached), nil
		}
		r.mu.Unlock()
		if cached, ok := r.loadSharedValidation(callCtx, zone); ok {
			return cached, nil
		}

		r.recordLiveResolution()
		r.appendCacheTrace("live_resolution", "validation", zone, "")
		security, keys, message, err := r.validateFn(callCtx, zone, finalServers)
		if err != nil {
			return validationResult{
				Security: security,
				Keys:     append([]*dns.DNSKEY(nil), keys...),
				Message:  message,
			}, err
		}

		result := validationResult{
			Security: security,
			Keys:     append([]*dns.DNSKEY(nil), keys...),
			Message:  message,
		}
		if stored, ok := r.cachedValidation(zone); ok {
			result = stored
		}
		r.storeValidation(zone, result)
		r.storeSharedValidation(callCtx, zone, result)
		return result, nil
	})
	if err != nil {
		return cached.Security, cached.Keys, cached.Message, err
	}
	return cached.Security, cached.Keys, cached.Message, nil
}

func (r *Resolver) storeLookup(cacheKey string, result LookupResult) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lookupCache[cacheKey] = result
}

func (r *Resolver) storeValidation(zone string, result validationResult) {
	zone = dns.Fqdn(zone)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.validateCache[zone] = validationResult{
		Security: result.Security,
		Keys:     append([]*dns.DNSKEY(nil), result.Keys...),
		Message:  result.Message,
		CacheTTL: result.CacheTTL,
	}
}

func (r *Resolver) cachedValidation(zone string) (validationResult, bool) {
	zone = dns.Fqdn(zone)
	r.mu.Lock()
	defer r.mu.Unlock()
	cached, ok := r.validateCache[zone]
	if !ok {
		return validationResult{}, false
	}
	return cloneValidationResult(cached), true
}

func cloneLookupResult(value LookupResult) LookupResult {
	return LookupResult{
		QName:               value.QName,
		QType:               value.QType,
		Zone:                value.Zone,
		Records:             append([]dns.RR(nil), value.Records...),
		Signatures:          append([]*dns.RRSIG(nil), value.Signatures...),
		Security:            value.Security,
		AuthenticatedNoData: value.AuthenticatedNoData,
		ValidationMessage:   value.ValidationMessage,
		CacheTTL:            value.CacheTTL,
	}
}

func cloneValidationResult(value validationResult) validationResult {
	return validationResult{
		Security: value.Security,
		Keys:     append([]*dns.DNSKEY(nil), value.Keys...),
		Message:  value.Message,
		CacheTTL: value.CacheTTL,
	}
}

func (r *Resolver) cachedAuthority(qname string) (authorityResult, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fqdn := dns.Fqdn(qname)
	if cached, ok := r.authorityCache[fqdn]; ok {
		r.recordLocalHit()
		r.appendCacheTrace("local_hit", "authority", fqdn, "")
		return authorityResult{
			Zone:     cached.Zone,
			Servers:  cloneNSAddrs(cached.Servers),
			Hops:     cloneDelegationHops(cached.Hops),
			CacheTTL: cached.CacheTTL,
		}, true
	}
	var best authorityResult
	var found bool
	for _, cached := range r.authorityCache {
		zone := dns.Fqdn(cached.Zone)
		if zone == "" || !dns.IsSubDomain(zone, fqdn) {
			continue
		}
		if !found || dns.CountLabel(zone) > dns.CountLabel(best.Zone) {
			best = cached
			found = true
		}
	}
	if !found {
		return authorityResult{}, false
	}
	r.recordLocalHit()
	r.appendCacheTrace("local_hit", "authority", fqdn, "ancestor authority reused")
	return authorityResult{
		Zone:     best.Zone,
		Servers:  cloneNSAddrs(best.Servers),
		Hops:     cloneDelegationHops(best.Hops),
		CacheTTL: best.CacheTTL,
	}, true
}

func (r *Resolver) storeAuthority(qname string, value authorityResult) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.authorityCache[dns.Fqdn(qname)] = authorityResult{
		Zone:     dns.Fqdn(value.Zone),
		Servers:  cloneNSAddrs(value.Servers),
		Hops:     cloneDelegationHops(value.Hops),
		CacheTTL: value.CacheTTL,
	}
}

func authorityResultForZone(zone string, hops []delegationHop) (authorityResult, bool) {
	zone = dns.Fqdn(zone)
	for i := range hops {
		hop := hops[i]
		if dns.Fqdn(hop.ToZone) != zone {
			continue
		}
		prefix := cloneDelegationHops(hops[:i+1])
		return authorityResult{
			Zone:     zone,
			Servers:  cloneNSAddrs(hop.ChildServers),
			Hops:     prefix,
			CacheTTL: authorityResultTTL(prefix),
		}, true
	}
	return authorityResult{}, false
}

func (r *Resolver) cachedZoneChain(zone string) ([]delegationHop, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cached, ok := r.zoneChainCache[dns.Fqdn(zone)]
	if !ok {
		return nil, false
	}
	r.recordLocalHit()
	r.appendCacheTrace("local_hit", "delegation", dns.Fqdn(zone), "")
	return cloneDelegationHops(cached), true
}

func (r *Resolver) cachedDeepestSecureValidation(zone string) (string, []*dns.DNSKEY, string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var bestZone string
	var best validationResult
	for _, candidate := range ancestorZonesInclusive(zone) {
		cached, ok := r.validateCache[candidate]
		if !ok || cached.Security != SecuritySecure || len(cached.Keys) == 0 {
			continue
		}
		if bestZone == "" || dns.CountLabel(candidate) > dns.CountLabel(bestZone) {
			bestZone = candidate
			best = cached
		}
	}
	if bestZone == "" {
		return "", nil, "", false
	}
	return bestZone, append([]*dns.DNSKEY(nil), best.Keys...), best.Message, true
}

func (r *Resolver) storeZoneChain(zone string, hops []delegationHop) {
	if zone == "" || zone == "." || len(hops) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range hops {
		prefixZone := dns.Fqdn(hops[i].ToZone)
		if prefixZone == "." {
			continue
		}
		r.zoneChainCache[prefixZone] = cloneDelegationHops(hops[:i+1])
	}
}

func (r *Resolver) validateZoneChain(ctx context.Context, zone string, finalServers []nsAddr) (SecurityState, []*dns.DNSKEY, string, error) {
	now := time.Now().UTC()
	zone = dns.Fqdn(zone)
	var chainTTL time.Duration

	startZone, trustedKeys, _, ok := r.cachedDeepestSecureValidation(zone)
	if !ok {
		rootRes, err := queryAny(ctx, rootHintsAny, ".", dns.TypeDNSKEY, true)
		if err != nil {
			return SecurityIndeterminate, nil, "", fmt.Errorf("fetch root DNSKEY RRset: %w", err)
		}
		if !rootRes.Msg.Authoritative {
			return SecurityIndeterminate, nil, "root DNSKEY response was not authoritative", nil
		}
		rootKeys, rootSigs := splitDNSKEYAnswer(rootRes.Msg.Answer, ".")
		anchoredKeys := matchRootTrustAnchorKeys(rootKeys)
		if len(anchoredKeys) == 0 {
			return SecurityBogus, nil, "published root DNSKEY RRset did not match the embedded root trust anchors", nil
		}
		if err := verifyRRSetWithDNSKEYs(anchoredKeys, rootSigs, dnskeysToRRs(rootKeys), now); err != nil {
			return SecurityBogus, nil, fmt.Sprintf("root DNSKEY RRset signature validation failed: %v", err), nil
		}
		startZone = "."
		trustedKeys = append([]*dns.DNSKEY(nil), rootKeys...)
		chainTTL = minTTL(chainTTL, rrTTL(append(dnskeysToRRs(rootKeys), rrsigSliceToRRs(rootSigs)...)))
		r.storeValidation(".", validationResult{
			Security: SecuritySecure,
			Keys:     append([]*dns.DNSKEY(nil), rootKeys...),
			Message:  "root DNSKEY RRset validated with embedded trust anchors",
			CacheTTL: chainTTL,
		})
		r.storeSharedValidation(ctx, ".", validationResult{
			Security: SecuritySecure,
			Keys:     append([]*dns.DNSKEY(nil), rootKeys...),
			Message:  "root DNSKEY RRset validated with embedded trust anchors",
			CacheTTL: chainTTL,
		})
	}
	if zone == startZone {
		return SecuritySecure, trustedKeys, fmt.Sprintf("DNSSEC chain to %s validated successfully", zone), nil
	}

	hops, ok := r.cachedZoneChain(zone)
	if !ok || !zoneChainCoversZone(hops, zone) {
		var err error
		hops, err = buildZoneChainFn(ctx, zone)
		if err != nil {
			return SecurityIndeterminate, nil, "", err
		}
		r.storeZoneChain(zone, hops)
	}

	skipUntilStart := startZone != "."
	for _, hop := range hops {
		if skipUntilStart {
			if dns.Fqdn(hop.ToZone) == startZone {
				skipUntilStart = false
			}
			continue
		}
		dsRes, err := queryAny(ctx, uniqueNSAddrs(hop.ParentServers), hop.ToZone, dns.TypeDS, true)
		if err != nil {
			return SecurityIndeterminate, nil, "", fmt.Errorf("query parent DS for %s: %w", hop.ToZone, err)
		}
		if !dsRes.Msg.Authoritative {
			return SecurityIndeterminate, nil, fmt.Sprintf("parent DS response for %s was not authoritative", hop.ToZone), nil
		}

		dsRecords, dsSigs := splitDSAnswer(dsRes.Msg.Answer, hop.ToZone)
		if len(dsRecords) == 0 {
			state, message, err := validateNoDSProof(hop.ToZone, dsRes.Msg.Ns, trustedKeys, now)
			if err != nil {
				return SecurityBogus, nil, fmt.Sprintf("missing DS denial proof validation failed for %s: %v", hop.ToZone, err), nil
			}
			return state, nil, message, nil
		}
		chainTTL = minTTL(chainTTL, rrTTL(append(dsToRRs(dsRecords), rrsigSliceToRRs(dsSigs)...)))
		if len(dsSigs) == 0 {
			return SecurityBogus, nil, fmt.Sprintf("parent published DS records for %s without RRSIG coverage", hop.ToZone), nil
		}
		if err := verifyRRSetWithDNSKEYs(trustedKeys, dsSigs, dsToRRs(dsRecords), now); err != nil {
			return SecurityBogus, nil, fmt.Sprintf("parent DS RRset signature validation failed for %s: %v", hop.ToZone, err), nil
		}

		dnskeyRes, err := queryAny(ctx, uniqueNSAddrs(hop.ChildServers), hop.ToZone, dns.TypeDNSKEY, true)
		if err != nil {
			return SecurityIndeterminate, nil, "", fmt.Errorf("query child DNSKEY for %s: %w", hop.ToZone, err)
		}
		if !dnskeyRes.Msg.Authoritative {
			return SecurityIndeterminate, nil, fmt.Sprintf("child DNSKEY response for %s was not authoritative", hop.ToZone), nil
		}
		childKeys, childSigs := splitDNSKEYAnswer(dnskeyRes.Msg.Answer, hop.ToZone)
		if len(childKeys) == 0 {
			return SecurityBogus, nil, fmt.Sprintf("child zone %s published no DNSKEY material", hop.ToZone), nil
		}
		chainTTL = minTTL(chainTTL, rrTTL(append(dnskeysToRRs(childKeys), rrsigSliceToRRs(childSigs)...)))
		matchedKeys := matchingDNSKEYs(dsRecords, childKeys)
		if len(matchedKeys) == 0 {
			return SecurityBogus, nil, fmt.Sprintf("no child DNSKEY at %s matched the validated DS set", hop.ToZone), nil
		}
		if err := verifyRRSetWithDNSKEYs(matchedKeys, childSigs, dnskeysToRRs(childKeys), now); err != nil {
			return SecurityBogus, nil, fmt.Sprintf("child DNSKEY RRset signature validation failed for %s: %v", hop.ToZone, err), nil
		}
		trustedKeys = append([]*dns.DNSKEY(nil), childKeys...)
		r.storeValidation(hop.ToZone, validationResult{
			Security: SecuritySecure,
			Keys:     append([]*dns.DNSKEY(nil), childKeys...),
			Message:  fmt.Sprintf("DNSSEC chain to %s validated successfully", hop.ToZone),
			CacheTTL: chainTTL,
		})
		r.storeSharedValidation(ctx, hop.ToZone, validationResult{
			Security: SecuritySecure,
			Keys:     append([]*dns.DNSKEY(nil), childKeys...),
			Message:  fmt.Sprintf("DNSSEC chain to %s validated successfully", hop.ToZone),
			CacheTTL: chainTTL,
		})
	}

	_ = finalServers
	return SecuritySecure, trustedKeys, fmt.Sprintf("DNSSEC chain to %s validated successfully", zone), nil
}

func zoneChainCoversZone(hops []delegationHop, zone string) bool {
	if len(hops) == 0 {
		return dns.Fqdn(zone) == "."
	}
	return dns.Fqdn(hops[len(hops)-1].ToZone) == dns.Fqdn(zone)
}

func (r *Resolver) CacheStats() CacheStats {
	return CacheStats{
		LocalHits:       r.cacheStats.localHits.Load(),
		SharedHits:      r.cacheStats.sharedHits.Load(),
		SharedMisses:    r.cacheStats.sharedMisses.Load(),
		LiveResolutions: r.cacheStats.liveResolutions.Load(),
		SharedWrites:    r.cacheStats.sharedWrites.Load(),
	}
}

func (r *Resolver) CacheTrace() []CacheTrace {
	r.cacheTraceMu.Lock()
	defer r.cacheTraceMu.Unlock()
	out := make([]CacheTrace, len(r.cacheTrace))
	copy(out, r.cacheTrace)
	return out
}

func (r *Resolver) recordLocalHit() {
	r.cacheStats.localHits.Add(1)
}

func (r *Resolver) recordSharedHit() {
	r.cacheStats.sharedHits.Add(1)
}

func (r *Resolver) recordSharedMiss() {
	r.cacheStats.sharedMisses.Add(1)
}

func (r *Resolver) recordLiveResolution() {
	r.cacheStats.liveResolutions.Add(1)
}

func (r *Resolver) recordSharedWrite() {
	r.cacheStats.sharedWrites.Add(1)
}

func (r *Resolver) appendCacheTrace(action, artifact, subject, detail string) {
	r.cacheTraceMu.Lock()
	defer r.cacheTraceMu.Unlock()
	r.cacheTrace = append(r.cacheTrace, CacheTrace{
		Action:   strings.TrimSpace(action),
		Artifact: strings.TrimSpace(artifact),
		Subject:  strings.TrimSpace(subject),
		Detail:   strings.TrimSpace(detail),
	})
	if len(r.cacheTrace) > 128 {
		r.cacheTrace = append([]CacheTrace(nil), r.cacheTrace[len(r.cacheTrace)-128:]...)
	}
}

func finalAuthority(iter *iterativeResult) (string, []nsAddr) {
	if iter == nil || len(iter.Hops) == 0 {
		return ".", append([]nsAddr(nil), rootHintsAny...)
	}
	if zone := authoritativeZoneFromMessage(iter.Response.Msg); zone != "" {
		return zone, append([]nsAddr(nil), iter.Hops[len(iter.Hops)-1].ChildServers...)
	}
	last := iter.Hops[len(iter.Hops)-1]
	return last.ToZone, append([]nsAddr(nil), last.ChildServers...)
}

func authoritativeZoneFromMessage(msg *dns.Msg) string {
	if msg == nil {
		return ""
	}
	var best string
	for _, rr := range msg.Ns {
		soa, ok := rr.(*dns.SOA)
		if !ok {
			continue
		}
		owner := dns.Fqdn(soa.Header().Name)
		if best == "" || dns.CountLabel(owner) > dns.CountLabel(best) {
			best = owner
		}
	}
	return best
}

func parentName(name string) string {
	fqdn := dns.Fqdn(name)
	if fqdn == "." {
		return "."
	}
	labels := dns.SplitDomainName(fqdn)
	if len(labels) <= 1 {
		return "."
	}
	return dns.Fqdn(strings.Join(labels[1:], "."))
}

func splitAnswerRRset(rrs []dns.RR, owner string, qtype uint16) ([]dns.RR, []*dns.RRSIG) {
	var records []dns.RR
	var sigs []*dns.RRSIG
	fqdn := dns.Fqdn(owner)
	for _, rr := range rrs {
		switch v := rr.(type) {
		case *dns.RRSIG:
			if dns.Fqdn(v.Header().Name) == fqdn && v.TypeCovered == qtype {
				sigs = append(sigs, v)
			}
		default:
			if rr.Header().Rrtype == qtype && dns.Fqdn(rr.Header().Name) == fqdn {
				records = append(records, rr)
			}
		}
	}
	return records, sigs
}

func splitDNSKEYAnswer(rrs []dns.RR, owner string) ([]*dns.DNSKEY, []*dns.RRSIG) {
	var keys []*dns.DNSKEY
	var sigs []*dns.RRSIG
	for _, rr := range rrs {
		switch v := rr.(type) {
		case *dns.DNSKEY:
			if dns.Fqdn(v.Header().Name) == dns.Fqdn(owner) {
				keys = append(keys, v)
			}
		case *dns.RRSIG:
			if dns.Fqdn(v.Header().Name) == dns.Fqdn(owner) && v.TypeCovered == dns.TypeDNSKEY {
				sigs = append(sigs, v)
			}
		}
	}
	return keys, sigs
}

func splitDSAnswer(rrs []dns.RR, owner string) ([]*dns.DS, []*dns.RRSIG) {
	var dsRecords []*dns.DS
	var sigs []*dns.RRSIG
	for _, rr := range rrs {
		switch v := rr.(type) {
		case *dns.DS:
			if dns.Fqdn(v.Header().Name) == dns.Fqdn(owner) {
				dsRecords = append(dsRecords, v)
			}
		case *dns.RRSIG:
			if dns.Fqdn(v.Header().Name) == dns.Fqdn(owner) && v.TypeCovered == dns.TypeDS {
				sigs = append(sigs, v)
			}
		}
	}
	return dsRecords, sigs
}

func matchingDNSKEYs(dsRecords []*dns.DS, keys []*dns.DNSKEY) []*dns.DNSKEY {
	var matched []*dns.DNSKEY
	for _, key := range keys {
		for _, ds := range dsRecords {
			if key.Header().Name != ds.Header().Name {
				continue
			}
			if generated := key.ToDS(ds.DigestType); generated != nil && strings.EqualFold(generated.Digest, ds.Digest) && generated.Algorithm == ds.Algorithm && generated.KeyTag == ds.KeyTag {
				matched = append(matched, key)
				break
			}
		}
	}
	return matched
}

func matchRootTrustAnchorKeys(keys []*dns.DNSKEY) []*dns.DNSKEY {
	_, _, anchored := countRootTrustAnchorMatches(keys)
	return anchored
}

func countRootTrustAnchorMatches(keys []*dns.DNSKEY) (matched int, missing int, anchored []*dns.DNSKEY) {
	for _, anchor := range rootTrustAnchors {
		found := false
		for _, key := range keys {
			if dns.Fqdn(key.Header().Name) != "." {
				continue
			}
			if key.Flags != anchor.Flags || key.Algorithm != anchor.Algorithm || strings.TrimSpace(key.PublicKey) != anchor.PublicKey {
				continue
			}
			generated := key.ToDS(anchor.DigestType)
			if generated == nil {
				continue
			}
			if generated.KeyTag == anchor.KeyTag && generated.Algorithm == anchor.Algorithm && strings.EqualFold(generated.Digest, anchor.Digest) {
				anchored = append(anchored, key)
				found = true
				break
			}
		}
		if found {
			matched++
		} else {
			missing++
		}
	}
	return matched, missing, anchored
}

func verifyRRSetWithDNSKEYs(keys []*dns.DNSKEY, sigs []*dns.RRSIG, rrset []dns.RR, now time.Time) error {
	if len(keys) == 0 {
		return fmt.Errorf("no DNSKEY records available for signature validation")
	}
	if len(sigs) == 0 {
		return fmt.Errorf("no RRSIG records available for signature validation")
	}
	for _, sig := range sigs {
		if !sig.ValidityPeriod(now) {
			continue
		}
		for _, key := range keys {
			if sig.KeyTag != key.KeyTag() || sig.Algorithm != key.Algorithm {
				continue
			}
			if err := sig.Verify(key, rrset); err == nil {
				return nil
			}
		}
	}
	return fmt.Errorf("no valid RRSIG matched the supplied DNSKEY material")
}

func dnskeysToRRs(keys []*dns.DNSKEY) []dns.RR {
	out := make([]dns.RR, 0, len(keys))
	for _, key := range keys {
		out = append(out, key)
	}
	return out
}

func dsToRRs(records []*dns.DS) []dns.RR {
	out := make([]dns.RR, 0, len(records))
	for _, record := range records {
		out = append(out, record)
	}
	return out
}

func rrtypeName(qtype uint16) string {
	if name, ok := dns.TypeToString[qtype]; ok {
		return name
	}
	return fmt.Sprintf("TYPE%d", qtype)
}

func lookupCacheKey(qname string, qtype uint16) string {
	return dns.Fqdn(qname) + "|" + rrtypeName(qtype)
}

func ancestorZonesInclusive(zone string) []string {
	fqdn := dns.Fqdn(zone)
	if fqdn == "." {
		return []string{"."}
	}
	ancestry := zoneAncestry(fqdn)
	out := make([]string, 0, len(ancestry)+1)
	out = append(out, ".")
	out = append(out, ancestry...)
	return out
}

func cloneNSAddrs(values []nsAddr) []nsAddr {
	if len(values) == 0 {
		return nil
	}
	out := make([]nsAddr, len(values))
	copy(out, values)
	return out
}

func cloneDelegationHops(values []delegationHop) []delegationHop {
	if len(values) == 0 {
		return nil
	}
	out := make([]delegationHop, 0, len(values))
	for _, hop := range values {
		out = append(out, delegationHop{
			FromZone:      hop.FromZone,
			ToZone:        hop.ToZone,
			ParentServer:  hop.ParentServer,
			ParentServers: cloneNSAddrs(hop.ParentServers),
			ChildNS:       append([]string(nil), hop.ChildNS...),
			ChildServers:  cloneNSAddrs(hop.ChildServers),
			CacheTTL:      hop.CacheTTL,
		})
	}
	return out
}
