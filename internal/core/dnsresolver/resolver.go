package dnsresolver

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

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
}

type EffectiveCAAResult struct {
	EffectiveName string
	Lookup        LookupResult
}

type Resolver struct {
	QueryTimeout  time.Duration
	mu            sync.Mutex
	lookupCache   map[string]LookupResult
	resolveCache  map[string]ResolveResult
	validateCache map[string]validationResult
	familyCaps    familyCapabilityCache
	iterativeFn   func(context.Context, string, uint16) (*iterativeResult, error)
	validateFn    func(context.Context, string, []nsAddr) (SecurityState, []*dns.DNSKEY, string, error)
}

// NewResolver creates a per-session authoritative DNS/DNSSEC resolver.
// Its caches are scoped to this resolver instance so a single probe run can
// reuse repeated lookups and zone validations without sharing state across runs.
func NewResolver(queryTimeout time.Duration) *Resolver {
	r := &Resolver{
		QueryTimeout:  queryTimeout,
		lookupCache:   map[string]LookupResult{},
		resolveCache:  map[string]ResolveResult{},
		validateCache: map[string]validationResult{},
	}
	r.iterativeFn = func(ctx context.Context, qname string, qtype uint16) (*iterativeResult, error) {
		return resolveIterative(ctx, qname, qtype)
	}
	r.validateFn = r.validateZoneChain
	return r
}

func (r *Resolver) familyCapabilities(ctx context.Context) resolverFamilyCapabilities {
	if r.QueryTimeout == 0 {
		return resolverFamilyCapabilities{IPv4: true, IPv6: true}
	}
	r.familyCaps.once.Do(func() {
		r.familyCaps.caps = resolverFamilyProbeFn(ctx, r.QueryTimeout)
	})
	return r.familyCaps.caps
}

type validationResult struct {
	Security SecurityState
	Keys     []*dns.DNSKEY
	Message  string
}

func (r *Resolver) Lookup(ctx context.Context, qname string, qtype uint16) (LookupResult, error) {
	ctx = withDNSQueryTimeout(ctx, r.QueryTimeout)
	ctx = withResolverFamilyConstraints(ctx, r.familyCapabilities(ctx))
	fqdn := dns.Fqdn(qname)
	cacheKey := lookupCacheKey(fqdn, qtype)

	r.mu.Lock()
	if cached, ok := r.lookupCache[cacheKey]; ok {
		r.mu.Unlock()
		return cached, nil
	}
	r.mu.Unlock()

	iter, err := r.iterativeFn(ctx, fqdn, qtype)
	if err != nil {
		return LookupResult{}, err
	}

	zone, servers := finalAuthority(iter)
	result := LookupResult{
		QName: fqdn,
		QType: qtype,
		Zone:  zone,
	}

	secureState, trustedKeys, validationMessage, err := r.cachedZoneValidation(ctx, zone, servers)
	if err != nil {
		return result, err
	}

	records, sigs := splitAnswerRRset(iter.Response.Msg.Answer, fqdn, qtype)
	result.Records = records
	result.Signatures = sigs

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
			return result, nil
		}

		result.Security = SecurityIndeterminate
		result.ValidationMessage = message
		r.storeLookup(cacheKey, result)
		return result, nil

	case SecurityInsecure:
		result.Security = SecurityInsecure
		result.ValidationMessage = validationMessage
		r.storeLookup(cacheKey, result)
		return result, nil

	case SecurityBogus:
		result.Security = SecurityBogus
		result.ValidationMessage = validationMessage
		r.storeLookup(cacheKey, result)
		return result, nil

	default:
		result.Security = SecurityIndeterminate
		result.ValidationMessage = validationMessage
		r.storeLookup(cacheKey, result)
		return result, nil
	}
}

func (r *Resolver) LookupEffectiveCAA(ctx context.Context, qname string) (EffectiveCAAResult, error) {
	ctx = withResolverFamilyConstraints(ctx, r.familyCapabilities(ctx))
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
	zone = dns.Fqdn(zone)

	r.mu.Lock()
	if cached, ok := r.validateCache[zone]; ok {
		r.mu.Unlock()
		return cached.Security, append([]*dns.DNSKEY(nil), cached.Keys...), cached.Message, nil
	}
	r.mu.Unlock()

	security, keys, message, err := r.validateFn(ctx, zone, finalServers)
	if err != nil {
		return security, keys, message, err
	}

	r.mu.Lock()
	r.validateCache[zone] = validationResult{
		Security: security,
		Keys:     append([]*dns.DNSKEY(nil), keys...),
		Message:  message,
	}
	r.mu.Unlock()
	return security, keys, message, nil
}

func (r *Resolver) storeLookup(cacheKey string, result LookupResult) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lookupCache[cacheKey] = result
}

func (r *Resolver) validateZoneChain(ctx context.Context, zone string, finalServers []nsAddr) (SecurityState, []*dns.DNSKEY, string, error) {
	now := time.Now().UTC()

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
	if zone == "." {
		return SecuritySecure, rootKeys, "root DNSKEY RRset validated with embedded trust anchors", nil
	}

	hops, err := buildZoneChain(ctx, zone)
	if err != nil {
		return SecurityIndeterminate, nil, "", err
	}

	trustedKeys := append([]*dns.DNSKEY(nil), rootKeys...)
	for _, hop := range hops {
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
		matchedKeys := matchingDNSKEYs(dsRecords, childKeys)
		if len(matchedKeys) == 0 {
			return SecurityBogus, nil, fmt.Sprintf("no child DNSKEY at %s matched the validated DS set", hop.ToZone), nil
		}
		if err := verifyRRSetWithDNSKEYs(matchedKeys, childSigs, dnskeysToRRs(childKeys), now); err != nil {
			return SecurityBogus, nil, fmt.Sprintf("child DNSKEY RRset signature validation failed for %s: %v", hop.ToZone, err), nil
		}
		trustedKeys = append([]*dns.DNSKEY(nil), childKeys...)
	}

	_ = finalServers
	return SecuritySecure, trustedKeys, fmt.Sprintf("DNSSEC chain to %s validated successfully", zone), nil
}

func finalAuthority(iter *iterativeResult) (string, []nsAddr) {
	if iter == nil || len(iter.Hops) == 0 {
		return ".", append([]nsAddr(nil), rootHintsAny...)
	}
	last := iter.Hops[len(iter.Hops)-1]
	return last.ToZone, append([]nsAddr(nil), last.ChildServers...)
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
