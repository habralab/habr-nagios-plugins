package dnschain

import (
	"fmt"
	"strings"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/miekg/dns"
)

type noDSProofKind string
type nsec3ProofKind string

const (
	noDSProofKindNSECExact                  noDSProofKind = "nsec_exact"
	noDSProofKindNSEC3Exact                 noDSProofKind = "nsec3_exact"
	noDSProofKindNSEC3ClosestEncloserOptOut noDSProofKind = "nsec3_closest_encloser_optout"
	noDSProofKindUnsupportedMaterial        noDSProofKind = "unsupported_material"
	noDSProofKindMissingMaterial            noDSProofKind = "missing_material"

	nsec3ProofKindNameError      nsec3ProofKind = "nsec3_name_error"
	nsec3ProofKindNoData         nsec3ProofKind = "nsec3_no_data"
	nsec3ProofKindWildcardNoData nsec3ProofKind = "nsec3_wildcard_no_data"
)

type noDSProofAssessment struct {
	Kind         noDSProofKind
	State        checkreport.CheckState
	Message      string
	TraceMessage string
	Evidence     []checkreport.Evidence
}

type denialTTLAssessment struct {
	State    checkreport.CheckState
	Message  string
	Evidence []checkreport.Evidence
}

type nsec3ProofAssessment struct {
	Kind     nsec3ProofKind
	State    checkreport.CheckState
	Message  string
	Evidence []checkreport.Evidence
}

type denialProofMaterial struct {
	NSEC  []rrsetWithSigs
	NSEC3 []rrsetWithSigs
}

type rrsetWithSigs struct {
	Owner string
	RRs   []dns.RR
	Sigs  []*dns.RRSIG
}

func validateNoDSProof(qname string, authority []dns.RR, trustedKeys []*dns.DNSKEY, now time.Time) (noDSProofAssessment, error) {
	material, err := verifyDenialMaterial(authority, trustedKeys, now)
	if err != nil {
		return noDSProofAssessment{}, err
	}

	if proof, ok := assessNoDSProofPattern(qname, material); ok {
		return proof, nil
	}

	if len(material.NSEC) == 0 && len(material.NSEC3) == 0 {
		return noDSProofAssessment{
			Kind:         noDSProofKindMissingMaterial,
			State:        checkreport.CheckNote,
			Message:      "parent returned no DS records and no denial proof material that this checker currently understands",
			TraceMessage: fmt.Sprintf("parent returned no DS records for %s and supplied no supported denial proof material", qname),
			Evidence: []checkreport.Evidence{
				{
					Kind:    "dnssec_denial",
					Summary: "no NSEC or NSEC3 denial material was returned",
					Attributes: []checkreport.KV{
						{Key: "proof_kind", Value: string(noDSProofKindMissingMaterial)},
					},
				},
			},
		}, nil
	}

	return noDSProofAssessment{
		Kind:         noDSProofKindUnsupportedMaterial,
		State:        checkreport.CheckNote,
		Message:      "parent returned signed denial proof material for missing DS, but it did not match a currently supported proof pattern",
		TraceMessage: fmt.Sprintf("parent returned signed denial proof material for %s, but the checker could not map it to a supported DS-absence proof pattern", qname),
		Evidence: []checkreport.Evidence{
			{
				Kind:    "dnssec_denial",
				Summary: "denial material did not satisfy the supported DS-absence proof patterns",
				Attributes: []checkreport.KV{
					{Key: "proof_kind", Value: string(noDSProofKindUnsupportedMaterial)},
					{Key: "nsec_rrsets", Value: fmt.Sprintf("%d", len(material.NSEC))},
					{Key: "nsec3_rrsets", Value: fmt.Sprintf("%d", len(material.NSEC3))},
				},
			},
		},
	}, nil
}

func validateNSEC3NameErrorProof(qname string, authority []dns.RR, trustedKeys []*dns.DNSKEY, now time.Time) (nsec3ProofAssessment, error) {
	material, err := verifyDenialMaterial(authority, trustedKeys, now)
	if err != nil {
		return nsec3ProofAssessment{}, err
	}
	proof, ok := assessNSEC3NameErrorPattern(qname, material)
	if !ok {
		return nsec3ProofAssessment{}, nil
	}
	return proof, nil
}

func validateNSEC3NoDataProof(qname string, qtype uint16, authority []dns.RR, trustedKeys []*dns.DNSKEY, now time.Time) (nsec3ProofAssessment, error) {
	material, err := verifyDenialMaterial(authority, trustedKeys, now)
	if err != nil {
		return nsec3ProofAssessment{}, err
	}
	proof, ok := assessNSEC3NoDataPattern(qname, qtype, material)
	if !ok {
		return nsec3ProofAssessment{}, nil
	}
	return proof, nil
}

func validateNSEC3WildcardNoDataProof(qname string, qtype uint16, authority []dns.RR, trustedKeys []*dns.DNSKEY, now time.Time) (nsec3ProofAssessment, error) {
	material, err := verifyDenialMaterial(authority, trustedKeys, now)
	if err != nil {
		return nsec3ProofAssessment{}, err
	}
	proof, ok := assessNSEC3WildcardNoDataPattern(qname, qtype, material)
	if !ok {
		return nsec3ProofAssessment{}, nil
	}
	return proof, nil
}

func verifyDenialMaterial(authority []dns.RR, trustedKeys []*dns.DNSKEY, now time.Time) (denialProofMaterial, error) {
	material := splitDenialAuthority(authority)

	for _, set := range material.NSEC {
		if err := verifyRRSetWithDNSKEYs(trustedKeys, set.Sigs, set.RRs, now); err != nil {
			return denialProofMaterial{}, fmt.Errorf("NSEC proof signature validation failed for %s: %w", set.Owner, err)
		}
	}

	for _, set := range material.NSEC3 {
		if err := verifyRRSetWithDNSKEYs(trustedKeys, set.Sigs, set.RRs, now); err != nil {
			return denialProofMaterial{}, fmt.Errorf("NSEC3 proof signature validation failed for %s: %w", set.Owner, err)
		}
	}

	return material, nil
}

func assessNoDSProofPattern(qname string, material denialProofMaterial) (noDSProofAssessment, bool) {
	fqdn := dns.Fqdn(qname)

	for _, set := range material.NSEC {
		for _, rr := range set.RRs {
			nsec := rr.(*dns.NSEC)
			if dns.Fqdn(nsec.Header().Name) != fqdn {
				continue
			}
			if hasDelegationNoDSBits(nsec.TypeBitMap) {
				return noDSProofAssessment{
					Kind:         noDSProofKindNSECExact,
					State:        checkreport.CheckPass,
					Message:      "parent authenticated an insecure delegation without DS with a signed NSEC proof",
					TraceMessage: fmt.Sprintf("signed NSEC proof established that %s is a delegation without DS at the parent", fqdn),
					Evidence: []checkreport.Evidence{
						{
							Kind:    "dnssec_denial",
							Summary: "exact NSEC proof matched the delegation name and showed NS without DS",
							Attributes: []checkreport.KV{
								{Key: "proof_kind", Value: string(noDSProofKindNSECExact)},
								{Key: "owner", Value: dns.Fqdn(nsec.Header().Name)},
								{Key: "types", Value: typeBitmapString(nsec.TypeBitMap)},
							},
						},
					},
				}, true
			}
		}
	}

	for _, set := range material.NSEC3 {
		for _, rr := range set.RRs {
			nsec3 := rr.(*dns.NSEC3)
			if !nsec3.Match(fqdn) {
				continue
			}
			if hasDelegationNoDSBits(nsec3.TypeBitMap) {
				return noDSProofAssessment{
					Kind:         noDSProofKindNSEC3Exact,
					State:        checkreport.CheckPass,
					Message:      "parent authenticated an insecure delegation without DS with a signed exact-match NSEC3 proof",
					TraceMessage: fmt.Sprintf("signed exact-match NSEC3 proof established that %s is a delegation without DS at the parent", fqdn),
					Evidence: []checkreport.Evidence{
						{
							Kind:    "dnssec_denial",
							Summary: "exact NSEC3 proof matched the delegation name and showed NS without DS",
							Attributes: []checkreport.KV{
								{Key: "proof_kind", Value: string(noDSProofKindNSEC3Exact)},
								{Key: "owner", Value: dns.Fqdn(nsec3.Header().Name)},
								{Key: "types", Value: typeBitmapString(nsec3.TypeBitMap)},
								{Key: "opt_out", Value: fmt.Sprintf("%t", nsec3.Flags&1 == 1)},
							},
						},
					},
				}, true
			}
		}
	}

	closestEncloser, closestSet, nextCloser, coverSet, ok := findClosestProvableEncloser(fqdn, material.NSEC3)
	if ok && coverSet != nil {
		for _, rr := range coverSet.RRs {
			nsec3 := rr.(*dns.NSEC3)
			if nsec3.Flags&1 != 1 {
				continue
			}
			return noDSProofAssessment{
				Kind:         noDSProofKindNSEC3ClosestEncloserOptOut,
				State:        checkreport.CheckPass,
				Message:      "parent authenticated an insecure delegation without DS using a signed opt-out NSEC3 closest-encloser proof",
				TraceMessage: fmt.Sprintf("signed opt-out NSEC3 proof established that %s is an insecure delegation without DS", fqdn),
				Evidence: []checkreport.Evidence{
					{
						Kind:    "dnssec_denial",
						Summary: "closest provable encloser proof plus opt-out cover proved an insecure delegation without DS",
						Attributes: []checkreport.KV{
							{Key: "proof_kind", Value: string(noDSProofKindNSEC3ClosestEncloserOptOut)},
							{Key: "closest_encloser", Value: closestEncloser},
							{Key: "closest_encloser_owner", Value: closestSet.Owner},
							{Key: "next_closer", Value: nextCloser},
							{Key: "cover_owner", Value: coverSet.Owner},
						},
					},
				},
			}, true
		}
	}

	return noDSProofAssessment{}, false
}

func assessNSEC3NoDataPattern(qname string, qtype uint16, material denialProofMaterial) (nsec3ProofAssessment, bool) {
	fqdn := dns.Fqdn(qname)
	match := findMatchingNSEC3Set(fqdn, material.NSEC3)
	if match == nil {
		return nsec3ProofAssessment{}, false
	}
	for _, rr := range match.RRs {
		nsec3 := rr.(*dns.NSEC3)
		if !nsec3.Match(fqdn) {
			continue
		}
		if typeBitmapContains(nsec3.TypeBitMap, qtype) || typeBitmapContains(nsec3.TypeBitMap, dns.TypeCNAME) {
			return nsec3ProofAssessment{}, false
		}
		return nsec3ProofAssessment{
			Kind:    nsec3ProofKindNoData,
			State:   checkreport.CheckPass,
			Message: "signed exact-match NSEC3 proof established that the requested RR type does not exist at the owner name",
			Evidence: []checkreport.Evidence{{
				Kind:    "dnssec_denial",
				Summary: "exact NSEC3 proof matched the owner name and omitted both the requested RR type and CNAME",
				Attributes: []checkreport.KV{
					{Key: "proof_kind", Value: string(nsec3ProofKindNoData)},
					{Key: "owner", Value: dns.Fqdn(nsec3.Header().Name)},
					{Key: "qname", Value: fqdn},
					{Key: "qtype", Value: dns.TypeToString[qtype]},
					{Key: "types", Value: typeBitmapString(nsec3.TypeBitMap)},
				},
			}},
		}, true
	}
	return nsec3ProofAssessment{}, false
}

func assessNSEC3NameErrorPattern(qname string, material denialProofMaterial) (nsec3ProofAssessment, bool) {
	fqdn := dns.Fqdn(qname)
	closestEncloser, closestSet, nextCloser, coverSet, ok := findClosestProvableEncloser(fqdn, material.NSEC3)
	if !ok || coverSet == nil || closestSet == nil {
		return nsec3ProofAssessment{}, false
	}
	wildcardName := dns.Fqdn("*." + strings.TrimSuffix(closestEncloser, "."))
	wildcardCover := findCoveringNSEC3Set(wildcardName, material.NSEC3, false)
	if wildcardCover == nil {
		return nsec3ProofAssessment{}, false
	}
	return nsec3ProofAssessment{
		Kind:    nsec3ProofKindNameError,
		State:   checkreport.CheckPass,
		Message: "signed NSEC3 closest-encloser proof established that the queried name does not exist and no wildcard answer applies",
		Evidence: []checkreport.Evidence{{
			Kind:    "dnssec_denial",
			Summary: "closest encloser proof plus next-closer and wildcard cover established an authenticated name error",
			Attributes: []checkreport.KV{
				{Key: "proof_kind", Value: string(nsec3ProofKindNameError)},
				{Key: "qname", Value: fqdn},
				{Key: "closest_encloser", Value: closestEncloser},
				{Key: "closest_encloser_owner", Value: closestSet.Owner},
				{Key: "next_closer", Value: nextCloser},
				{Key: "next_closer_cover_owner", Value: coverSet.Owner},
				{Key: "wildcard_name", Value: wildcardName},
				{Key: "wildcard_cover_owner", Value: wildcardCover.Owner},
			},
		}},
	}, true
}

func assessNSEC3WildcardNoDataPattern(qname string, qtype uint16, material denialProofMaterial) (nsec3ProofAssessment, bool) {
	fqdn := dns.Fqdn(qname)
	closestEncloser, closestSet, nextCloser, coverSet, ok := findClosestProvableEncloser(fqdn, material.NSEC3)
	if !ok || coverSet == nil || closestSet == nil {
		return nsec3ProofAssessment{}, false
	}
	wildcardName := dns.Fqdn("*." + strings.TrimSuffix(closestEncloser, "."))
	wildcardMatch := findMatchingNSEC3Set(wildcardName, material.NSEC3)
	if wildcardMatch == nil {
		return nsec3ProofAssessment{}, false
	}
	for _, rr := range wildcardMatch.RRs {
		nsec3 := rr.(*dns.NSEC3)
		if !nsec3.Match(wildcardName) {
			continue
		}
		if typeBitmapContains(nsec3.TypeBitMap, qtype) || typeBitmapContains(nsec3.TypeBitMap, dns.TypeCNAME) {
			return nsec3ProofAssessment{}, false
		}
		return nsec3ProofAssessment{
			Kind:    nsec3ProofKindWildcardNoData,
			State:   checkreport.CheckPass,
			Message: "signed NSEC3 wildcard proof established that no closer name exists and the matching wildcard lacks the requested RR type",
			Evidence: []checkreport.Evidence{{
				Kind:    "dnssec_denial",
				Summary: "closest encloser proof plus wildcard exact-match proved wildcard no-data",
				Attributes: []checkreport.KV{
					{Key: "proof_kind", Value: string(nsec3ProofKindWildcardNoData)},
					{Key: "qname", Value: fqdn},
					{Key: "qtype", Value: dns.TypeToString[qtype]},
					{Key: "closest_encloser", Value: closestEncloser},
					{Key: "closest_encloser_owner", Value: closestSet.Owner},
					{Key: "next_closer", Value: nextCloser},
					{Key: "next_closer_cover_owner", Value: coverSet.Owner},
					{Key: "wildcard_name", Value: wildcardName},
					{Key: "wildcard_owner", Value: wildcardMatch.Owner},
					{Key: "wildcard_types", Value: typeBitmapString(nsec3.TypeBitMap)},
				},
			}},
		}, true
	}
	return nsec3ProofAssessment{}, false
}

func findClosestProvableEncloser(qname string, sets []rrsetWithSigs) (closestEncloser string, closestSet *rrsetWithSigs, nextCloser string, coverSet *rrsetWithSigs, ok bool) {
	zone := nsec3Zone(sets)
	if zone == "" {
		return "", nil, "", nil, false
	}
	ancestors := ancestorChainWithinZone(qname, zone)
	if len(ancestors) < 2 {
		return "", nil, "", nil, false
	}
	for i := 1; i < len(ancestors); i++ {
		candidateClosest := ancestors[i]
		candidateNextCloser := ancestors[i-1]
		match := findMatchingNSEC3Set(candidateClosest, sets)
		if match == nil || !validClosestEncloserNSEC3(match) {
			continue
		}
		cover := findCoveringNSEC3Set(candidateNextCloser, sets, true)
		if cover == nil {
			continue
		}
		return candidateClosest, match, candidateNextCloser, cover, true
	}
	return "", nil, "", nil, false
}

func findMatchingNSEC3Set(name string, sets []rrsetWithSigs) *rrsetWithSigs {
	for i := range sets {
		for _, rr := range sets[i].RRs {
			if rr.(*dns.NSEC3).Match(name) {
				return &sets[i]
			}
		}
	}
	return nil
}

func findCoveringNSEC3Set(name string, sets []rrsetWithSigs, preferOptOut bool) *rrsetWithSigs {
	var fallback *rrsetWithSigs
	for i := range sets {
		for _, rr := range sets[i].RRs {
			nsec3 := rr.(*dns.NSEC3)
			if !nsec3.Cover(name) {
				continue
			}
			if preferOptOut && nsec3.Flags&1 == 1 {
				return &sets[i]
			}
			if fallback == nil {
				fallback = &sets[i]
			}
		}
	}
	return fallback
}

func validClosestEncloserNSEC3(set *rrsetWithSigs) bool {
	for _, rr := range set.RRs {
		nsec3 := rr.(*dns.NSEC3)
		if typeBitmapContains(nsec3.TypeBitMap, dns.TypeDNAME) {
			continue
		}
		if typeBitmapContains(nsec3.TypeBitMap, dns.TypeNS) && !typeBitmapContains(nsec3.TypeBitMap, dns.TypeSOA) {
			continue
		}
		return true
	}
	return false
}

func nsec3Zone(sets []rrsetWithSigs) string {
	for _, set := range sets {
		for _, rr := range set.RRs {
			name := dns.Fqdn(rr.Header().Name)
			if _, zone, ok := strings.Cut(name, "."); ok && zone != "" {
				return dns.Fqdn(zone)
			}
		}
	}
	return ""
}

func ancestorChainWithinZone(qname, zone string) []string {
	nameLabels := dns.SplitDomainName(dns.Fqdn(qname))
	zoneLabels := dns.SplitDomainName(dns.Fqdn(zone))
	if len(nameLabels) < len(zoneLabels) || !dns.IsSubDomain(dns.Fqdn(zone), dns.Fqdn(qname)) {
		return nil
	}
	depth := len(nameLabels) - len(zoneLabels)
	out := make([]string, 0, depth+1)
	for i := 0; i <= depth; i++ {
		out = append(out, dns.Fqdn(strings.Join(nameLabels[i:], ".")))
	}
	return out
}

func hasDelegationNoDSBits(bitmap []uint16) bool {
	return typeBitmapContains(bitmap, dns.TypeNS) &&
		!typeBitmapContains(bitmap, dns.TypeDS) &&
		!typeBitmapContains(bitmap, dns.TypeSOA) &&
		!typeBitmapContains(bitmap, dns.TypeCNAME)
}

func splitDenialAuthority(authority []dns.RR) denialProofMaterial {
	nsecSets := map[string]*rrsetWithSigs{}
	nsec3Sets := map[string]*rrsetWithSigs{}

	for _, rr := range authority {
		switch v := rr.(type) {
		case *dns.NSEC:
			key := dns.Fqdn(v.Header().Name)
			set := nsecSets[key]
			if set == nil {
				set = &rrsetWithSigs{Owner: key}
				nsecSets[key] = set
			}
			set.RRs = append(set.RRs, rr)
		case *dns.NSEC3:
			key := dns.Fqdn(v.Header().Name)
			set := nsec3Sets[key]
			if set == nil {
				set = &rrsetWithSigs{Owner: key}
				nsec3Sets[key] = set
			}
			set.RRs = append(set.RRs, rr)
		case *dns.RRSIG:
			switch v.TypeCovered {
			case dns.TypeNSEC:
				key := dns.Fqdn(v.Header().Name)
				set := nsecSets[key]
				if set == nil {
					set = &rrsetWithSigs{Owner: key}
					nsecSets[key] = set
				}
				set.Sigs = append(set.Sigs, v)
			case dns.TypeNSEC3:
				key := dns.Fqdn(v.Header().Name)
				set := nsec3Sets[key]
				if set == nil {
					set = &rrsetWithSigs{Owner: key}
					nsec3Sets[key] = set
				}
				set.Sigs = append(set.Sigs, v)
			}
		}
	}

	return denialProofMaterial{
		NSEC:  flattenRRSetMap(nsecSets),
		NSEC3: flattenRRSetMap(nsec3Sets),
	}
}

func flattenRRSetMap(in map[string]*rrsetWithSigs) []rrsetWithSigs {
	out := make([]rrsetWithSigs, 0, len(in))
	for _, set := range in {
		out = append(out, *set)
	}
	return out
}

func typeBitmapContains(bitmap []uint16, qtype uint16) bool {
	for _, rrtype := range bitmap {
		if rrtype == qtype {
			return true
		}
	}
	return false
}

func typeBitmapString(bitmap []uint16) string {
	if len(bitmap) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(bitmap))
	for _, rrtype := range bitmap {
		if name, ok := dns.TypeToString[rrtype]; ok {
			parts = append(parts, name)
			continue
		}
		parts = append(parts, fmt.Sprintf("TYPE%d", rrtype))
	}
	return strings.Join(parts, ",")
}

func assessDenialProofTTL(authority []dns.RR) *denialTTLAssessment {
	material := splitDenialAuthority(authority)
	if len(material.NSEC) == 0 && len(material.NSEC3) == 0 {
		return nil
	}

	var soa *dns.SOA
	for _, rr := range authority {
		if v, ok := rr.(*dns.SOA); ok {
			soa = v
			break
		}
	}
	if soa == nil {
		return &denialTTLAssessment{
			State:   checkreport.CheckNote,
			Message: "denial proof TTL could not be assessed because the parent response contained no SOA record",
			Evidence: []checkreport.Evidence{{
				Kind:    "dnssec_denial_ttl",
				Summary: "negative TTL bound unavailable without SOA",
			}},
		}
	}

	expected := soa.Minttl
	if soa.Hdr.Ttl < expected {
		expected = soa.Hdr.Ttl
	}

	maxObserved := uint32(0)
	minObserved := uint32(^uint32(0))
	collect := func(sets []rrsetWithSigs) {
		for _, set := range sets {
			for _, rr := range set.RRs {
				ttl := rr.Header().Ttl
				if ttl > maxObserved {
					maxObserved = ttl
				}
				if ttl < minObserved {
					minObserved = ttl
				}
			}
		}
	}
	collect(material.NSEC)
	collect(material.NSEC3)
	if minObserved == ^uint32(0) {
		minObserved = 0
	}

	evidence := []checkreport.Evidence{{
		Kind:    "dnssec_denial_ttl",
		Summary: "denial proof TTL compared against the RFC 9077 negative TTL bound",
		Attributes: []checkreport.KV{
			{Key: "soa_ttl", Value: fmt.Sprintf("%d", soa.Hdr.Ttl)},
			{Key: "soa_minimum", Value: fmt.Sprintf("%d", soa.Minttl)},
			{Key: "expected_max_ttl", Value: fmt.Sprintf("%d", expected)},
			{Key: "observed_min_ttl", Value: fmt.Sprintf("%d", minObserved)},
			{Key: "observed_max_ttl", Value: fmt.Sprintf("%d", maxObserved)},
		},
	}}

	switch {
	case maxObserved > expected:
		return &denialTTLAssessment{
			State:    checkreport.CheckWarning,
			Message:  fmt.Sprintf("denial proof TTL exceeded the RFC 9077 bound: observed up to %d, expected at most %d", maxObserved, expected),
			Evidence: evidence,
		}
	case minObserved != expected || maxObserved != expected:
		return &denialTTLAssessment{
			State:    checkreport.CheckNote,
			Message:  fmt.Sprintf("denial proof TTL differed from the expected RFC 9077 bound: observed range %d..%d, expected %d", minObserved, maxObserved, expected),
			Evidence: evidence,
		}
	default:
		return &denialTTLAssessment{
			State:    checkreport.CheckPass,
			Message:  fmt.Sprintf("denial proof TTL matched the RFC 9077 bound of %d", expected),
			Evidence: evidence,
		}
	}
}
