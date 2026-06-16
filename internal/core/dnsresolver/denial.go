package dnsresolver

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type denialProofMaterial struct {
	NSEC  []rrsetWithSigs
	NSEC3 []rrsetWithSigs
}

type rrsetWithSigs struct {
	Owner string
	RRs   []dns.RR
	Sigs  []*dns.RRSIG
}

func validateNoDSProof(qname string, authority []dns.RR, trustedKeys []*dns.DNSKEY, now time.Time) (SecurityState, string, error) {
	material, err := verifyDenialMaterial(authority, trustedKeys, now)
	if err != nil {
		return SecurityBogus, "", err
	}

	if hasNSECDelegationNoDS(qname, material) {
		return SecurityInsecure, "signed NSEC proof established an insecure delegation without DS", nil
	}
	if hasNSEC3ExactDelegationNoDS(qname, material) {
		return SecurityInsecure, "signed exact-match NSEC3 proof established an insecure delegation without DS", nil
	}
	if hasNSEC3ClosestEncloserOptOutNoDS(qname, material) {
		return SecurityInsecure, "signed opt-out NSEC3 proof established an insecure delegation without DS", nil
	}

	if len(material.NSEC) == 0 && len(material.NSEC3) == 0 {
		return SecurityIndeterminate, "no DS records and no supported denial material were returned", nil
	}
	return SecurityIndeterminate, "signed denial material did not match a supported DS-absence proof pattern", nil
}

func validateNoDataProof(qname string, qtype uint16, authority []dns.RR, trustedKeys []*dns.DNSKEY, now time.Time) (bool, string, error) {
	material, err := verifyDenialMaterial(authority, trustedKeys, now)
	if err != nil {
		return false, "", err
	}

	if hasNSECExactNoData(qname, qtype, material) {
		return true, "signed exact-match NSEC proof established that the requested RR type does not exist", nil
	}
	if hasNSEC3ExactNoData(qname, qtype, material) {
		return true, "signed exact-match NSEC3 proof established that the requested RR type does not exist", nil
	}
	if hasNSEC3NameError(qname, material) {
		return true, "signed NSEC3 closest-encloser proof established that the queried owner name does not exist", nil
	}
	if hasNSEC3WildcardNoData(qname, qtype, material) {
		return true, "signed NSEC3 wildcard proof established that no matching wildcard RR type exists", nil
	}

	if len(material.NSEC) == 0 && len(material.NSEC3) == 0 {
		return false, "no supported denial proof material was returned", nil
	}
	return false, "signed denial material did not match a supported no-data proof pattern", nil
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

func hasNSECDelegationNoDS(qname string, material denialProofMaterial) bool {
	fqdn := dns.Fqdn(qname)
	for _, set := range material.NSEC {
		for _, rr := range set.RRs {
			nsec := rr.(*dns.NSEC)
			if dns.Fqdn(nsec.Header().Name) != fqdn {
				continue
			}
			if hasDelegationNoDSBits(nsec.TypeBitMap) {
				return true
			}
		}
	}
	return false
}

func hasNSEC3ExactDelegationNoDS(qname string, material denialProofMaterial) bool {
	fqdn := dns.Fqdn(qname)
	for _, set := range material.NSEC3 {
		for _, rr := range set.RRs {
			nsec3 := rr.(*dns.NSEC3)
			if nsec3.Match(fqdn) && hasDelegationNoDSBits(nsec3.TypeBitMap) {
				return true
			}
		}
	}
	return false
}

func hasNSEC3ClosestEncloserOptOutNoDS(qname string, material denialProofMaterial) bool {
	_, _, _, coverSet, ok := findClosestProvableEncloser(qname, material.NSEC3)
	if !ok || coverSet == nil {
		return false
	}
	for _, rr := range coverSet.RRs {
		if rr.(*dns.NSEC3).Flags&1 == 1 {
			return true
		}
	}
	return false
}

func hasNSECExactNoData(qname string, qtype uint16, material denialProofMaterial) bool {
	fqdn := dns.Fqdn(qname)
	for _, set := range material.NSEC {
		for _, rr := range set.RRs {
			nsec := rr.(*dns.NSEC)
			if dns.Fqdn(nsec.Header().Name) != fqdn {
				continue
			}
			if typeBitmapContains(nsec.TypeBitMap, qtype) || typeBitmapContains(nsec.TypeBitMap, dns.TypeCNAME) {
				return false
			}
			return true
		}
	}
	return false
}

func hasNSEC3ExactNoData(qname string, qtype uint16, material denialProofMaterial) bool {
	fqdn := dns.Fqdn(qname)
	match := findMatchingNSEC3Set(fqdn, material.NSEC3)
	if match == nil {
		return false
	}
	for _, rr := range match.RRs {
		nsec3 := rr.(*dns.NSEC3)
		if !nsec3.Match(fqdn) {
			continue
		}
		if typeBitmapContains(nsec3.TypeBitMap, qtype) || typeBitmapContains(nsec3.TypeBitMap, dns.TypeCNAME) {
			return false
		}
		return true
	}
	return false
}

func hasNSEC3NameError(qname string, material denialProofMaterial) bool {
	closestEncloser, _, _, _, ok := findClosestProvableEncloser(qname, material.NSEC3)
	if !ok {
		return false
	}
	wildcardName := dns.Fqdn("*." + strings.TrimSuffix(closestEncloser, "."))
	return findCoveringNSEC3Set(wildcardName, material.NSEC3, false) != nil
}

func hasNSEC3WildcardNoData(qname string, qtype uint16, material denialProofMaterial) bool {
	closestEncloser, _, _, _, ok := findClosestProvableEncloser(qname, material.NSEC3)
	if !ok {
		return false
	}
	wildcardName := dns.Fqdn("*." + strings.TrimSuffix(closestEncloser, "."))
	wildcardMatch := findMatchingNSEC3Set(wildcardName, material.NSEC3)
	if wildcardMatch == nil {
		return false
	}
	for _, rr := range wildcardMatch.RRs {
		nsec3 := rr.(*dns.NSEC3)
		if !nsec3.Match(wildcardName) {
			continue
		}
		if typeBitmapContains(nsec3.TypeBitMap, qtype) || typeBitmapContains(nsec3.TypeBitMap, dns.TypeCNAME) {
			return false
		}
		return true
	}
	return false
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
