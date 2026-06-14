package dnschain

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/miekg/dns"
)

type algorithmUseProfile string

const (
	algorithmUseRecommended    algorithmUseProfile = "recommended"
	algorithmUseAcceptable     algorithmUseProfile = "acceptable"
	algorithmUseNotRecommended algorithmUseProfile = "not_recommended"
	algorithmUseMustNot        algorithmUseProfile = "must_not"
	algorithmUseUnknown        algorithmUseProfile = "unknown"
)

type dnskeyAlgorithmProfile struct {
	Name          string
	UseProfile    algorithmUseProfile
	VerifySupport bool
}

type dsDigestProfile struct {
	Name           string
	UseProfile     algorithmUseProfile
	ComputeSupport bool
}

var dnskeyAlgorithmProfiles = map[uint8]dnskeyAlgorithmProfile{
	dns.RSAMD5:           {Name: "RSAMD5", UseProfile: algorithmUseMustNot, VerifySupport: false},
	dns.DSA:              {Name: "DSA", UseProfile: algorithmUseMustNot, VerifySupport: false},
	dns.RSASHA1:          {Name: "RSASHA1", UseProfile: algorithmUseNotRecommended, VerifySupport: true},
	dns.DSANSEC3SHA1:     {Name: "DSA-NSEC3-SHA1", UseProfile: algorithmUseMustNot, VerifySupport: false},
	dns.RSASHA1NSEC3SHA1: {Name: "RSASHA1-NSEC3-SHA1", UseProfile: algorithmUseNotRecommended, VerifySupport: true},
	dns.RSASHA256:        {Name: "RSASHA256", UseProfile: algorithmUseRecommended, VerifySupport: true},
	dns.RSASHA512:        {Name: "RSASHA512", UseProfile: algorithmUseAcceptable, VerifySupport: true},
	dns.ECCGOST:          {Name: "ECC-GOST", UseProfile: algorithmUseMustNot, VerifySupport: false},
	dns.ECDSAP256SHA256:  {Name: "ECDSAP256SHA256", UseProfile: algorithmUseRecommended, VerifySupport: true},
	dns.ECDSAP384SHA384:  {Name: "ECDSAP384SHA384", UseProfile: algorithmUseAcceptable, VerifySupport: true},
	dns.ED25519:          {Name: "ED25519", UseProfile: algorithmUseRecommended, VerifySupport: true},
	dns.ED448:            {Name: "ED448", UseProfile: algorithmUseAcceptable, VerifySupport: false},
}

var dsDigestProfiles = map[uint8]dsDigestProfile{
	dns.SHA1:   {Name: "SHA1", UseProfile: algorithmUseNotRecommended, ComputeSupport: true},
	dns.SHA256: {Name: "SHA256", UseProfile: algorithmUseRecommended, ComputeSupport: true},
	dns.GOST94: {Name: "GOST94", UseProfile: algorithmUseMustNot, ComputeSupport: false},
	dns.SHA384: {Name: "SHA384", UseProfile: algorithmUseAcceptable, ComputeSupport: true},
	dns.SHA512: {Name: "SHA512", UseProfile: algorithmUseUnknown, ComputeSupport: true},
}

type cryptoPolicyAssessment struct {
	Evidence                           []checkreport.Evidence
	ActiveNotRecommendedAlgorithmNames []string
	ActiveMustNotAlgorithmNames        []string
	ActiveNotRecommendedDigestNames    []string
	ActiveMustNotDigestNames           []string
	PublishedNotRecommendedAlgorithms  []string
	PublishedMustNotAlgorithms         []string
	PublishedNotRecommendedDigests     []string
	PublishedMustNotDigests            []string
	PublishedUnsupportedAlgorithms     []string
	PublishedUnsupportedDigestNames    []string
	IgnoredDigestNames                 []string
}

func assessCryptoPolicy(dsRecords []*dns.DS, keys []*dns.DNSKEY, sigs []*dns.RRSIG, now time.Time) cryptoPolicyAssessment {
	activeKeys, activeDSRecords, _ := verifiedSEPMaterial(dsRecords, keys, sigs, now)
	activeAlgorithms := map[uint8]bool{}
	activeDigests := map[uint8]bool{}
	allChildAlgorithms := map[uint8]bool{}
	dsAlgorithms := map[uint8]bool{}
	dsDigests := map[uint8]bool{}
	var unsupportedChildAlgos []string
	var unsupportedDigests []string
	var activeNotRecommendedAlgorithms []string
	var activeMustNotAlgorithms []string
	var activeNotRecommendedDigests []string
	var activeMustNotDigests []string
	var publishedNotRecommendedAlgorithms []string
	var publishedMustNotAlgorithms []string
	var publishedNotRecommendedDigests []string
	var publishedMustNotDigests []string
	ignoredDigests := ignoredDSDigestTypes(dsRecords)

	for _, key := range keys {
		allChildAlgorithms[key.Algorithm] = true
		profile := profileForDNSKEYAlgorithm(key.Algorithm)
		if !profile.VerifySupport {
			unsupportedChildAlgos = append(unsupportedChildAlgos, profileLabelDNSKEY(key.Algorithm))
		}
		switch profile.UseProfile {
		case algorithmUseNotRecommended:
			publishedNotRecommendedAlgorithms = append(publishedNotRecommendedAlgorithms, profile.Name)
		case algorithmUseMustNot:
			publishedMustNotAlgorithms = append(publishedMustNotAlgorithms, profile.Name)
		}
	}
	for _, key := range activeKeys {
		activeAlgorithms[key.Algorithm] = true
		profile := profileForDNSKEYAlgorithm(key.Algorithm)
		switch profile.UseProfile {
		case algorithmUseNotRecommended:
			activeNotRecommendedAlgorithms = append(activeNotRecommendedAlgorithms, profile.Name)
		case algorithmUseMustNot:
			activeMustNotAlgorithms = append(activeMustNotAlgorithms, profile.Name)
		}
	}
	for _, ds := range activeDSRecords {
		activeDigests[ds.DigestType] = true
		if ignoredDigests[ds.DigestType] {
			continue
		}
		profile := profileForDSDigest(ds.DigestType)
		switch profile.UseProfile {
		case algorithmUseNotRecommended:
			activeNotRecommendedDigests = append(activeNotRecommendedDigests, profile.Name)
		case algorithmUseMustNot:
			activeMustNotDigests = append(activeMustNotDigests, profile.Name)
		}
	}
	for _, ds := range dsRecords {
		dsAlgorithms[ds.Algorithm] = true
		dsDigests[ds.DigestType] = true
		digestProfile := profileForDSDigest(ds.DigestType)
		if !digestProfile.ComputeSupport {
			unsupportedDigests = append(unsupportedDigests, profileLabelDigest(ds.DigestType))
		}
		if ignoredDigests[ds.DigestType] {
			continue
		}
		switch digestProfile.UseProfile {
		case algorithmUseNotRecommended:
			publishedNotRecommendedDigests = append(publishedNotRecommendedDigests, digestProfile.Name)
		case algorithmUseMustNot:
			publishedMustNotDigests = append(publishedMustNotDigests, digestProfile.Name)
		}
	}

	evidence := checkreport.Evidence{
		Kind:    "dnssec.crypto_policy",
		Summary: "DNSSEC algorithm and digest profile for the active trust path",
		Attributes: []checkreport.KV{
			{Key: "active_dnskey_algorithms", Value: strings.Join(sortedAlgorithmLabels(activeAlgorithms), ", ")},
			{Key: "active_ds_digests", Value: strings.Join(sortedDigestLabels(activeDigests), ", ")},
			{Key: "child_dnskey_algorithms", Value: strings.Join(sortedAlgorithmLabels(allChildAlgorithms), ", ")},
			{Key: "parent_ds_algorithms", Value: strings.Join(sortedAlgorithmLabels(dsAlgorithms), ", ")},
			{Key: "parent_ds_digests", Value: strings.Join(sortedDigestLabels(dsDigests), ", ")},
		},
	}
	if len(activeNotRecommendedAlgorithms) > 0 {
		evidence.Attributes = append(evidence.Attributes, checkreport.KV{
			Key:   "active_not_recommended_algorithms",
			Value: strings.Join(uniqueSorted(activeNotRecommendedAlgorithms), ", "),
		})
	}
	if len(activeMustNotAlgorithms) > 0 {
		evidence.Attributes = append(evidence.Attributes, checkreport.KV{
			Key:   "active_must_not_algorithms",
			Value: strings.Join(uniqueSorted(activeMustNotAlgorithms), ", "),
		})
	}
	if len(activeNotRecommendedDigests) > 0 {
		evidence.Attributes = append(evidence.Attributes, checkreport.KV{
			Key:   "active_not_recommended_ds_digests",
			Value: strings.Join(uniqueSorted(activeNotRecommendedDigests), ", "),
		})
	}
	if len(activeMustNotDigests) > 0 {
		evidence.Attributes = append(evidence.Attributes, checkreport.KV{
			Key:   "active_must_not_ds_digests",
			Value: strings.Join(uniqueSorted(activeMustNotDigests), ", "),
		})
	}
	if len(publishedNotRecommendedAlgorithms) > 0 {
		evidence.Attributes = append(evidence.Attributes, checkreport.KV{
			Key:   "published_not_recommended_dnskey_algorithms",
			Value: strings.Join(uniqueSorted(publishedNotRecommendedAlgorithms), ", "),
		})
	}
	if len(publishedMustNotAlgorithms) > 0 {
		evidence.Attributes = append(evidence.Attributes, checkreport.KV{
			Key:   "published_must_not_dnskey_algorithms",
			Value: strings.Join(uniqueSorted(publishedMustNotAlgorithms), ", "),
		})
	}
	if len(publishedNotRecommendedDigests) > 0 {
		evidence.Attributes = append(evidence.Attributes, checkreport.KV{
			Key:   "published_not_recommended_ds_digests",
			Value: strings.Join(uniqueSorted(publishedNotRecommendedDigests), ", "),
		})
	}
	if len(publishedMustNotDigests) > 0 {
		evidence.Attributes = append(evidence.Attributes, checkreport.KV{
			Key:   "published_must_not_ds_digests",
			Value: strings.Join(uniqueSorted(publishedMustNotDigests), ", "),
		})
	}
	if len(unsupportedChildAlgos) > 0 {
		evidence.Attributes = append(evidence.Attributes, checkreport.KV{
			Key:   "checker_unimplemented_dnskey_algorithms",
			Value: strings.Join(uniqueSorted(unsupportedChildAlgos), ", "),
		})
	}
	if len(unsupportedDigests) > 0 {
		evidence.Attributes = append(evidence.Attributes, checkreport.KV{
			Key:   "checker_unimplemented_ds_digests",
			Value: strings.Join(uniqueSorted(unsupportedDigests), ", "),
		})
	}
	if len(ignoredDigests) > 0 {
		evidence.Attributes = append(evidence.Attributes, checkreport.KV{
			Key:   "ignored_ds_digests",
			Value: strings.Join(sortedDigestLabels(ignoredDigests), ", "),
		})
	}

	return cryptoPolicyAssessment{
		Evidence:                           []checkreport.Evidence{evidence},
		ActiveNotRecommendedAlgorithmNames: uniqueSorted(activeNotRecommendedAlgorithms),
		ActiveMustNotAlgorithmNames:        uniqueSorted(activeMustNotAlgorithms),
		ActiveNotRecommendedDigestNames:    uniqueSorted(activeNotRecommendedDigests),
		ActiveMustNotDigestNames:           uniqueSorted(activeMustNotDigests),
		PublishedNotRecommendedAlgorithms:  uniqueSorted(publishedNotRecommendedAlgorithms),
		PublishedMustNotAlgorithms:         uniqueSorted(publishedMustNotAlgorithms),
		PublishedNotRecommendedDigests:     uniqueSorted(publishedNotRecommendedDigests),
		PublishedMustNotDigests:            uniqueSorted(publishedMustNotDigests),
		PublishedUnsupportedAlgorithms:     uniqueSorted(unsupportedChildAlgos),
		PublishedUnsupportedDigestNames:    uniqueSorted(unsupportedDigests),
		IgnoredDigestNames:                 sortedDigestLabels(ignoredDigests),
	}
}

func verifiedSEPKeys(dsRecords []*dns.DS, keys []*dns.DNSKEY, sigs []*dns.RRSIG, now time.Time) ([]*dns.DNSKEY, []uint8) {
	keysOnly, _, unsupported := verifiedSEPMaterial(dsRecords, keys, sigs, now)
	return keysOnly, unsupported
}

func verifiedSEPMaterial(dsRecords []*dns.DS, keys []*dns.DNSKEY, sigs []*dns.RRSIG, now time.Time) ([]*dns.DNSKEY, []*dns.DS, []uint8) {
	verified := map[uint16]*dns.DNSKEY{}
	activeDS := map[string]*dns.DS{}
	unsupported := map[uint8]bool{}
	for _, ds := range dsRecords {
		for _, key := range matchingDNSKEYs([]*dns.DS{ds}, keys) {
			sawUnsupported := false
			for _, sig := range sigs {
				if sig.KeyTag != key.KeyTag() || !sig.ValidityPeriod(now) {
					continue
				}
				err := sig.Verify(key, dnskeysToRRs(keys))
				if err == nil {
					verified[key.KeyTag()] = key
					activeDS[dsIdentity(ds)] = ds
					sawUnsupported = false
					break
				}
				if err == dns.ErrAlg {
					sawUnsupported = true
				}
			}
			if sawUnsupported {
				unsupported[key.Algorithm] = true
			}
		}
	}
	var verifiedKeys []*dns.DNSKEY
	for _, key := range verified {
		verifiedKeys = append(verifiedKeys, key)
	}
	sort.Slice(verifiedKeys, func(i, j int) bool {
		if verifiedKeys[i].Algorithm != verifiedKeys[j].Algorithm {
			return verifiedKeys[i].Algorithm < verifiedKeys[j].Algorithm
		}
		return verifiedKeys[i].KeyTag() < verifiedKeys[j].KeyTag()
	})
	var verifiedDS []*dns.DS
	for _, ds := range activeDS {
		verifiedDS = append(verifiedDS, ds)
	}
	sort.Slice(verifiedDS, func(i, j int) bool {
		if verifiedDS[i].Algorithm != verifiedDS[j].Algorithm {
			return verifiedDS[i].Algorithm < verifiedDS[j].Algorithm
		}
		if verifiedDS[i].DigestType != verifiedDS[j].DigestType {
			return verifiedDS[i].DigestType < verifiedDS[j].DigestType
		}
		if verifiedDS[i].KeyTag != verifiedDS[j].KeyTag {
			return verifiedDS[i].KeyTag < verifiedDS[j].KeyTag
		}
		return verifiedDS[i].Digest < verifiedDS[j].Digest
	})
	var unsupportedAlgs []uint8
	for alg := range unsupported {
		unsupportedAlgs = append(unsupportedAlgs, alg)
	}
	sort.Slice(unsupportedAlgs, func(i, j int) bool { return unsupportedAlgs[i] < unsupportedAlgs[j] })
	return verifiedKeys, verifiedDS, unsupportedAlgs
}

func profileForDNSKEYAlgorithm(alg uint8) dnskeyAlgorithmProfile {
	if profile, ok := dnskeyAlgorithmProfiles[alg]; ok {
		return profile
	}
	return dnskeyAlgorithmProfile{
		Name:          dns.AlgorithmToString[alg],
		UseProfile:    algorithmUseUnknown,
		VerifySupport: false,
	}
}

func profileForDSDigest(digest uint8) dsDigestProfile {
	if profile, ok := dsDigestProfiles[digest]; ok {
		return profile
	}
	return dsDigestProfile{
		Name:           dns.HashToString[digest],
		UseProfile:     algorithmUseUnknown,
		ComputeSupport: false,
	}
}

func profileLabelDNSKEY(alg uint8) string {
	profile := profileForDNSKEYAlgorithm(alg)
	name := profile.Name
	if name == "" {
		name = fmt.Sprintf("alg-%d", alg)
	}
	return fmt.Sprintf("%s(%d)", name, alg)
}

func profileLabelDigest(digest uint8) string {
	profile := profileForDSDigest(digest)
	name := profile.Name
	if name == "" {
		name = fmt.Sprintf("digest-%d", digest)
	}
	return fmt.Sprintf("%s(%d)", name, digest)
}

func sortedAlgorithmLabels(values map[uint8]bool) []string {
	var labels []string
	for alg := range values {
		labels = append(labels, profileLabelDNSKEY(alg))
	}
	sort.Strings(labels)
	return labels
}

func sortedDigestLabels(values map[uint8]bool) []string {
	var labels []string
	for digest := range values {
		labels = append(labels, profileLabelDigest(digest))
	}
	sort.Strings(labels)
	return labels
}

func uniqueSorted(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	index := map[string]bool{}
	for _, value := range values {
		index[value] = true
	}
	out := make([]string, 0, len(index))
	for value := range index {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func ignoredDSDigestTypes(dsRecords []*dns.DS) map[uint8]bool {
	ignored := map[uint8]bool{}
	hasSHA256 := false
	for _, ds := range dsRecords {
		if ds.DigestType == dns.SHA256 {
			hasSHA256 = true
			break
		}
	}
	if hasSHA256 {
		for _, ds := range dsRecords {
			if ds.DigestType == dns.SHA1 {
				ignored[dns.SHA1] = true
			}
		}
	}
	return ignored
}

func dsIdentity(ds *dns.DS) string {
	return fmt.Sprintf("%s|%d|%d|%d|%s", dns.Fqdn(ds.Header().Name), ds.KeyTag, ds.Algorithm, ds.DigestType, strings.ToUpper(ds.Digest))
}
