package dnsresolver

import (
	"strings"
	"time"

	"github.com/miekg/dns"
)

func MatchDNSKEYs(dsRecords []*dns.DS, keys []*dns.DNSKEY) []*dns.DNSKEY {
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

func VerifySignedRRSet(keys []*dns.DNSKEY, sigs []*dns.RRSIG, rrset []dns.RR, now time.Time) error {
	return verifyRRSetWithDNSKEYs(keys, sigs, rrset, now)
}

func DNSKEYRRs(keys []*dns.DNSKEY) []dns.RR {
	rrs := make([]dns.RR, 0, len(keys))
	for _, rr := range keys {
		rrs = append(rrs, rr)
	}
	return rrs
}

func DSRRs(records []*dns.DS) []dns.RR {
	rrs := make([]dns.RR, 0, len(records))
	for _, rr := range records {
		rrs = append(rrs, rr)
	}
	return rrs
}
