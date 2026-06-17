package dnsresolver

import (
	"time"

	"github.com/miekg/dns"
)

func lookupResultTTL(records []dns.RR, sigs []*dns.RRSIG, authority []dns.RR) time.Duration {
	if ttl := rrTTL(append(append([]dns.RR(nil), records...), rrsigSliceToRRs(sigs)...)); ttl > 0 {
		return ttl
	}
	return rrTTL(authority)
}

func resolveResultTTL(result ResolveResult) time.Duration {
	if ttl := lookupResultTTL(result.Lookup.Records, result.Lookup.Signatures, nil); ttl > 0 {
		return ttl
	}
	var ttl time.Duration
	for _, response := range result.Responses {
		if !response.Authoritative {
			continue
		}
		ttl = minTTL(ttl, lookupResultTTL(response.Records, response.Signatures, response.Authority))
	}
	return ttl
}

func authorityResultTTL(hops []delegationHop) time.Duration {
	if len(hops) == 0 {
		return 0
	}
	return delegationHopTTL(hops[len(hops)-1])
}

func authorityResultTTLForZone(zone string, hops []delegationHop) time.Duration {
	zone = dns.Fqdn(zone)
	for i := len(hops) - 1; i >= 0; i-- {
		if dns.Fqdn(hops[i].ToZone) == zone {
			return delegationHopTTL(hops[i])
		}
	}
	return 0
}

func zoneChainTTL(hops []delegationHop) time.Duration {
	if len(hops) == 0 {
		return 0
	}
	var ttl time.Duration
	for _, hop := range hops {
		ttl = minTTL(ttl, delegationHopTTL(hop))
	}
	return ttl
}

func delegationHopTTL(hop delegationHop) time.Duration {
	return hop.CacheTTL
}

func referralTTL(msg *dns.Msg, zone string, nsNames []string) time.Duration {
	if msg == nil {
		return 0
	}
	var rrset []dns.RR
	target := dns.Fqdn(zone)
	wantNS := map[string]bool{}
	for _, name := range nsNames {
		wantNS[dns.Fqdn(name)] = true
	}
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns} {
		for _, rr := range section {
			ns, ok := rr.(*dns.NS)
			if !ok {
				continue
			}
			if dns.Fqdn(ns.Header().Name) != target {
				continue
			}
			rrset = append(rrset, rr)
		}
	}
	for _, rr := range msg.Extra {
		switch v := rr.(type) {
		case *dns.A:
			if wantNS[dns.Fqdn(v.Header().Name)] {
				rrset = append(rrset, rr)
			}
		case *dns.AAAA:
			if wantNS[dns.Fqdn(v.Header().Name)] {
				rrset = append(rrset, rr)
			}
		}
	}
	return rrTTL(rrset)
}

func rrTTL(rrs []dns.RR) time.Duration {
	var ttl time.Duration
	for _, rr := range rrs {
		if rr == nil || rr.Header() == nil {
			continue
		}
		candidate := time.Duration(rr.Header().Ttl) * time.Second
		ttl = minTTL(ttl, candidate)
	}
	return ttl
}

func rrsigSliceToRRs(sigs []*dns.RRSIG) []dns.RR {
	if len(sigs) == 0 {
		return nil
	}
	out := make([]dns.RR, 0, len(sigs))
	for _, sig := range sigs {
		if sig != nil {
			out = append(out, sig)
		}
	}
	return out
}

func minTTL(current, candidate time.Duration) time.Duration {
	switch {
	case candidate <= 0:
		return current
	case current <= 0:
		return candidate
	case candidate < current:
		return candidate
	default:
		return current
	}
}
