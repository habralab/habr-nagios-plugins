package msgcatalog

func DNSRREnglishSource() Source {
	return Source{
		Name:            "probe/dnsrr",
		AllowedPrefixes: []string{"dnsrr_"},
		Items: map[Key]Message{
			"dnsrr_not_found":                {Summary: "the requested RRset was not present where the selected mode required it"},
			"dnsrr_inconclusive":             {Summary: "authoritative endpoint failures made the RRset presence result inconclusive"},
			"dnsrr_unexpected_presence":      {Summary: "the requested RRset was present where the selected mode required absence"},
			"dnsrr_endpoint_failed":          {Summary: "an authoritative endpoint failed during RRset evaluation"},
			"dnsrr_discovery_failed":         {Summary: "authoritative zone discovery failed"},
			"dnsrr_no_authoritative_answers": {Summary: "no authoritative endpoint returned a usable answer"},
			"dnsrr_rrset_inconsistent":       {Summary: "the requested RRset differed across authoritative endpoints"},
			"dnsrr_master_missing_soa":       {Summary: "the formal master could not be determined from authoritative SOA data"},
			"dnsrr_master_unresolved":        {Summary: "the formal master could not be resolved to usable endpoints"},
			"dnsrr_dnssec_not_secure":        {Summary: "the requested RRset was not protected by a secure DNSSEC chain"},
			"dnsrr_dnssec_validation_failed": {Summary: "the requested RRset failed DNSSEC validation"},
			"dnsrr_dnssec_inconclusive":      {Summary: "the requested RRset DNSSEC state was inconclusive"},
		},
	}
}
