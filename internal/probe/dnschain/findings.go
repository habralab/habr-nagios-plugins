package dnschain

import (
	"sort"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/core/probecli"
)

type FindingCategory string

const (
	FindingCategoryTransport   FindingCategory = "transport"
	FindingCategoryDelegation  FindingCategory = "delegation"
	FindingCategoryDNSSEC      FindingCategory = "dnssec"
	FindingCategoryAuthority   FindingCategory = "authority"
	FindingCategoryConsistency FindingCategory = "consistency"
)

type FindingSpec struct {
	Code            string
	Category        FindingCategory
	DefaultSeverity checkreport.Status
	DefaultMessage  string
}

var FindingCatalog = map[string]FindingSpec{
	"dnschain_discovery_failed":                    {Code: "dnschain_discovery_failed", Category: FindingCategoryDelegation, DefaultSeverity: checkreport.StatusUnknown, DefaultMessage: "zone discovery failed"},
	"dnschain_nameserver_unreachable":              {Code: "dnschain_nameserver_unreachable", Category: FindingCategoryTransport, DefaultSeverity: checkreport.StatusWarning, DefaultMessage: "authoritative name server did not answer"},
	"dnschain_nameserver_endpoint_unreachable":     {Code: "dnschain_nameserver_endpoint_unreachable", Category: FindingCategoryTransport, DefaultSeverity: checkreport.StatusWarning, DefaultMessage: "an authoritative name server address did not answer"},
	"dnschain_nameserver_endpoint_rrset_failed":    {Code: "dnschain_nameserver_endpoint_rrset_failed", Category: FindingCategoryAuthority, DefaultSeverity: checkreport.StatusWarning, DefaultMessage: "an authoritative name server address did not serve an expected RRset"},
	"dnschain_lame_nameserver":                     {Code: "dnschain_lame_nameserver", Category: FindingCategoryAuthority, DefaultSeverity: checkreport.StatusCritical, DefaultMessage: "delegated name server answered without authoritative data"},
	"dnschain_child_soa_inconsistent":              {Code: "dnschain_child_soa_inconsistent", Category: FindingCategoryConsistency, DefaultSeverity: checkreport.StatusWarning, DefaultMessage: "child authoritative servers served different SOA RRsets"},
	"dnschain_child_ns_inconsistent":               {Code: "dnschain_child_ns_inconsistent", Category: FindingCategoryConsistency, DefaultSeverity: checkreport.StatusWarning, DefaultMessage: "child authoritative servers served different NS RRsets"},
	"dnschain_dnskey_rrset_inconsistent":           {Code: "dnschain_dnskey_rrset_inconsistent", Category: FindingCategoryConsistency, DefaultSeverity: checkreport.StatusWarning, DefaultMessage: "child authoritative servers served different DNSKEY RRsets"},
	"dnschain_nsec3param_inconsistent":             {Code: "dnschain_nsec3param_inconsistent", Category: FindingCategoryConsistency, DefaultSeverity: checkreport.StatusWarning, DefaultMessage: "child authoritative servers served different NSEC3PARAM RRsets"},
	"dnschain_parent_ds_inconsistent":              {Code: "dnschain_parent_ds_inconsistent", Category: FindingCategoryConsistency, DefaultSeverity: checkreport.StatusWarning, DefaultMessage: "parent authoritative servers served different DS RRsets"},
	"dnschain_no_authoritative_servers":            {Code: "dnschain_no_authoritative_servers", Category: FindingCategoryAuthority, DefaultSeverity: checkreport.StatusCritical, DefaultMessage: "no delegated authoritative server returned an authoritative SOA response"},
	"dnschain_partial_authoritative_reachability":  {Code: "dnschain_partial_authoritative_reachability", Category: FindingCategoryAuthority, DefaultSeverity: checkreport.StatusWarning, DefaultMessage: "only part of the delegated authoritative set answered authoritatively"},
	"dnschain_delegation_ns_mismatch":              {Code: "dnschain_delegation_ns_mismatch", Category: FindingCategoryDelegation, DefaultSeverity: checkreport.StatusWarning, DefaultMessage: "delegation NS set differs from child authoritative NS RRset"},
	"dnschain_owner_rr_missing":                    {Code: "dnschain_owner_rr_missing", Category: FindingCategoryAuthority, DefaultSeverity: checkreport.StatusCritical, DefaultMessage: "the requested owner name has no CNAME, A, or AAAA RRset on the authoritative servers"},
	"dnschain_owner_rrset_inconsistent":            {Code: "dnschain_owner_rrset_inconsistent", Category: FindingCategoryConsistency, DefaultSeverity: checkreport.StatusWarning, DefaultMessage: "authoritative servers served different owner RRsets for the requested name"},
	"dnschain_root_dnskey_fetch_failed":            {Code: "dnschain_root_dnskey_fetch_failed", Category: FindingCategoryTransport, DefaultSeverity: checkreport.StatusUnknown, DefaultMessage: "root DNSKEY lookup failed"},
	"dnschain_root_dnskey_missing":                 {Code: "dnschain_root_dnskey_missing", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusCritical, DefaultMessage: "root DNSKEY RRset was not returned"},
	"dnschain_root_anchor_mismatch":                {Code: "dnschain_root_anchor_mismatch", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusCritical, DefaultMessage: "embedded root trust anchors did not match the published root DNSKEY RRset"},
	"dnschain_root_anchor_partial_match":           {Code: "dnschain_root_anchor_partial_match", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning, DefaultMessage: "not all current root trust anchors matched the published root DNSKEY RRset"},
	"dnschain_root_dnskey_rrsig_missing":           {Code: "dnschain_root_dnskey_rrsig_missing", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusCritical, DefaultMessage: "root DNSKEY RRset had no RRSIG records"},
	"dnschain_root_dnskey_rrsig_invalid":           {Code: "dnschain_root_dnskey_rrsig_invalid", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusCritical, DefaultMessage: "root DNSKEY RRset signature validation failed"},
	"dnschain_dnssec_chain_unavailable":            {Code: "dnschain_dnssec_chain_unavailable", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusUnknown, DefaultMessage: "DNSSEC chain validation was unavailable"},
	"dnschain_root_trust_state_unknown":            {Code: "dnschain_root_trust_state_unknown", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusUnknown, DefaultMessage: "root trust anchor validation did not yield a trusted root DNSKEY RRset"},
	"dnschain_parent_ds_lookup_failed":             {Code: "dnschain_parent_ds_lookup_failed", Category: FindingCategoryTransport, DefaultSeverity: checkreport.StatusUnknown, DefaultMessage: "parent DS lookup failed"},
	"dnschain_parent_ds_endpoint_failed":           {Code: "dnschain_parent_ds_endpoint_failed", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning, DefaultMessage: "a parent authoritative endpoint did not return an authoritative DS response"},
	"dnschain_parent_ds_mixed_state":               {Code: "dnschain_parent_ds_mixed_state", Category: FindingCategoryConsistency, DefaultSeverity: checkreport.StatusWarning, DefaultMessage: "parent authoritative endpoints disagree on whether the delegation has DS records"},
	"dnschain_ds_absence_proof_invalid":            {Code: "dnschain_ds_absence_proof_invalid", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusCritical, DefaultMessage: "missing DS denial proof validation failed"},
	"dnschain_denial_ttl_unexpected":               {Code: "dnschain_denial_ttl_unexpected", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning, DefaultMessage: "denial proof TTL exceeded the RFC 9077 negative TTL bound"},
	"dnschain_ds_rrsig_missing":                    {Code: "dnschain_ds_rrsig_missing", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusCritical, DefaultMessage: "parent published DS records without RRSIG coverage"},
	"dnschain_ds_rrsig_invalid":                    {Code: "dnschain_ds_rrsig_invalid", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusCritical, DefaultMessage: "parent DS RRset signature validation failed"},
	"dnschain_ds_partial_sep_coverage":             {Code: "dnschain_ds_partial_sep_coverage", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning, DefaultMessage: "some parent DS algorithms do not establish a valid secure entry point"},
	"dnschain_algorithm_not_recommended_in_use":    {Code: "dnschain_algorithm_not_recommended_in_use", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning, DefaultMessage: "active secure entry points rely on not-recommended DNSKEY algorithms"},
	"dnschain_algorithm_must_not_in_use":           {Code: "dnschain_algorithm_must_not_in_use", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning, DefaultMessage: "active secure entry points rely on MUST-NOT DNSKEY algorithms"},
	"dnschain_digest_not_recommended_in_use":       {Code: "dnschain_digest_not_recommended_in_use", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning, DefaultMessage: "active secure entry points rely on not-recommended DS digests"},
	"dnschain_digest_must_not_in_use":              {Code: "dnschain_digest_must_not_in_use", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning, DefaultMessage: "active secure entry points rely on MUST-NOT DS digests"},
	"dnschain_algorithm_not_recommended_published": {Code: "dnschain_algorithm_not_recommended_published", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning, DefaultMessage: "published DNSKEY algorithms include not-recommended values"},
	"dnschain_algorithm_must_not_published":        {Code: "dnschain_algorithm_must_not_published", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning, DefaultMessage: "published DNSKEY algorithms include MUST-NOT values"},
	"dnschain_digest_not_recommended_published":    {Code: "dnschain_digest_not_recommended_published", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning, DefaultMessage: "published DS digests include not-recommended values"},
	"dnschain_digest_must_not_published":           {Code: "dnschain_digest_must_not_published", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning, DefaultMessage: "published DS digests include MUST-NOT values"},
	"dnschain_algorithm_unsupported_published":     {Code: "dnschain_algorithm_unsupported_published", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning, DefaultMessage: "published DNSKEY algorithms include values the checker cannot validate"},
	"dnschain_digest_unsupported_published":        {Code: "dnschain_digest_unsupported_published", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning, DefaultMessage: "published DS digests include values the checker cannot reproduce"},
	"dnschain_nsec3param_not_recommended":          {Code: "dnschain_nsec3param_not_recommended", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning, DefaultMessage: "published NSEC3PARAM settings depart from RFC 9276 recommendations"},
	"dnschain_nsec3_name_error_invalid":            {Code: "dnschain_nsec3_name_error_invalid", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusCritical, DefaultMessage: "NSEC3 name-error proof validation failed"},
	"dnschain_nsec3_name_error_unrecognized":       {Code: "dnschain_nsec3_name_error_unrecognized", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning, DefaultMessage: "NSEC3 name-error proof was not recognized"},
	"dnschain_nsec3_no_data_invalid":               {Code: "dnschain_nsec3_no_data_invalid", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusCritical, DefaultMessage: "NSEC3 no-data proof validation failed"},
	"dnschain_nsec3_no_data_unrecognized":          {Code: "dnschain_nsec3_no_data_unrecognized", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning, DefaultMessage: "NSEC3 no-data proof was not recognized"},
	"dnschain_nsec3_wildcard_no_data_invalid":      {Code: "dnschain_nsec3_wildcard_no_data_invalid", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusCritical, DefaultMessage: "NSEC3 wildcard no-data proof validation failed"},
	"dnschain_no_secure_entry_point":               {Code: "dnschain_no_secure_entry_point", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusCritical, DefaultMessage: "no secure entry point was established from the parent DS RRset"},
	"dnschain_dnskey_lookup_failed":                {Code: "dnschain_dnskey_lookup_failed", Category: FindingCategoryTransport, DefaultSeverity: checkreport.StatusCritical, DefaultMessage: "child DNSKEY lookup failed"},
	"dnschain_dnskey_missing":                      {Code: "dnschain_dnskey_missing", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusCritical, DefaultMessage: "parent publishes DS records but no child DNSKEY RRset was obtained"},
	"dnschain_dnskey_rrsig_missing":                {Code: "dnschain_dnskey_rrsig_missing", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusCritical, DefaultMessage: "child DNSKEY RRset had no RRSIG records"},
	"dnschain_ds_dnskey_mismatch":                  {Code: "dnschain_ds_dnskey_mismatch", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusCritical, DefaultMessage: "no parent DS record matches any child DNSKEY"},
	"dnschain_dnskey_rrsig_invalid":                {Code: "dnschain_dnskey_rrsig_invalid", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusCritical, DefaultMessage: "child DNSKEY RRset signature validation failed"},
	"dnschain_not_implemented":                     {Code: "dnschain_not_implemented", Category: FindingCategoryDelegation, DefaultSeverity: checkreport.StatusUnknown, DefaultMessage: "live authoritative DNS analysis was not selected for this execution path"},
}

func makeFinding(code string, severity checkreport.Status, target, message string) checkreport.Finding {
	spec, ok := FindingCatalog[code]
	if !ok {
		spec = FindingSpec{
			Code:            code,
			Category:        FindingCategoryDelegation,
			DefaultSeverity: severity,
			DefaultMessage:  code,
		}
	}
	if message == "" {
		message = spec.DefaultMessage
	}
	if severity == "" {
		severity = spec.DefaultSeverity
	}
	return checkreport.Finding{
		Code:     spec.Code,
		Severity: severity,
		Target:   target,
		Message:  message,
	}
}

func CatalogHasSlug(slug string) bool {
	_, ok := FindingCatalog[slug]
	return ok
}

func CatalogSlugs() []string {
	out := make([]string, 0, len(FindingCatalog))
	for slug := range FindingCatalog {
		out = append(out, slug)
	}
	sort.Strings(out)
	return out
}

func CatalogEntries() []probecli.ErrorSlugDescriptor {
	slugs := CatalogSlugs()
	out := make([]probecli.ErrorSlugDescriptor, 0, len(slugs))
	for _, slug := range slugs {
		spec := FindingCatalog[slug]
		out = append(out, probecli.ErrorSlugDescriptor{
			Slug:     spec.Code,
			Category: string(spec.Category),
			Severity: string(spec.DefaultSeverity),
			Message:  spec.DefaultMessage,
		})
	}
	return out
}
