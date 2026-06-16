package dnschain

import (
	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/core/msgcatalog"
	"github.com/habralab/habr-nagios-plugins/internal/core/probecli"
	"github.com/habralab/habr-nagios-plugins/internal/core/rulecatalog"
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
}

var FindingCatalog = map[string]FindingSpec{
	"dnschain_discovery_failed":                    {Code: "dnschain_discovery_failed", Category: FindingCategoryDelegation, DefaultSeverity: checkreport.StatusUnknown},
	"dnschain_nameserver_unreachable":              {Code: "dnschain_nameserver_unreachable", Category: FindingCategoryTransport, DefaultSeverity: checkreport.StatusWarning},
	"dnschain_nameserver_endpoint_unreachable":     {Code: "dnschain_nameserver_endpoint_unreachable", Category: FindingCategoryTransport, DefaultSeverity: checkreport.StatusWarning},
	"dnschain_nameserver_endpoint_rrset_failed":    {Code: "dnschain_nameserver_endpoint_rrset_failed", Category: FindingCategoryAuthority, DefaultSeverity: checkreport.StatusWarning},
	"dnschain_lame_nameserver":                     {Code: "dnschain_lame_nameserver", Category: FindingCategoryAuthority, DefaultSeverity: checkreport.StatusCritical},
	"dnschain_child_soa_inconsistent":              {Code: "dnschain_child_soa_inconsistent", Category: FindingCategoryConsistency, DefaultSeverity: checkreport.StatusWarning},
	"dnschain_child_ns_inconsistent":               {Code: "dnschain_child_ns_inconsistent", Category: FindingCategoryConsistency, DefaultSeverity: checkreport.StatusWarning},
	"dnschain_dnskey_rrset_inconsistent":           {Code: "dnschain_dnskey_rrset_inconsistent", Category: FindingCategoryConsistency, DefaultSeverity: checkreport.StatusWarning},
	"dnschain_nsec3param_inconsistent":             {Code: "dnschain_nsec3param_inconsistent", Category: FindingCategoryConsistency, DefaultSeverity: checkreport.StatusWarning},
	"dnschain_parent_ds_inconsistent":              {Code: "dnschain_parent_ds_inconsistent", Category: FindingCategoryConsistency, DefaultSeverity: checkreport.StatusWarning},
	"dnschain_no_authoritative_servers":            {Code: "dnschain_no_authoritative_servers", Category: FindingCategoryAuthority, DefaultSeverity: checkreport.StatusCritical},
	"dnschain_partial_authoritative_reachability":  {Code: "dnschain_partial_authoritative_reachability", Category: FindingCategoryAuthority, DefaultSeverity: checkreport.StatusWarning},
	"dnschain_delegation_ns_mismatch":              {Code: "dnschain_delegation_ns_mismatch", Category: FindingCategoryDelegation, DefaultSeverity: checkreport.StatusWarning},
	"dnschain_owner_rr_missing":                    {Code: "dnschain_owner_rr_missing", Category: FindingCategoryAuthority, DefaultSeverity: checkreport.StatusCritical},
	"dnschain_owner_rrset_inconsistent":            {Code: "dnschain_owner_rrset_inconsistent", Category: FindingCategoryConsistency, DefaultSeverity: checkreport.StatusWarning},
	"dnschain_root_dnskey_fetch_failed":            {Code: "dnschain_root_dnskey_fetch_failed", Category: FindingCategoryTransport, DefaultSeverity: checkreport.StatusUnknown},
	"dnschain_root_dnskey_missing":                 {Code: "dnschain_root_dnskey_missing", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusCritical},
	"dnschain_root_anchor_mismatch":                {Code: "dnschain_root_anchor_mismatch", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusCritical},
	"dnschain_root_anchor_partial_match":           {Code: "dnschain_root_anchor_partial_match", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning},
	"dnschain_root_dnskey_rrsig_missing":           {Code: "dnschain_root_dnskey_rrsig_missing", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusCritical},
	"dnschain_root_dnskey_rrsig_invalid":           {Code: "dnschain_root_dnskey_rrsig_invalid", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusCritical},
	"dnschain_dnssec_chain_unavailable":            {Code: "dnschain_dnssec_chain_unavailable", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusUnknown},
	"dnschain_root_trust_state_unknown":            {Code: "dnschain_root_trust_state_unknown", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusUnknown},
	"dnschain_parent_ds_lookup_failed":             {Code: "dnschain_parent_ds_lookup_failed", Category: FindingCategoryTransport, DefaultSeverity: checkreport.StatusUnknown},
	"dnschain_parent_ds_endpoint_failed":           {Code: "dnschain_parent_ds_endpoint_failed", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning},
	"dnschain_parent_ds_mixed_state":               {Code: "dnschain_parent_ds_mixed_state", Category: FindingCategoryConsistency, DefaultSeverity: checkreport.StatusWarning},
	"dnschain_ds_absence_proof_invalid":            {Code: "dnschain_ds_absence_proof_invalid", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusCritical},
	"dnschain_denial_ttl_unexpected":               {Code: "dnschain_denial_ttl_unexpected", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning},
	"dnschain_ds_rrsig_missing":                    {Code: "dnschain_ds_rrsig_missing", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusCritical},
	"dnschain_ds_rrsig_invalid":                    {Code: "dnschain_ds_rrsig_invalid", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusCritical},
	"dnschain_ds_partial_sep_coverage":             {Code: "dnschain_ds_partial_sep_coverage", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning},
	"dnschain_algorithm_not_recommended_in_use":    {Code: "dnschain_algorithm_not_recommended_in_use", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning},
	"dnschain_algorithm_must_not_in_use":           {Code: "dnschain_algorithm_must_not_in_use", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning},
	"dnschain_digest_not_recommended_in_use":       {Code: "dnschain_digest_not_recommended_in_use", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning},
	"dnschain_digest_must_not_in_use":              {Code: "dnschain_digest_must_not_in_use", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning},
	"dnschain_algorithm_not_recommended_published": {Code: "dnschain_algorithm_not_recommended_published", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning},
	"dnschain_algorithm_must_not_published":        {Code: "dnschain_algorithm_must_not_published", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning},
	"dnschain_digest_not_recommended_published":    {Code: "dnschain_digest_not_recommended_published", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning},
	"dnschain_digest_must_not_published":           {Code: "dnschain_digest_must_not_published", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning},
	"dnschain_algorithm_unsupported_published":     {Code: "dnschain_algorithm_unsupported_published", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning},
	"dnschain_digest_unsupported_published":        {Code: "dnschain_digest_unsupported_published", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning},
	"dnschain_nsec3param_not_recommended":          {Code: "dnschain_nsec3param_not_recommended", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning},
	"dnschain_nsec3_name_error_invalid":            {Code: "dnschain_nsec3_name_error_invalid", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusCritical},
	"dnschain_nsec3_name_error_unrecognized":       {Code: "dnschain_nsec3_name_error_unrecognized", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning},
	"dnschain_nsec3_no_data_invalid":               {Code: "dnschain_nsec3_no_data_invalid", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusCritical},
	"dnschain_nsec3_no_data_unrecognized":          {Code: "dnschain_nsec3_no_data_unrecognized", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning},
	"dnschain_nsec3_wildcard_no_data_invalid":      {Code: "dnschain_nsec3_wildcard_no_data_invalid", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusCritical},
	"dnschain_no_secure_entry_point":               {Code: "dnschain_no_secure_entry_point", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusCritical},
	"dnschain_dnskey_lookup_failed":                {Code: "dnschain_dnskey_lookup_failed", Category: FindingCategoryTransport, DefaultSeverity: checkreport.StatusCritical},
	"dnschain_dnskey_missing":                      {Code: "dnschain_dnskey_missing", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusCritical},
	"dnschain_dnskey_rrsig_missing":                {Code: "dnschain_dnskey_rrsig_missing", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusCritical},
	"dnschain_ds_dnskey_mismatch":                  {Code: "dnschain_ds_dnskey_mismatch", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusCritical},
	"dnschain_dnskey_rrsig_invalid":                {Code: "dnschain_dnskey_rrsig_invalid", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusCritical},
	"dnschain_not_implemented":                     {Code: "dnschain_not_implemented", Category: FindingCategoryDelegation, DefaultSeverity: checkreport.StatusUnknown},
}

var findingRegistry = rulecatalog.New(FindingCatalogToEntries(FindingCatalog), func(status checkreport.Status) string {
	return string(status)
})

func makeFinding(code string, severity checkreport.Status, target, message string) checkreport.Finding {
	spec, ok := FindingCatalog[code]
	if !ok {
		spec = FindingSpec{
			Code:            code,
			Category:        FindingCategoryDelegation,
			DefaultSeverity: severity,
		}
	}
	if message == "" {
		message = msgcatalog.DefaultSummaryOrKey(spec.Code)
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
	return findingRegistry.HasSlug(slug)
}

func CatalogSlugs() []string {
	return findingRegistry.Slugs()
}

func CatalogEntries() []probecli.ErrorSlugDescriptor {
	return findingRegistry.Entries()
}

func FindingCatalogToEntries(catalog map[string]FindingSpec) map[string]rulecatalog.Entry[checkreport.Status] {
	out := make(map[string]rulecatalog.Entry[checkreport.Status], len(catalog))
	for slug, spec := range catalog {
		out[slug] = rulecatalog.Entry[checkreport.Status]{
			Slug:     spec.Code,
			Category: string(spec.Category),
			Severity: spec.DefaultSeverity,
			Message:  msgcatalog.DefaultSummaryOrKey(spec.Code),
		}
	}
	return out
}
