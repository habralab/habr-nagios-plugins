package dnsrr

import (
	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/core/msgcatalog"
	"github.com/habralab/habr-nagios-plugins/internal/core/probecli"
	"github.com/habralab/habr-nagios-plugins/internal/core/rulecatalog"
)

type FindingCategory string

const (
	FindingCategoryPresence    FindingCategory = "presence"
	FindingCategoryTransport   FindingCategory = "transport"
	FindingCategoryConsistency FindingCategory = "consistency"
	FindingCategoryAuthority   FindingCategory = "authority"
	FindingCategoryDNSSEC      FindingCategory = "dnssec"
)

type FindingSpec struct {
	Code            string
	Category        FindingCategory
	DefaultSeverity checkreport.Status
}

var FindingCatalog = map[string]FindingSpec{
	"dnsrr_not_found":                {Code: "dnsrr_not_found", Category: FindingCategoryPresence, DefaultSeverity: checkreport.StatusCritical},
	"dnsrr_inconclusive":             {Code: "dnsrr_inconclusive", Category: FindingCategoryAuthority, DefaultSeverity: checkreport.StatusUnknown},
	"dnsrr_unexpected_presence":      {Code: "dnsrr_unexpected_presence", Category: FindingCategoryPresence, DefaultSeverity: checkreport.StatusCritical},
	"dnsrr_endpoint_failed":          {Code: "dnsrr_endpoint_failed", Category: FindingCategoryTransport, DefaultSeverity: checkreport.StatusWarning},
	"dnsrr_discovery_failed":         {Code: "dnsrr_discovery_failed", Category: FindingCategoryAuthority, DefaultSeverity: checkreport.StatusUnknown},
	"dnsrr_no_authoritative_answers": {Code: "dnsrr_no_authoritative_answers", Category: FindingCategoryAuthority, DefaultSeverity: checkreport.StatusUnknown},
	"dnsrr_rrset_inconsistent":       {Code: "dnsrr_rrset_inconsistent", Category: FindingCategoryConsistency, DefaultSeverity: checkreport.StatusWarning},
	"dnsrr_master_missing_soa":       {Code: "dnsrr_master_missing_soa", Category: FindingCategoryAuthority, DefaultSeverity: checkreport.StatusUnknown},
	"dnsrr_master_unresolved":        {Code: "dnsrr_master_unresolved", Category: FindingCategoryAuthority, DefaultSeverity: checkreport.StatusUnknown},
	"dnsrr_dnssec_not_secure":        {Code: "dnsrr_dnssec_not_secure", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusWarning},
	"dnsrr_dnssec_validation_failed": {Code: "dnsrr_dnssec_validation_failed", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusCritical},
	"dnsrr_dnssec_inconclusive":      {Code: "dnsrr_dnssec_inconclusive", Category: FindingCategoryDNSSEC, DefaultSeverity: checkreport.StatusUnknown},
}

var findingRegistry = rulecatalog.New(FindingCatalogToEntries(FindingCatalog), func(status checkreport.Status) string {
	return string(status)
})

func makeFinding(code string, severity checkreport.Status, target, message string) checkreport.Finding {
	spec, ok := FindingCatalog[code]
	if !ok {
		spec = FindingSpec{Code: code, Category: FindingCategoryPresence, DefaultSeverity: severity}
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
