package tlsprobe

import (
	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/core/msgcatalog"
	"github.com/habralab/habr-nagios-plugins/internal/core/probecli"
	"github.com/habralab/habr-nagios-plugins/internal/core/rulecatalog"
)

type FindingCategory string

const (
	FindingCategoryTransport   FindingCategory = "transport"
	FindingCategoryProtocol    FindingCategory = "tls_protocol"
	FindingCategoryCipher      FindingCategory = "tls_cipher"
	FindingCategoryPKIChain    FindingCategory = "pki_chain"
	FindingCategoryPKIIdentity FindingCategory = "pki_identity"
	FindingCategoryRevocation  FindingCategory = "revocation"
	FindingCategoryCT          FindingCategory = "ct"
	FindingCategoryDNS         FindingCategory = "dns"
	FindingCategoryDANE        FindingCategory = "dane"
	FindingCategoryPolicy      FindingCategory = "policy"
)

type FindingSpec struct {
	Code            string
	Category        FindingCategory
	DefaultSeverity checkreport.Status
}

var FindingCatalog = map[string]FindingSpec{
	"tls_not_implemented":                {Code: "tls_not_implemented", Category: FindingCategoryPolicy, DefaultSeverity: checkreport.StatusUnknown},
	"tls_connect_failed":                 {Code: "tls_connect_failed", Category: FindingCategoryTransport, DefaultSeverity: checkreport.StatusCritical},
	"tls_handshake_timeout":              {Code: "tls_handshake_timeout", Category: FindingCategoryTransport, DefaultSeverity: checkreport.StatusCritical},
	"tls_protocol_deprecated_supported":  {Code: "tls_protocol_deprecated_supported", Category: FindingCategoryProtocol, DefaultSeverity: checkreport.StatusCritical},
	"tls_cipher_weak_supported":          {Code: "tls_cipher_weak_supported", Category: FindingCategoryCipher, DefaultSeverity: checkreport.StatusWarning},
	"tls_alpn_unexpected":                {Code: "tls_alpn_unexpected", Category: FindingCategoryProtocol, DefaultSeverity: checkreport.StatusWarning},
	"tls_sni_profile_differs":            {Code: "tls_sni_profile_differs", Category: FindingCategoryProtocol, DefaultSeverity: checkreport.StatusWarning},
	"tls_endpoint_failed":                {Code: "tls_endpoint_failed", Category: FindingCategoryTransport, DefaultSeverity: checkreport.StatusWarning},
	"tls_address_semantics_partial":      {Code: "tls_address_semantics_partial", Category: FindingCategoryPolicy, DefaultSeverity: checkreport.StatusWarning},
	"tls_endpoint_pki_differs":           {Code: "tls_endpoint_pki_differs", Category: FindingCategoryPKIChain, DefaultSeverity: checkreport.StatusWarning},
	"tls_endpoint_ocsp_differs":          {Code: "tls_endpoint_ocsp_differs", Category: FindingCategoryRevocation, DefaultSeverity: checkreport.StatusWarning},
	"tls_endpoint_ct_differs":            {Code: "tls_endpoint_ct_differs", Category: FindingCategoryCT, DefaultSeverity: checkreport.StatusWarning},
	"tls_endpoint_dane_differs":          {Code: "tls_endpoint_dane_differs", Category: FindingCategoryDANE, DefaultSeverity: checkreport.StatusWarning},
	"tls_endpoint_transport_differs":     {Code: "tls_endpoint_transport_differs", Category: FindingCategoryProtocol, DefaultSeverity: checkreport.StatusWarning},
	"tls_endpoint_sni_differs":           {Code: "tls_endpoint_sni_differs", Category: FindingCategoryProtocol, DefaultSeverity: checkreport.StatusWarning},
	"tls_chain_incomplete":               {Code: "tls_chain_incomplete", Category: FindingCategoryPKIChain, DefaultSeverity: checkreport.StatusCritical},
	"tls_chain_invalid":                  {Code: "tls_chain_invalid", Category: FindingCategoryPKIChain, DefaultSeverity: checkreport.StatusCritical},
	"tls_chain_untrusted":                {Code: "tls_chain_untrusted", Category: FindingCategoryPKIChain, DefaultSeverity: checkreport.StatusCritical},
	"tls_hostname_mismatch":              {Code: "tls_hostname_mismatch", Category: FindingCategoryPKIIdentity, DefaultSeverity: checkreport.StatusCritical},
	"tls_cert_expired":                   {Code: "tls_cert_expired", Category: FindingCategoryPKIIdentity, DefaultSeverity: checkreport.StatusCritical},
	"tls_cert_not_yet_valid":             {Code: "tls_cert_not_yet_valid", Category: FindingCategoryPKIIdentity, DefaultSeverity: checkreport.StatusCritical},
	"tls_cert_expiry_soon":               {Code: "tls_cert_expiry_soon", Category: FindingCategoryPKIIdentity, DefaultSeverity: checkreport.StatusWarning},
	"tls_public_key_weak":                {Code: "tls_public_key_weak", Category: FindingCategoryPKIIdentity, DefaultSeverity: checkreport.StatusWarning},
	"tls_curve_legacy":                   {Code: "tls_curve_legacy", Category: FindingCategoryPKIIdentity, DefaultSeverity: checkreport.StatusWarning},
	"tls_ocsp_stapling_invalid":          {Code: "tls_ocsp_stapling_invalid", Category: FindingCategoryRevocation, DefaultSeverity: checkreport.StatusWarning},
	"tls_ocsp_stapling_revoked":          {Code: "tls_ocsp_stapling_revoked", Category: FindingCategoryRevocation, DefaultSeverity: checkreport.StatusCritical},
	"tls_ocsp_lookup_failed":             {Code: "tls_ocsp_lookup_failed", Category: FindingCategoryRevocation, DefaultSeverity: checkreport.StatusWarning},
	"tls_ocsp_response_invalid":          {Code: "tls_ocsp_response_invalid", Category: FindingCategoryRevocation, DefaultSeverity: checkreport.StatusWarning},
	"tls_ocsp_response_revoked":          {Code: "tls_ocsp_response_revoked", Category: FindingCategoryRevocation, DefaultSeverity: checkreport.StatusCritical},
	"tls_ocsp_staple_responder_mismatch": {Code: "tls_ocsp_staple_responder_mismatch", Category: FindingCategoryRevocation, DefaultSeverity: checkreport.StatusWarning},
	"tls_sct_missing":                    {Code: "tls_sct_missing", Category: FindingCategoryCT, DefaultSeverity: checkreport.StatusWarning},
	"tls_caa_forbidden":                  {Code: "tls_caa_forbidden", Category: FindingCategoryDNS, DefaultSeverity: checkreport.StatusWarning},
	"tls_caa_lookup_failed":              {Code: "tls_caa_lookup_failed", Category: FindingCategoryDNS, DefaultSeverity: checkreport.StatusUnknown},
	"tls_caa_dnssec_invalid":             {Code: "tls_caa_dnssec_invalid", Category: FindingCategoryDNS, DefaultSeverity: checkreport.StatusWarning},
	"tls_dane_lookup_failed":             {Code: "tls_dane_lookup_failed", Category: FindingCategoryDANE, DefaultSeverity: checkreport.StatusUnknown},
	"tls_dane_dnssec_invalid":            {Code: "tls_dane_dnssec_invalid", Category: FindingCategoryDANE, DefaultSeverity: checkreport.StatusCritical},
	"tls_dane_mismatch":                  {Code: "tls_dane_mismatch", Category: FindingCategoryDANE, DefaultSeverity: checkreport.StatusCritical},
	"tls_untrusted_root_policy_degraded": {Code: "tls_untrusted_root_policy_degraded", Category: FindingCategoryPolicy, DefaultSeverity: checkreport.StatusWarning},
	"tls_dual_stack_branch_degraded":     {Code: "tls_dual_stack_branch_degraded", Category: FindingCategoryPolicy, DefaultSeverity: checkreport.StatusWarning},
	"tls_expired_alternative_ignored":    {Code: "tls_expired_alternative_ignored", Category: FindingCategoryPolicy, DefaultSeverity: checkreport.StatusWarning},
}

var findingRegistry = rulecatalog.New(FindingCatalogToEntries(FindingCatalog), func(status checkreport.Status) string {
	return string(status)
})

func makeFinding(code string, severity checkreport.Status, target, message string) checkreport.Finding {
	spec, ok := FindingCatalog[code]
	if !ok {
		spec = FindingSpec{
			Code:            code,
			Category:        FindingCategoryPolicy,
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
