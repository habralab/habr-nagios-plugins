package dnschain

import (
	"testing"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
)

func TestFindingCatalogContainsCoreCodes(t *testing.T) {
	for _, code := range []string{
		"dnschain_ds_dnskey_mismatch",
		"dnschain_denial_ttl_unexpected",
		"dnschain_parent_ds_endpoint_failed",
		"dnschain_parent_ds_mixed_state",
		"dnschain_ds_partial_sep_coverage",
		"dnschain_algorithm_not_recommended_in_use",
		"dnschain_algorithm_must_not_in_use",
		"dnschain_digest_not_recommended_in_use",
		"dnschain_digest_must_not_in_use",
		"dnschain_algorithm_not_recommended_published",
		"dnschain_algorithm_must_not_published",
		"dnschain_digest_not_recommended_published",
		"dnschain_digest_must_not_published",
		"dnschain_algorithm_unsupported_published",
		"dnschain_digest_unsupported_published",
		"dnschain_no_secure_entry_point",
		"dnschain_nameserver_endpoint_unreachable",
		"dnschain_nameserver_endpoint_rrset_failed",
		"dnschain_owner_rr_missing",
		"dnschain_owner_rrset_inconsistent",
		"dnschain_root_anchor_mismatch",
		"dnschain_child_soa_inconsistent",
		"dnschain_nsec3param_inconsistent",
		"dnschain_nsec3param_not_recommended",
		"dnschain_nsec3_name_error_invalid",
		"dnschain_nsec3_name_error_unrecognized",
		"dnschain_nsec3_no_data_invalid",
		"dnschain_nsec3_no_data_unrecognized",
		"dnschain_nsec3_wildcard_no_data_invalid",
		"dnschain_parent_ds_inconsistent",
	} {
		if _, ok := FindingCatalog[code]; !ok {
			t.Fatalf("FindingCatalog missing %q", code)
		}
	}
}

func TestMakeFindingUsesCatalogDefaults(t *testing.T) {
	f := makeFinding("dnschain_root_anchor_mismatch", "", ".", "")
	if got, want := f.Severity, checkreport.StatusCritical; got != want {
		t.Fatalf("Severity = %q, want %q", got, want)
	}
	if got, want := f.Message, FindingCatalog["dnschain_root_anchor_mismatch"].DefaultMessage; got != want {
		t.Fatalf("Message = %q, want %q", got, want)
	}
}
