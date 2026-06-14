//go:build live

package dnschain

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
)

func TestRunLiveDNSSECCorpus(t *testing.T) {
	tests := []struct {
		name           string
		zone           string
		wantStatus     checkreport.Status
		wantDetailPart string
	}{
		{
			name:           "secure-example-com",
			zone:           "example.com",
			wantStatus:     checkreport.StatusOK,
			wantDetailPart: "validated secure hop com. -> example.com.",
		},
		{
			name:           "insecure-neverssl-com",
			zone:           "neverssl.com",
			wantStatus:     checkreport.StatusOK,
			wantDetailPart: "signed opt-out NSEC3 proof established that neverssl.com. is an insecure delegation without DS",
		},
		{
			name:           "broken-dnssec-failed-org",
			zone:           "dnssec-failed.org",
			wantStatus:     checkreport.StatusCritical,
			wantDetailPart: "dnschain_ds_dnskey_mismatch",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Zone = tc.zone
			cfg.Timeout = 20 * time.Second
			cfg.Verbosity = 1

			result, err := Run(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if got, want := result.Report.Status, tc.wantStatus; got != want {
				t.Fatalf("Report.Status = %q, want %q; detail=%s", got, want, result.Detail())
			}
			if got := result.Detail(); !strings.Contains(got, tc.wantDetailPart) {
				t.Fatalf("Detail() missing %q; detail=%s", tc.wantDetailPart, got)
			}
		})
	}
}
