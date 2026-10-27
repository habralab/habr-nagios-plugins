package tlsprobe

import (
	"strings"
	"testing"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/core/msgcatalog"
)

func TestMakeFindingUsesCatalogDefaults(t *testing.T) {
	f := makeFinding("tls_chain_incomplete", "", "example.com", "")
	if got, want := f.Severity, checkreport.StatusCritical; got != want {
		t.Fatalf("Severity = %q, want %q", got, want)
	}
	if got, want := f.Message, "server did not provide a complete certificate chain"; got != want {
		t.Fatalf("Message = %q, want %q", got, want)
	}
}

func TestFindingCatalogMessagesCovered(t *testing.T) {
	for slug := range FindingCatalog {
		if _, ok := msgcatalog.DefaultSummary(msgcatalog.Key(slug)); !ok {
			t.Fatalf("missing default summary for %q", slug)
		}
	}
}

func TestFindingCatalogSlugPrefixes(t *testing.T) {
	for slug := range FindingCatalog {
		if !strings.HasPrefix(slug, "tls_") {
			t.Fatalf("slug %q does not use tls_ prefix", slug)
		}
	}
}
