package robots

import (
	"strings"
	"testing"

	"github.com/habralab/habr-nagios-plugins/internal/core/msgcatalog"
)

func TestCatalogCategory(t *testing.T) {
	category, ok := CatalogCategory("robots_fetch_timeout")
	if !ok {
		t.Fatal("CatalogCategory() ok = false, want true")
	}
	if got, want := category, "transport"; got != want {
		t.Fatalf("CatalogCategory() = %q, want %q", got, want)
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
		if !strings.HasPrefix(slug, "robots_") {
			t.Fatalf("slug %q does not use robots_ prefix", slug)
		}
	}
}
