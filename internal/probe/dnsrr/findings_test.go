package dnsrr

import (
	"strings"
	"testing"

	"github.com/habralab/habr-nagios-plugins/internal/core/msgcatalog"
)

func TestFindingCatalogMessagesExist(t *testing.T) {
	for slug := range FindingCatalog {
		if _, ok := msgcatalog.DefaultSummary(msgcatalog.Key(slug)); !ok {
			t.Fatalf("missing catalog message for %s", slug)
		}
	}
}

func TestFindingCatalogSlugPrefixes(t *testing.T) {
	for slug := range FindingCatalog {
		if !strings.HasPrefix(slug, "dnsrr_") {
			t.Fatalf("slug %q does not use dnsrr_ prefix", slug)
		}
	}
}
