package finding

import "testing"

func TestCatalogEntriesExposeStructuredMetadata(t *testing.T) {
	entries := CatalogEntries()
	if len(entries) == 0 {
		t.Fatal("CatalogEntries() returned no entries")
	}
	found := false
	for _, entry := range entries {
		if entry.Slug != "robots_fetch_timeout" {
			continue
		}
		found = true
		if entry.Category != "transport" {
			t.Fatalf("Category = %q, want transport", entry.Category)
		}
		if entry.Severity != "CRITICAL" {
			t.Fatalf("Severity = %q, want CRITICAL", entry.Severity)
		}
		if entry.Message == "" {
			t.Fatal("Message is empty")
		}
	}
	if !found {
		t.Fatal("robots_fetch_timeout not found in CatalogEntries()")
	}
}
