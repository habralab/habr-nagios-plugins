package rulecatalog

import "testing"

func TestRegistryEntriesAreSortedAndStructured(t *testing.T) {
	registry := New(map[string]Entry[int]{
		"b": {Slug: "b", Category: "beta", Severity: 2, Message: "second"},
		"a": {Slug: "a", Category: "alpha", Severity: 1, Message: "first"},
	}, func(v int) string {
		if v == 1 {
			return "WARNING"
		}
		return "CRITICAL"
	})

	entries := registry.Entries()
	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2", len(entries))
	}
	if got, want := entries[0].Slug, "a"; got != want {
		t.Fatalf("entries[0].Slug = %q, want %q", got, want)
	}
	if got, want := entries[0].Severity, "WARNING"; got != want {
		t.Fatalf("entries[0].Severity = %q, want %q", got, want)
	}
	if got, want := entries[1].Slug, "b"; got != want {
		t.Fatalf("entries[1].Slug = %q, want %q", got, want)
	}

	entry, ok := registry.Lookup("b")
	if !ok {
		t.Fatal("Lookup() ok = false, want true")
	}
	if got, want := entry.Category, "beta"; got != want {
		t.Fatalf("Lookup().Category = %q, want %q", got, want)
	}
}
