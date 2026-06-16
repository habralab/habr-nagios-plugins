package msgcatalog

import "testing"

func TestCatalogRender(t *testing.T) {
	catalog := New("en", map[Key]Message{
		"finding.transport_connect_failed": {
			Summary: "Connection to the target service failed",
			Detail:  "Connection to {{ target }} failed: {{ error }}",
		},
	})

	rendered, ok := catalog.Render("finding.transport_connect_failed", VariantDetail, Params{
		"target": "example.com:443",
		"error":  "timeout",
	})
	if !ok {
		t.Fatal("Render() ok = false, want true")
	}
	if got, want := rendered, "Connection to example.com:443 failed: timeout"; got != want {
		t.Fatalf("Render() = %q, want %q", got, want)
	}
}

func TestCatalogRenderMissingKey(t *testing.T) {
	catalog := New("en", nil)
	rendered, ok := catalog.Render("missing", VariantSummary, nil)
	if ok {
		t.Fatal("Render() ok = true, want false")
	}
	if rendered != "" {
		t.Fatalf("Render() = %q, want empty string", rendered)
	}
}

func TestMessageTemplateVariantSelection(t *testing.T) {
	message := Message{
		Title:   "Title",
		Summary: "Summary",
		Detail:  "Detail",
		Hint:    "Hint",
	}

	if got, want := message.Template(VariantTitle), "Title"; got != want {
		t.Fatalf("Template(VariantTitle) = %q, want %q", got, want)
	}
	if got, want := message.Template(VariantDetail), "Detail"; got != want {
		t.Fatalf("Template(VariantDetail) = %q, want %q", got, want)
	}
	if got, want := message.Template(VariantHint), "Hint"; got != want {
		t.Fatalf("Template(VariantHint) = %q, want %q", got, want)
	}
	if got, want := message.Template(VariantSummary), "Summary"; got != want {
		t.Fatalf("Template(VariantSummary) = %q, want %q", got, want)
	}
}

func TestRenderTemplateSupportsCompactAndSpacedPlaceholders(t *testing.T) {
	params := Params{
		"code":   "connect_failed",
		"target": "example.com",
	}
	template := "{{code}} on {{ target }}"
	if got, want := RenderTemplate(template, params), "connect_failed on example.com"; got != want {
		t.Fatalf("RenderTemplate() = %q, want %q", got, want)
	}
}

func TestMergeRejectsDuplicateKeys(t *testing.T) {
	_, err := Merge("en",
		Source{Name: "one", AllowedPrefixes: []string{"probe_"}, Items: map[Key]Message{"probe_key": {Summary: "a"}}},
		Source{Name: "two", AllowedPrefixes: []string{"probe_"}, Items: map[Key]Message{"probe_key": {Summary: "b"}}},
	)
	if err == nil {
		t.Fatal("Merge() error = nil, want duplicate-key error")
	}
}

func TestMergeRejectsUnexpectedPrefix(t *testing.T) {
	_, err := Merge("en",
		Source{Name: "sitemap", AllowedPrefixes: []string{"sitemap_"}, Items: map[Key]Message{"fetch_failed": {Summary: "bad"}}},
	)
	if err == nil {
		t.Fatal("Merge() error = nil, want prefix-validation error")
	}
}
