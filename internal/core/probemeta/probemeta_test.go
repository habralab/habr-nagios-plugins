package probemeta

import "testing"

func TestBinaryNaming(t *testing.T) {
	meta := Metadata{Slug: "example"}

	if got, want := meta.DefaultBinaryName(), "check_example"; got != want {
		t.Fatalf("DefaultBinaryName() = %q, want %q", got, want)
	}
	if got, want := meta.NamespacedBinaryName("habr"), "check_habr_example"; got != want {
		t.Fatalf("NamespacedBinaryName() = %q, want %q", got, want)
	}
	if got, want := meta.PackageName("habr"), "habr-nagios-plugin-example"; got != want {
		t.Fatalf("PackageName() = %q, want %q", got, want)
	}
}
