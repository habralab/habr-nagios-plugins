package checkreport

import "testing"

func TestPartitionSuppressedFindings(t *testing.T) {
	findings := []Finding{
		{Code: "a", Severity: StatusWarning, Message: "a"},
		{Code: "b", Severity: StatusCritical, Message: "b"},
	}

	active, suppressed := PartitionSuppressedFindings(findings, map[string]bool{"a": true})
	if got, want := len(active), 1; got != want {
		t.Fatalf("active len = %d, want %d", got, want)
	}
	if got, want := len(suppressed), 1; got != want {
		t.Fatalf("suppressed len = %d, want %d", got, want)
	}
	if !suppressed[0].Suppressed {
		t.Fatalf("suppressed[0].Suppressed = false, want true")
	}
	if got, want := active[0].Code, "b"; got != want {
		t.Fatalf("active[0].Code = %q, want %q", got, want)
	}
}
