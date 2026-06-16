package finding

import "testing"

func TestSeverityName(t *testing.T) {
	if got, want := SeverityName(SeverityCritical), "CRITICAL"; got != want {
		t.Fatalf("SeverityName(SeverityCritical) = %q, want %q", got, want)
	}
	if got, want := SeverityName(SeverityWarning), "WARNING"; got != want {
		t.Fatalf("SeverityName(SeverityWarning) = %q, want %q", got, want)
	}
	if got, want := SeverityName(SeverityOK), "OK"; got != want {
		t.Fatalf("SeverityName(SeverityOK) = %q, want %q", got, want)
	}
}
