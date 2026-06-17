package checkreport

import "testing"

func TestExitCodeMapping(t *testing.T) {
	cases := []struct {
		status Status
		want   int
	}{
		{StatusOK, 0},
		{StatusWarning, 1},
		{StatusCritical, 2},
		{StatusUnknown, 3},
	}

	for _, tc := range cases {
		report := Report{Status: tc.status}
		if got := report.ExitCode(); got != tc.want {
			t.Fatalf("ExitCode(%q) = %d, want %d", tc.status, got, tc.want)
		}
	}
}

func TestNagiosLabelMapping(t *testing.T) {
	report := Report{Status: StatusWarning}
	if got, want := report.NagiosLabel(), "WARNING"; got != want {
		t.Fatalf("NagiosLabel() = %q, want %q", got, want)
	}
}

func TestEffectiveTargetPrefersPrimaryTarget(t *testing.T) {
	report := Report{
		Target:        "legacy.example",
		PrimaryTarget: "primary.example",
	}
	if got, want := report.EffectiveTarget(), "primary.example"; got != want {
		t.Fatalf("EffectiveTarget() = %q, want %q", got, want)
	}
}

func TestMetricDisplayValueSupportsNumericFallback(t *testing.T) {
	value := 12.5
	metric := Metric{Name: "elapsed_ms", Number: &value}
	if got, want := metric.DisplayValue(), "12.5"; got != want {
		t.Fatalf("DisplayValue() = %q, want %q", got, want)
	}
}

func TestResultSummaryWithPerfdataUsesSharedShape(t *testing.T) {
	report := &Report{
		Status:        StatusWarning,
		Summary:       "something happened",
		PrimaryTarget: "example.com",
	}
	if got, want := ResultSummaryWithPerfdata(report, "metric=1"), "WARNING - something happened (example.com) | metric=1"; got != want {
		t.Fatalf("ResultSummaryWithPerfdata() = %q, want %q", got, want)
	}
}
