package checkreport

import "testing"

func TestNewRuleCheckAndDisplayState(t *testing.T) {
	check := NewRuleCheck(7, "warn", "document.parse", "https://example.test/sitemap.xml", "unexpected content type")

	if got, want := check.State, CheckWarning; got != want {
		t.Fatalf("State = %q, want %q", got, want)
	}
	if got, want := CheckDisplayState(check), "WARN"; got != want {
		t.Fatalf("CheckDisplayState() = %q, want %q", got, want)
	}
	if got, want := MetaValue(check.Meta, "kind", ""), "rule"; got != want {
		t.Fatalf("kind = %q, want %q", got, want)
	}
	if got, want := MetaValue(check.Meta, "order", ""), "000007"; got != want {
		t.Fatalf("order = %q, want %q", got, want)
	}
}

func TestChecksByMetaOrdersByMetaOrder(t *testing.T) {
	report := Report{
		Stages: []Stage{
			{
				ID: "one",
				Checks: []Check{
					NewRuleCheck(2, "PASS", "late", "b", "second"),
					{ID: "plain", State: CheckPass, Message: "no meta"},
				},
			},
			{
				ID: "two",
				Checks: []Check{
					NewRuleCheck(1, "FAIL", "early", "a", "first"),
				},
			},
		},
	}

	checks := ChecksByMeta(report.Stages, "kind", "rule")
	if got, want := len(checks), 2; got != want {
		t.Fatalf("len(ChecksByMeta()) = %d, want %d", got, want)
	}
	if got, want := checks[0].ID, "early"; got != want {
		t.Fatalf("checks[0].ID = %q, want %q", got, want)
	}
	if got, want := checks[1].ID, "late"; got != want {
		t.Fatalf("checks[1].ID = %q, want %q", got, want)
	}
}

func TestCountMetricAndUintMetric(t *testing.T) {
	count := CountMetric("findings", 3)
	if got, want := count.DisplayValue(), "3"; got != want {
		t.Fatalf("CountMetric().DisplayValue() = %q, want %q", got, want)
	}

	uintCount := UintMetric("heap_alloc_peak", 42)
	if got, want := uintCount.DisplayValue(), "42"; got != want {
		t.Fatalf("UintMetric().DisplayValue() = %q, want %q", got, want)
	}
}

func TestEmptyAsDash(t *testing.T) {
	if got, want := EmptyAsDash(""), "-"; got != want {
		t.Fatalf("EmptyAsDash(\"\") = %q, want %q", got, want)
	}
	if got, want := EmptyAsDash("value"), "value"; got != want {
		t.Fatalf("EmptyAsDash(\"value\") = %q, want %q", got, want)
	}
}

func TestSectionTitle(t *testing.T) {
	if got, want := SectionTitle("target"), "Target"; got != want {
		t.Fatalf("SectionTitle(target) = %q, want %q", got, want)
	}
	if got, want := SectionTitle("suppressed_findings"), "Suppressed Findings"; got != want {
		t.Fatalf("SectionTitle(suppressed_findings) = %q, want %q", got, want)
	}
}
