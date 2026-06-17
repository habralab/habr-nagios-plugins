package sitemap

import (
	"strings"
	"testing"
)

func TestSummaryIncludesPrimaryTarget(t *testing.T) {
	result := &Result{
		Config: Config{
			OutputMode: DefaultConfig().OutputMode,
		},
		TargetSource:     "hostname",
		EffectiveBaseURL: "https://example.com/",
		Entrypoints:      []string{"https://example.com/sitemap.xml"},
	}

	summary := result.Summary()
	if !strings.Contains(summary, "(https://example.com/sitemap.xml) |") {
		t.Fatalf("Summary() = %q, want shared target-bearing summary format", summary)
	}
}
