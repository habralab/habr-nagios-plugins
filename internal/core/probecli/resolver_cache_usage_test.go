package probecli

import (
	"testing"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/core/dnsresolver"
)

func TestResolverCacheUsageStageIncludesStructuredStats(t *testing.T) {
	t.Parallel()

	stage := ResolverCacheUsageStage("example.com", dnsresolver.CacheStats{
		LocalHits:       2,
		SharedHits:      3,
		SharedMisses:    4,
		LiveResolutions: 5,
		SharedWrites:    6,
	})
	if got, want := stage.ID, "resolver.cache_usage"; got != want {
		t.Fatalf("stage.ID = %q, want %q", got, want)
	}
	if len(stage.Checks) != 1 {
		t.Fatalf("len(stage.Checks) = %d, want 1", len(stage.Checks))
	}
	check := stage.Checks[0]
	for key, want := range map[string]string{
		"local_hits":       "2",
		"shared_hits":      "3",
		"shared_misses":    "4",
		"live_resolutions": "5",
		"shared_writes":    "6",
		"total_hits":       "5",
		"total":            "10",
		"hit_ratio_pct":    "50.0",
	} {
		if got := metaValue(check.Meta, key); got != want {
			t.Fatalf("meta[%s] = %q, want %q", key, got, want)
		}
	}
}

func metaValue(items []checkreport.KV, key string) string {
	for _, item := range items {
		if item.Key == key {
			return item.Value
		}
	}
	return ""
}
