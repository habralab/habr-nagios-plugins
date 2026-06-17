package probecli

import (
	"fmt"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/core/dnsresolver"
)

func AppendResolverCacheUsageStage(report *checkreport.Report, target string, stats dnsresolver.CacheStats, traces []dnsresolver.CacheTrace) {
	if report == nil {
		return
	}
	report.Stages = append(report.Stages, ResolverCacheUsageStage(target, stats))
	report.Traces = append(report.Traces, ResolverCacheTraceEvents(traces)...)
}

func ResolverCacheUsageStage(target string, stats dnsresolver.CacheStats) checkreport.Stage {
	totalHits := stats.TotalHits()
	totalLookups := stats.TotalLookups()
	hitRatio := stats.HitRatio() * 100
	message := fmt.Sprintf(
		"cache hits=%d (local=%d shared=%d) live_resolutions=%d shared_misses=%d shared_writes=%d hit_ratio=%.1f%% total=%d",
		totalHits,
		stats.LocalHits,
		stats.SharedHits,
		stats.LiveResolutions,
		stats.SharedMisses,
		stats.SharedWrites,
		hitRatio,
		totalLookups,
	)
	state := checkreport.CheckNote
	if totalLookups > 0 || stats.SharedWrites > 0 || stats.SharedMisses > 0 {
		state = checkreport.CheckPass
	}
	return checkreport.Stage{
		ID:     "resolver.cache_usage",
		Title:  "Resolver Cache Usage",
		Status: checkreport.StatusOK,
		Target: target,
		Checks: []checkreport.Check{
			{
				ID:           "resolver.cache_usage.summary",
				State:        state,
				Subject:      target,
				Message:      message,
				MinVerbosity: 1,
				Meta: []checkreport.KV{
					{Key: "local_hits", Value: fmt.Sprintf("%d", stats.LocalHits)},
					{Key: "shared_hits", Value: fmt.Sprintf("%d", stats.SharedHits)},
					{Key: "shared_misses", Value: fmt.Sprintf("%d", stats.SharedMisses)},
					{Key: "live_resolutions", Value: fmt.Sprintf("%d", stats.LiveResolutions)},
					{Key: "shared_writes", Value: fmt.Sprintf("%d", stats.SharedWrites)},
					{Key: "total_hits", Value: fmt.Sprintf("%d", totalHits)},
					{Key: "total", Value: fmt.Sprintf("%d", totalLookups)},
					{Key: "hit_ratio_pct", Value: fmt.Sprintf("%.1f", hitRatio)},
				},
			},
		},
	}
}

func ResolverCacheTraceEvents(traces []dnsresolver.CacheTrace) []checkreport.TraceEvent {
	if len(traces) == 0 {
		return nil
	}
	out := make([]checkreport.TraceEvent, 0, len(traces))
	for _, trace := range traces {
		message := fmt.Sprintf("%s artifact=%s subject=%s", trace.Action, trace.Artifact, trace.Subject)
		if trace.Detail != "" {
			message += " detail=" + trace.Detail
		}
		out = append(out, checkreport.TraceEvent{
			Kind:         "resolver",
			StageID:      "resolver.cache_usage",
			State:        checkreport.CheckNote,
			Target:       trace.Subject,
			Message:      message,
			MinVerbosity: 2,
			Attributes: []checkreport.KV{
				{Key: "action", Value: trace.Action},
				{Key: "artifact", Value: trace.Artifact},
				{Key: "subject", Value: trace.Subject},
				{Key: "detail", Value: trace.Detail},
			},
		})
	}
	return out
}
