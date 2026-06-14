package dnschain

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
)

type Config struct {
	Hostname       string
	Zone           string
	Timeout        time.Duration
	QueryTimeout   time.Duration
	Verbosity      int
	OutputMode     checkreport.OutputMode
	IgnoreErrors   []string
	IgnoreErrorSet map[string]bool
	ShowErrorSlugs bool
	Analyzer       Analyzer
}

func DefaultConfig() Config {
	return Config{
		Timeout:        30 * time.Second,
		QueryTimeout:   3 * time.Second,
		OutputMode:     checkreport.OutputNagios,
		IgnoreErrorSet: map[string]bool{},
	}
}

type Result struct {
	Config Config
	Report checkreport.Report
}

type Analyzer interface {
	Analyze(ctx context.Context, cfg Config, target string) (checkreport.Report, error)
}

var DefaultAnalyzerFactory = func() Analyzer {
	return placeholderAnalyzer{}
}

func Run(ctx context.Context, cfg Config) (*Result, error) {
	target, err := normalizeTarget(cfg)
	if err != nil {
		return nil, err
	}

	analyzer := cfg.Analyzer
	if analyzer == nil {
		analyzer = DefaultAnalyzerFactory()
	}
	report, err := analyzer.Analyze(ctx, cfg, target)
	if err != nil {
		return nil, err
	}

	return &Result{Config: cfg, Report: report}, nil
}

func normalizeTarget(cfg Config) (string, error) {
	zone := strings.TrimSpace(cfg.Zone)
	host := strings.TrimSpace(cfg.Hostname)

	switch {
	case zone != "":
		return strings.TrimSuffix(zone, "."), nil
	case host != "":
		return strings.TrimSuffix(host, "."), nil
	default:
		return "", fmt.Errorf("either -H/--hostname or --zone is required")
	}
}

func targetSelectionMessage(cfg Config, target string) string {
	switch {
	case strings.TrimSpace(cfg.Zone) != "":
		return fmt.Sprintf("target zone=%q selected from --zone", target)
	default:
		return fmt.Sprintf("target name=%q selected from --hostname", target)
	}
}

type placeholderAnalyzer struct{}

func (placeholderAnalyzer) Analyze(_ context.Context, cfg Config, target string) (checkreport.Report, error) {
	started := time.Now()
	report := checkreport.Report{
		Probe:         Meta.Slug,
		Target:        target,
		PrimaryTarget: target,
		Targets: []checkreport.Target{
			{Role: "input", Value: target},
		},
		Status:       checkreport.StatusUnknown,
		Summary:      "dnschain placeholder analyzer was used instead of the live authoritative engine",
		Partial:      true,
		CoverageNote: "this placeholder path exists only as a fallback for tests or explicit analyzer injection; normal runs should use the live authoritative analyzer",
		StartedAt:    started.UTC(),
		Meta: []checkreport.KV{
			{Key: "output_mode", Value: string(cfg.OutputMode)},
		},
	}

	report.Stages = append(report.Stages,
		checkreport.Stage{
			ID:     "target.selection",
			Title:  "Target Selection",
			Status: checkreport.StatusOK,
			Target: target,
			Checks: []checkreport.Check{
				{
					ID:      "target.input",
					State:   checkreport.CheckPass,
					Subject: target,
					Message: targetSelectionMessage(cfg, target),
				},
			},
		},
		checkreport.Stage{
			ID:     "analysis.plan",
			Title:  "Analysis Plan",
			Status: checkreport.StatusOK,
			Target: target,
			Checks: []checkreport.Check{
				{
					ID:      "plan.root-bootstrap",
					State:   checkreport.CheckPass,
					Subject: ".",
					Message: "the live checker bootstraps from bundled root hints and root trust anchors",
				},
				{
					ID:      "plan.authoritative-walk",
					State:   checkreport.CheckPass,
					Subject: target,
					Message: "the live checker walks parent delegation and queries authoritative servers directly",
				},
				{
					ID:      "plan.dnssec-validation",
					State:   checkreport.CheckPass,
					Subject: target,
					Message: "the live checker validates DS, DNSKEY, RRSIG, and authenticated denial where applicable",
				},
			},
		},
		checkreport.Stage{
			ID:     "engine.status",
			Title:  "Engine Status",
			Status: checkreport.StatusUnknown,
			Target: target,
			Checks: []checkreport.Check{
				{
					ID:      "implementation",
					State:   checkreport.CheckUnknown,
					Subject: target,
					Message: "live authoritative analysis was not wired into this execution path",
					Evidence: []checkreport.Evidence{
						{
							Kind:    "design",
							Summary: "the structured report and renderer contract are in place",
							Attributes: []checkreport.KV{
								{Key: "renderers", Value: "nagios,json"},
								{Key: "waterfall_stages", Value: "yes"},
							},
						},
					},
				},
			},
			Notes: []string{
				"use this placeholder only when tests or callers intentionally inject a non-live analyzer",
			},
		},
	)
	report.Traces = append(report.Traces,
		checkreport.TraceEvent{
			Kind:    "input",
			StageID: "target.selection",
			State:   checkreport.CheckPass,
			Target:  target,
			Message: targetSelectionMessage(cfg, target),
		},
		checkreport.TraceEvent{
			Kind:    "plan",
			StageID: "analysis.plan",
			State:   checkreport.CheckPass,
			Target:  target,
			Message: "this placeholder report summarizes the intended live analysis stages when the live analyzer is not selected",
		},
	)
	report.Findings = append(report.Findings, makeFinding(
		"dnschain_not_implemented",
		checkreport.StatusUnknown,
		target,
		"live authoritative DNS analysis was not selected for this execution path",
	))
	report.Metrics = []checkreport.Metric{
		countMetric("stages", len(report.Stages)),
		countMetric("findings", len(report.Findings)),
	}
	report.DurationMS = time.Since(started).Milliseconds()
	return report, nil
}

func countMetric(name string, n int) checkreport.Metric {
	value := float64(n)
	return checkreport.Metric{
		Name:   name,
		Type:   "count",
		Unit:   "items",
		Value:  fmt.Sprintf("%d", n),
		Number: &value,
	}
}
