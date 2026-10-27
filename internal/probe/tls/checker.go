package tlsprobe

import (
	"context"
	"fmt"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/core/ipfamily"
	"github.com/habralab/habr-nagios-plugins/internal/core/pkix"
	"github.com/habralab/habr-nagios-plugins/internal/core/probecli"
	"github.com/habralab/habr-nagios-plugins/internal/core/tlsx"
)

type Config struct {
	Hostname                 string
	Port                     int
	Transport                tlsx.Transport
	STARTTLS                 tlsx.STARTTLSProfile
	ExpectALPN               []string
	Timeout                  time.Duration
	DNSTimeout               time.Duration
	HandshakeTimeout         time.Duration
	CacheBackend             string
	TransportFamilyPolicy    ipfamily.Policy
	WarnExpiryDays           int
	Verbosity                int
	OutputMode               checkreport.OutputMode
	IgnoreErrors             []string
	IgnoreErrorSet           map[string]bool
	ShowHelp                 bool
	ShowVersion              bool
	ShowErrorSlugs           bool
	CAFile                   string
	CAPath                   string
	PolicyUntrustedRoot      pkix.UntrustedRootPolicy
	PolicyDualStack          pkix.DualStackPolicy
	OCSPMode                 pkix.OCSPMode
	IgnoreExpiredAlternative bool
	Analyzer                 Analyzer
}

func DefaultConfig() Config {
	return Config{
		Port:                  443,
		Transport:             tlsx.TransportTCP,
		Timeout:               30 * time.Second,
		DNSTimeout:            5 * time.Second,
		HandshakeTimeout:      5 * time.Second,
		TransportFamilyPolicy: ipfamily.PolicyAuto,
		WarnExpiryDays:        30,
		OutputMode:            checkreport.OutputNagios,
		PolicyUntrustedRoot:   pkix.UntrustedRootCritical,
		PolicyDualStack:       pkix.DualStackDegraded,
		OCSPMode:              pkix.OCSPStapled,
		IgnoreErrorSet:        map[string]bool{},
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
	return liveAnalyzer{}
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

func (r *Result) ProbeReport() *checkreport.Report {
	return &r.Report
}

func normalizeTarget(cfg Config) (string, error) {
	target, err := probecli.ResolveServiceTargetInput(probecli.ServiceTargetInput{
		Hostname: cfg.Hostname,
		Port:     cfg.Port,
	})
	if err != nil {
		return "", err
	}
	return target.Hostname, nil
}

type placeholderAnalyzer struct{}

func (placeholderAnalyzer) Analyze(_ context.Context, cfg Config, target string) (checkreport.Report, error) {
	started := time.Now()
	serviceTarget := fmt.Sprintf("%s:%d", target, cfg.Port)
	report := checkreport.Report{
		Probe:         Meta.Slug,
		Target:        serviceTarget,
		PrimaryTarget: serviceTarget,
		Targets: []checkreport.Target{
			{Role: "hostname", Value: target},
			{Role: "service", Value: serviceTarget},
			{Role: "transport", Value: string(cfg.Transport)},
		},
		Status:       checkreport.StatusUnknown,
		Summary:      "requested TLS execution path is not implemented in this phase",
		Partial:      true,
		CoverageNote: "direct TCP TLS and SMTP/IMAP STARTTLS paths are implemented; QUIC, deeper PKI graph handling, and richer revocation and cipher policy checks remain outside this fallback path",
		StartedAt:    started.UTC(),
		Meta: []checkreport.KV{
			{Key: "output_mode", Value: string(cfg.OutputMode)},
			{Key: "policy_untrusted_root", Value: string(cfg.PolicyUntrustedRoot)},
			{Key: "policy_dual_stack", Value: string(cfg.PolicyDualStack)},
		},
	}
	if cfg.STARTTLS != tlsx.STARTTLSNone {
		report.Targets = append(report.Targets, checkreport.Target{Role: "starttls", Value: string(cfg.STARTTLS)})
	}

	report.Stages = []checkreport.Stage{
		{
			ID:     "target.selection",
			Title:  "Target Selection",
			Status: checkreport.StatusOK,
			Target: serviceTarget,
			Checks: []checkreport.Check{
				{
					ID:      "target.hostname",
					State:   checkreport.CheckPass,
					Subject: target,
					Message: fmt.Sprintf("target hostname %q with service port %d selected", target, cfg.Port),
					Meta: []checkreport.KV{
						{Key: "transport", Value: string(cfg.Transport)},
					},
				},
			},
		},
		{
			ID:     "transport.plan",
			Title:  "Transport Plan",
			Status: checkreport.StatusOK,
			Target: serviceTarget,
			Checks: []checkreport.Check{
				{
					ID:      "transport.primary",
					State:   checkreport.CheckPass,
					Subject: string(cfg.Transport),
					Message: "direct TLS handshakes will be attempted for modern and deprecated protocol probes",
				},
				{
					ID:      "transport.starttls",
					State:   checkreport.CheckNote,
					Subject: string(cfg.STARTTLS),
					Message: starttlsPlanMessage(cfg.STARTTLS),
				},
			},
		},
		{
			ID:     "dns.plan",
			Title:  "DNS Layer Plan",
			Status: checkreport.StatusOK,
			Target: target,
			Checks: []checkreport.Check{
				{
					ID:      "dns.caa",
					State:   checkreport.CheckPass,
					Subject: target,
					Message: "CAA policy lookup is part of the intended live analyzer",
				},
				{
					ID:      "dns.dane",
					State:   checkreport.CheckPass,
					Subject: fmt.Sprintf("_%d._tcp.%s", cfg.Port, target),
					Message: "DANE TLSA lookup and DNSSEC-backed validation are planned through shared DNSSEC helpers",
				},
			},
		},
		{
			ID:     "pki.plan",
			Title:  "PKI Graph Plan",
			Status: checkreport.StatusOK,
			Target: serviceTarget,
			Checks: []checkreport.Check{
				{
					ID:      "pki.chain_graph",
					State:   checkreport.CheckPass,
					Subject: serviceTarget,
					Message: "the live analyzer will build a certificate path graph rather than trusting a single linear chain",
				},
				{
					ID:      "pki.policy",
					State:   checkreport.CheckPass,
					Subject: string(cfg.PolicyDualStack),
					Message: fmt.Sprintf("dual-stack branch policy=%s, untrusted-root policy=%s", cfg.PolicyDualStack, cfg.PolicyUntrustedRoot),
				},
			},
		},
		{
			ID:     "engine.status",
			Title:  "Engine Status",
			Status: checkreport.StatusUnknown,
			Target: serviceTarget,
			Checks: []checkreport.Check{
				{
					ID:      "implementation",
					State:   checkreport.CheckUnknown,
					Subject: serviceTarget,
					Message: "the requested TLS transport or execution mode is not implemented in this phase",
					Evidence: []checkreport.Evidence{
						{
							Kind:    "design",
							Summary: "the report contract is present, but this execution mode falls back to the placeholder analyzer",
							Attributes: []checkreport.KV{
								{Key: "renderers", Value: "nagios,json"},
								{Key: "timeout_default", Value: cfg.Timeout.String()},
								{Key: "dns_timeout", Value: cfg.DNSTimeout.String()},
								{Key: "handshake_timeout", Value: cfg.HandshakeTimeout.String()},
							},
						},
					},
				},
			},
		},
	}
	report.Traces = []checkreport.TraceEvent{
		{
			Kind:    "input",
			StageID: "target.selection",
			State:   checkreport.CheckPass,
			Target:  serviceTarget,
			Message: fmt.Sprintf("check_tls scaffold selected %s over %s", serviceTarget, cfg.Transport),
		},
	}
	report.Findings = append(report.Findings, makeFinding(
		"tls_not_implemented",
		checkreport.StatusUnknown,
		serviceTarget,
		"the requested TLS transport or execution mode is not implemented in this phase",
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

func starttlsPlanMessage(profile tlsx.STARTTLSProfile) string {
	if profile == tlsx.STARTTLSNone {
		return "no STARTTLS pre-flight profile was requested"
	}
	return fmt.Sprintf("a %s STARTTLS pre-flight will precede the TLS handshake in the live analyzer", profile)
}
