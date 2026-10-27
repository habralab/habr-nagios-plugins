package dnsrr

import (
	"context"
	"strings"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/core/dnsprobe"
	"github.com/habralab/habr-nagios-plugins/internal/core/ipfamily"
	"github.com/habralab/habr-nagios-plugins/internal/core/probecli"
)

type Config struct {
	Hostname              string
	Zone                  string
	Owner                 string
	RRType                string
	ExpectValue           string
	ContainsValue         string
	RegexValue            string
	Mode                  dnsprobe.PresenceMode
	DNSSECMode            dnsprobe.DNSSECMode
	Timeout               time.Duration
	QueryTimeout          time.Duration
	TransportFamilyPolicy ipfamily.Policy
	CacheBackend          string
	Verbosity             int
	OutputMode            checkreport.OutputMode
	IgnoreErrors          []string
	IgnoreErrorSet        map[string]bool
	ShowHelp              bool
	ShowVersion           bool
	ShowErrorSlugs        bool
	Analyzer              Analyzer
}

type Result struct {
	Config Config
	Report checkreport.Report
}

type Analyzer interface {
	Analyze(context.Context, Config, Target) (checkreport.Report, error)
}

type Target struct {
	Input     string
	Zone      string
	Owner     string
	RRType    uint16
	RRTypeRaw string
	Matcher   *dnsprobe.RRValueMatcher
	Mode      dnsprobe.PresenceMode
}

var DefaultAnalyzerFactory = func() Analyzer {
	return liveAnalyzer{}
}

func DefaultConfig() Config {
	return Config{
		Mode:                  dnsprobe.PresenceAny,
		DNSSECMode:            dnsprobe.DNSSECPrefer,
		Timeout:               30 * time.Second,
		QueryTimeout:          3 * time.Second,
		TransportFamilyPolicy: ipfamily.PolicyAuto,
		OutputMode:            checkreport.OutputNagios,
		IgnoreErrorSet:        map[string]bool{},
	}
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

func normalizeTarget(cfg Config) (Target, error) {
	resolved, err := probecli.ResolveDNSTargetInput(probecli.DNSTargetInput{
		Hostname:      cfg.Hostname,
		Zone:          cfg.Zone,
		Owner:         cfg.Owner,
		RRType:        cfg.RRType,
		RequireRRType: true,
	})
	if err != nil {
		return Target{}, err
	}
	matcher, err := buildMatcher(cfg)
	if err != nil {
		return Target{}, err
	}
	return Target{
		Input:     resolved.Input,
		Zone:      resolved.Zone,
		Owner:     resolved.Owner,
		RRType:    resolved.RRType,
		RRTypeRaw: resolved.RRTypeRaw,
		Matcher:   matcher,
		Mode:      cfg.Mode,
	}, nil
}

func buildMatcher(cfg Config) (*dnsprobe.RRValueMatcher, error) {
	count := 0
	if strings.TrimSpace(cfg.ExpectValue) != "" {
		count++
	}
	if strings.TrimSpace(cfg.ContainsValue) != "" {
		count++
	}
	if strings.TrimSpace(cfg.RegexValue) != "" {
		count++
	}
	if count == 0 {
		return nil, nil
	}
	if count > 1 {
		return nil, probecli.ErrInputConstraint(probecli.InputRefRRType, "value matching accepts only one of --expect-value, --contains, or --regex")
	}
	if strings.TrimSpace(cfg.ExpectValue) != "" {
		m := dnsprobe.NewExactRRValueMatcher(cfg.ExpectValue)
		return &m, nil
	}
	if strings.TrimSpace(cfg.ContainsValue) != "" {
		m := dnsprobe.NewContainsRRValueMatcher(cfg.ContainsValue)
		return &m, nil
	}
	m, err := dnsprobe.NewRegexRRValueMatcher(cfg.RegexValue)
	if err != nil {
		return nil, probecli.ErrInvalidInput(probecli.InputRefRRType, err)
	}
	return &m, nil
}

func (r *Result) ExitCode() int {
	return r.Report.ExitCode()
}

func (r *Result) Summary() string {
	return checkreport.DefaultResultSummary(&r.Report)
}

func (r *Result) Detail() string {
	return checkreport.DefaultResultDetail(&r.Report, r.Config.Verbosity)
}

func (r *Result) JSON() ([]byte, error) {
	return checkreport.DefaultResultJSON(&r.Report)
}

func (r *Result) ProbeReport() *checkreport.Report {
	return &r.Report
}
