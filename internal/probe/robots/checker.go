package robots

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	neturl "net/url"
	"strings"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/core/finding"
	"github.com/habralab/habr-nagios-plugins/internal/core/httpx"
)

const (
	ExitOK       = 0
	ExitWarning  = 1
	ExitCritical = 2
	ExitUnknown  = 3

	maxRobotsBodyBytes    = 500 * 1024
	warnRobotsBodyBytes   = 400 * 1024
	maxRobotsRedirectHops = 5
)

type BehaviorProfile string

const (
	BehaviorProfileRFC         BehaviorProfile = "rfc"
	BehaviorProfileVendorAware BehaviorProfile = "vendor-aware"
	BehaviorProfileStrict      BehaviorProfile = "strict"
)

type Config struct {
	Hostname                string
	URL                     string
	RobotsURL               string
	Strict                  bool
	BehaviorProfile         BehaviorProfile
	OutputMode              checkreport.OutputMode
	Verbosity               int
	Timeout                 time.Duration
	HTTP                    httpx.Options
	HTTPClient              *http.Client
	RequireSitemap          bool
	RequireUserAgents       []string
	RequireDisallows        []string
	ForbidDisallows         []string
	IgnoreErrors            []string
	IgnoreErrorSet          map[string]bool
	ShowHelp                bool
	ShowErrorSlugs          bool
	ShowKnownAgents         bool
	ShowKnownAgentBehaviors bool
	ShowKnownDirectives     bool
	ShowVersion             bool
}

func DefaultConfig() Config {
	return Config{
		BehaviorProfile: BehaviorProfileRFC,
		OutputMode:      checkreport.OutputNagios,
		Verbosity:       0,
		Timeout:         30 * time.Second,
		IgnoreErrorSet:  map[string]bool{},
		HTTP: httpx.Options{
			UserAgent: httpx.DefaultUserAgent(),
		},
	}
}

type Severity = finding.Severity
type Problem = finding.Problem

const (
	SeverityOK       = finding.SeverityOK
	SeverityWarning  = finding.SeverityWarning
	SeverityCritical = finding.SeverityCritical
)

type Group struct {
	UserAgents []string
	Allows     []string
	Disallows  []string
	Extensions []DirectiveObservation
}

type HTTPCall struct {
	Method      string
	URL         string
	StatusCode  int
	FinalURL    string
	HeadersTime time.Duration
	ReadTime    time.Duration
	TotalTime   time.Duration
	Bytes       int
	Note        string
}

type RuleCheck struct {
	Status string
	Name   string
	Target string
	Detail string
}

type PerfStats struct {
	Bytes   int
	Elapsed time.Duration
}

type Result struct {
	Config             Config
	Report             checkreport.Report
	TargetSource       string
	EffectiveBaseURL   string
	EffectiveRobotsURL string
	FinalURL           string
	StatusCode         int
	ContentType        string
	Encoding           string
	RawLines           int
	Groups             []Group
	Sitemaps           []string
	Hosts              []string
	Extensions         []DirectiveObservation
	KnownAgents        []KnownAgentObservation
	Problems           []Problem
	IgnoredProblems    []Problem
	Rules              []RuleCheck
	HTTPTrace          []HTTPCall
	Perf               PerfStats
	Absent             bool
}

func Run(ctx context.Context, cfg Config) (*Result, error) {
	startedAt := time.Now()
	source, baseSite, robotsURL, err := normalizeRobotsURL(cfg)
	if err != nil {
		return nil, err
	}
	if robotsURL == "" {
		return nil, fmt.Errorf("either -H/--hostname, -u/--url or --robots-url is required")
	}

	client := cfg.HTTPClient
	if client == nil {
		client = httpx.NewClient(cfg.Timeout, cfg.HTTP)
	}
	result := &Result{
		Config:             cfg,
		TargetSource:       source,
		EffectiveBaseURL:   baseSite,
		EffectiveRobotsURL: robotsURL,
	}
	client = httpx.CloneWithRedirectPolicy(client, maxRobotsRedirectHops, func(method, fromURL, toURL string, statusCode int) {
		result.HTTPTrace = append(result.HTTPTrace, HTTPCall{
			Method:     method,
			URL:        fromURL,
			FinalURL:   toURL,
			StatusCode: statusCode,
			Note:       "redirect",
		})
	})
	defer func() {
		result.Perf.Elapsed = time.Since(startedAt)
	}()
	result.addRule("PASS", "target.selection", robotsURL, targetSelectionTrace(cfg, baseSite, robotsURL))

	res, err := fetch(ctx, client, cfg, robotsURL, result)
	if err != nil {
		if isDNSResolutionError(err) {
			return nil, fmt.Errorf("DNS resolution failed for %s: %w", robotsURL, err)
		}

		code := "robots_fetch_failed"
		message := err.Error()
		ruleStatus := "FAIL"
		switch {
		case errors.Is(ctx.Err(), context.DeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
			code = "robots_fetch_timeout"
			message = fmt.Sprintf("request timeout after %s", cfg.Timeout)
		case errors.Is(err, ErrRobotsBodyTooLarge):
			code = "robots_too_large"
		case errors.Is(err, httpx.ErrRedirectLoopDetected):
			code = "robots_redirect_loop"
			ruleStatus = "WARN"
		case errors.Is(err, httpx.ErrRedirectLimitExceeded):
			code = "robots_redirect_limit_exceeded"
			ruleStatus = "WARN"
		}
		result.addProblem(makeProblem(cfg, code, robotsURL, message))
		result.addRule(ruleStatus, "robots.fetch", robotsURL, message)
		return result, nil
	}

	result.StatusCode = res.StatusCode
	result.FinalURL = res.FinalURL
	result.ContentType = res.ContentType
	result.Perf.Bytes = res.Bytes

	switch {
	case res.StatusCode == http.StatusNotFound:
		result.Absent = true
		result.addRule("PASS", "robots.absent", result.finalTarget(), "robots.txt not present (HTTP 404)")
		return result, nil
	case res.StatusCode >= http.StatusInternalServerError:
		result.addProblem(makeProblem(cfg, "robots_bad_status", result.finalTarget(), fmt.Sprintf("HTTP %d", res.StatusCode)))
		result.addRule("FAIL", "robots.status", result.finalTarget(), fmt.Sprintf("HTTP %d", res.StatusCode))
		return result, nil
	case res.StatusCode >= http.StatusBadRequest && res.StatusCode < http.StatusInternalServerError:
		result.addProblem(makeProblem(cfg, "robots_unavailable_status", result.finalTarget(), fmt.Sprintf("HTTP %d", res.StatusCode)))
		result.addRule("WARN", "robots.status", result.finalTarget(), fmt.Sprintf("HTTP %d", res.StatusCode))
		return result, nil
	case res.StatusCode != http.StatusOK:
		result.addProblem(makeProblem(cfg, "robots_bad_status", result.finalTarget(), fmt.Sprintf("HTTP %d", res.StatusCode)))
		result.addRule("FAIL", "robots.status", result.finalTarget(), fmt.Sprintf("HTTP %d", res.StatusCode))
		return result, nil
	}

	if res.Bytes > warnRobotsBodyBytes {
		result.addProblem(makeProblem(cfg, "robots_size_near_limit", result.finalTarget(), fmt.Sprintf("robots.txt size %d bytes is close to the 500 KiB parsing limit", res.Bytes)))
		result.addRule("WARN", "robots.size", result.finalTarget(), fmt.Sprintf("size=%d bytes is close to the parsing limit", res.Bytes))
	}

	if message, ok := unexpectedContentTypeMessage(res.ContentType); ok {
		result.addProblem(makeProblem(cfg, "robots_content_type_unexpected", result.finalTarget(), message))
		result.addRule("WARN", "robots.content_type", result.finalTarget(), message)
	} else if res.ContentType != "" {
		result.addRule("PASS", "robots.content_type", result.finalTarget(), normalizeContentType(res.ContentType))
	}

	parsed, problems := parseDocument(cfg, result.finalTarget(), res.Body)
	result.addProblems(problems...)
	result.Groups = parsed.Groups
	result.Sitemaps = parsed.Sitemaps
	result.Hosts = parsed.Hosts
	result.Extensions = parsed.Extensions
	result.KnownAgents = parsed.KnownAgents
	result.RawLines = parsed.RawLines
	result.Encoding = parsed.Encoding

	validatePolicies(cfg, result)
	evaluateAgentBehaviors(cfg, result)

	if len(result.Groups) == 0 {
		result.addProblem(makeProblem(cfg, "robots_no_groups", result.finalTarget(), "no User-agent groups found"))
		result.addRule("WARN", "robots.groups", result.finalTarget(), "no User-agent groups found")
	} else {
		result.addRule("PASS", "robots.groups", result.finalTarget(), fmt.Sprintf("groups=%d", len(result.Groups)))
	}

	if len(result.Problems) == 0 {
		result.addRule("PASS", "robots.parse", result.finalTarget(), fmt.Sprintf("groups=%d sitemaps=%d rules=%d", len(result.Groups), len(result.Sitemaps), result.ruleCount()))
	}

	return result, nil
}

func isDNSResolutionError(err error) bool {
	var urlErr *neturl.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr)
}

func validatePolicies(cfg Config, result *Result) {
	target := result.finalTarget()
	if cfg.RequireSitemap && len(result.Sitemaps) == 0 {
		result.addProblem(makeProblem(cfg, "robots_rule_missing", target, "required Sitemap directive not found"))
		result.addRule("FAIL", "policy.require_sitemap", target, "required Sitemap directive not found")
	}

	agents := map[string]bool{}
	disallows := map[string]bool{}
	for _, group := range result.Groups {
		for _, agent := range group.UserAgents {
			agents[strings.ToLower(strings.TrimSpace(agent))] = true
		}
		for _, rule := range group.Disallows {
			disallows[rule] = true
		}
	}

	for _, required := range cfg.RequireUserAgents {
		key := strings.ToLower(strings.TrimSpace(required))
		if key == "" || agents[key] {
			continue
		}
		result.addProblem(makeProblem(cfg, "robots_rule_missing", target, fmt.Sprintf("required User-agent %q not found", required)))
		result.addRule("FAIL", "policy.require_user_agent", target, fmt.Sprintf("required User-agent %q not found", required))
	}

	for _, required := range cfg.RequireDisallows {
		if required == "" || disallows[required] {
			continue
		}
		result.addProblem(makeProblem(cfg, "robots_rule_missing", target, fmt.Sprintf("required Disallow %q not found", required)))
		result.addRule("FAIL", "policy.require_disallow", target, fmt.Sprintf("required Disallow %q not found", required))
	}

	for _, forbidden := range cfg.ForbidDisallows {
		if forbidden == "" || !disallows[forbidden] {
			continue
		}
		result.addProblem(makeProblem(cfg, "robots_rule_forbidden", target, fmt.Sprintf("forbidden Disallow %q is present", forbidden)))
		result.addRule("FAIL", "policy.forbid_disallow", target, fmt.Sprintf("forbidden Disallow %q is present", forbidden))
	}
}
