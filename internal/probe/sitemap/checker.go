package sitemap

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"slices"
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

	maxSitemapFileBytes = 52_428_800
	maxSitemapEntries   = 50_000
)

var DefaultFallbackPaths = []string{
	"/sitemap.xml",
	"/sitemap_index.xml",
	"/sitemap.txt",
	"/sitemap.xml.gz",
}

type FallbackSeverity string

const (
	FallbackOK   FallbackSeverity = "ok"
	FallbackWarn FallbackSeverity = "warn"
)

type Config struct {
	Hostname       string
	URL            string
	Entrypoint     string
	RobotsURL      string
	OutputMode     checkreport.OutputMode
	Strict         bool
	FallbackProbe  bool
	Verbosity      int
	FallbackStatus string
	AllowCrossHost bool
	MaxDepth       int
	MaxFiles       int
	MaxURLs        int
	HTTP           httpx.Options
	Timeout        time.Duration
	HTTPClient     *http.Client
	FallbackPaths  []string
	IgnoreErrors   []string
	IgnoreErrorSet map[string]bool
	ShowHelp       bool
	ShowErrorSlugs bool
	ShowVersion    bool
}

func DefaultConfig() Config {
	return Config{
		FallbackProbe:  true,
		OutputMode:     checkreport.OutputNagios,
		Verbosity:      0,
		FallbackStatus: string(FallbackWarn),
		MaxDepth:       0,
		MaxFiles:       0,
		MaxURLs:        0,
		HTTP: httpx.Options{
			UserAgent: httpx.DefaultUserAgent(),
		},
		Timeout:        60 * time.Second,
		FallbackPaths:  slices.Clone(DefaultFallbackPaths),
		IgnoreErrorSet: map[string]bool{},
	}
}

type Severity = finding.Severity
type Problem = finding.Problem

const (
	SeverityOK       = finding.SeverityOK
	SeverityWarning  = finding.SeverityWarning
	SeverityCritical = finding.SeverityCritical
)

type Result struct {
	Config           Config
	Report           checkreport.Report
	Entrypoints      []string
	Documents        []DocumentResult
	Problems         []Problem
	IgnoredProblems  []Problem
	Rules            []RuleCheck
	DiscoveryTrace   []string
	HTTPTrace        []HTTPCall
	DiscoveredVia    string
	TargetSource     string
	EffectiveBaseURL string
	CrossHostTrust   map[string]bool // map["host:port"]verified
	CrossHostChecks  map[string]crossHostCheck
	MaxObservedDepth int
	TotalURLs        int
	Perf             PerfStats
}

type crossHostCheck struct {
	Trusted bool
	Robots  string
	Err     string
}

type DocumentResult struct {
	URL        string
	Kind       string
	StatusCode int
	Depth      int
	Entries    int
	Children   int
	Encoding   string
	Compressed bool
}

type RuleCheck struct {
	Status string
	Name   string
	Target string
	Detail string
}

type PerfStats struct {
	TotalNetBytes int
	TotalRawBytes int
	Elapsed       time.Duration
	PeakHeapAlloc uint64
	PeakHeapSys   uint64
}

type PayloadStats struct {
	Compressed bool
	NetBytes   int
	RawBytes   int
}

type HTTPCall struct {
	Method      string
	URL         string
	StatusCode  int
	FinalURL    string
	HeadersTime time.Duration
	ReadTime    time.Duration
	ParseTime   time.Duration
	TotalTime   time.Duration
	Payload     PayloadStats
	Note        string
}

type queueItem struct {
	URL    string
	Depth  int
	Parent string
}

type robotsDiscovery struct {
	RequestedURL string
	FinalURL     string
	Sitemaps     []string
}

type fetchResult struct {
	StatusCode  int
	Body        []byte
	ContentType string
	HeadersTime time.Duration
	ReadTime    time.Duration
	FinalURL    string
	Payload     PayloadStats
}

type countingReader struct {
	io.Reader
	N int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.Reader.Read(p)
	c.N += n
	return n, err
}

type parsedSitemap struct {
	Kind       string
	URLCount   int
	URLs       []string
	Children   []string
	Extensions []ExtensionObservation
	Encoding   string
	Compressed bool
}

type ExtensionObservation struct {
	ID           string
	NamespaceURI string
	Count        int
	IssueCount   int
}

func Run(ctx context.Context, cfg Config) (*Result, error) {
	startedAt := time.Now()
	baseSite, err := normalizeBaseSite(cfg)
	if err != nil {
		return nil, err
	}

	if cfg.MaxDepth < 0 || cfg.MaxFiles < 0 || cfg.MaxURLs < 0 {
		return nil, fmt.Errorf("max-depth, max-files, and max-urls must be non-negative")
	}

	client := cfg.HTTPClient
	if client == nil {
		client = httpx.NewClient(cfg.Timeout, cfg.HTTP)
	}
	result := &Result{
		Config:          cfg,
		CrossHostTrust:  map[string]bool{},
		CrossHostChecks: map[string]crossHostCheck{},
	}
	defer func() {
		result.Perf.Elapsed = time.Since(startedAt)
		result.updateRuntimeStats()
	}()
	if baseSite != "" {
		result.trustHost(baseSite)
	}
	client = httpx.CloneWithRedirectPolicy(client, httpx.DefaultMaxRedirects, func(method, fromURL, toURL string, statusCode int) {
		result.HTTPTrace = append(result.HTTPTrace, HTTPCall{
			Method:     method,
			URL:        fromURL,
			FinalURL:   toURL,
			StatusCode: statusCode,
			Note:       "redirect",
		})
	})
	result.TargetSource = targetSource(cfg)
	result.EffectiveBaseURL = baseSite
	result.updateRuntimeStats()

	result.addTrace("input hostname=%q url=%q entrypoint=%q timeout=%s strict=%t fallback=%t", cfg.Hostname, cfg.URL, cfg.Entrypoint, cfg.Timeout, cfg.Strict, cfg.FallbackProbe)
	if cfg.HTTP.InsecureSkipVerify {
		result.addTrace("tls verification disabled by --insecure-skip-verify")
		result.addRule("WARN", "tls.verify", baseSiteOrHostname(baseSite, cfg.Hostname), "TLS certificate verification disabled by flag")
	}
	result.addTrace("%s", targetSelectionTrace(cfg, baseSite))

	entrypoints, via, discoveryProblems := discoverEntrypoints(ctx, client, cfg, baseSite, result)
	result.addProblems(discoveryProblems...)
	result.Entrypoints = entrypoints
	result.DiscoveredVia = via
	result.addTrace("resolved entrypoints via=%s count=%d", via, len(entrypoints))

	if len(entrypoints) == 0 {
		result.addRule("FAIL", "entrypoint.discovery", baseSiteOrHostname(baseSite, cfg.Hostname), "no sitemap entrypoint discovered")
		result.addProblem(makeProblem(cfg, "entrypoint_not_found", baseSiteOrHostname(baseSite, cfg.Hostname), ""))
		return result, nil
	}

	visited := map[string]bool{}
	queued := map[string]bool{}
	parents := map[string]string{}
	queue := make([]queueItem, 0, len(entrypoints))
	for _, ep := range entrypoints {
		if queued[ep] {
			continue
		}
		result.trustHost(ep)
		queue = append(queue, queueItem{URL: ep, Depth: 0})
		queued[ep] = true
		parents[ep] = ""
	}

	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			if !hasProblemCode(result.Problems, "fetch_timeout") && !hasProblemCode(result.Problems, "check_timeout") {
				result.addRule("FAIL", "check.timeout", baseSiteOrHostname(baseSite, cfg.Hostname), fmt.Sprintf("timeout after %s", cfg.Timeout))
				result.addProblem(makeProblem(cfg, "check_timeout", baseSiteOrHostname(baseSite, cfg.Hostname), fmt.Sprintf("check timeout after %s", cfg.Timeout)))
			}
			break
		}

		item := queue[0]
		queue = queue[1:]

		if visited[item.URL] {
			continue
		}
		visited[item.URL] = true

		if cfg.MaxFiles > 0 && len(result.Documents) >= cfg.MaxFiles {
			result.addRule("FAIL", "limit.max_files", item.URL, fmt.Sprintf("reached max sitemap files limit %d", cfg.MaxFiles))
			result.addProblem(makeProblem(cfg, "max_files_exceeded", item.URL, fmt.Sprintf("reached max sitemap files limit %d", cfg.MaxFiles)))
			break
		}
		if cfg.MaxDepth > 0 && item.Depth > cfg.MaxDepth {
			result.addRule("FAIL", "limit.max_depth", item.URL, fmt.Sprintf("sitemap depth exceeds limit %d", cfg.MaxDepth))
			result.addProblem(makeProblem(cfg, "max_depth_exceeded", item.URL, fmt.Sprintf("sitemap depth exceeds limit %d", cfg.MaxDepth)))
			continue
		}

		doc, problems, children, urlCount := inspectDocument(ctx, client, cfg, baseSite, item, result)
		result.Documents = append(result.Documents, doc)
		result.addProblems(problems...)
		result.TotalURLs += urlCount
		if item.Depth > result.MaxObservedDepth {
			result.MaxObservedDepth = item.Depth
		}
		result.updateRuntimeStats()

		if cfg.MaxURLs > 0 && result.TotalURLs > cfg.MaxURLs {
			result.addRule("FAIL", "limit.max_urls", item.URL, fmt.Sprintf("parsed URL count exceeds limit %d", cfg.MaxURLs))
			result.addProblem(makeProblem(cfg, "max_urls_exceeded", item.URL, fmt.Sprintf("parsed URL count exceeds limit %d", cfg.MaxURLs)))
			break
		}

		for _, child := range children {
			if createsCycle(item.URL, child, parents) {
				result.addProblem(makeProblem(cfg, "cycle_detected", child, fmt.Sprintf("child sitemap %q points back into the current sitemap chain", child)))
				result.addRule("WARN", "tree.cycle", child, "cyclic sitemap reference detected")
				continue
			}
			if queued[child] || visited[child] {
				result.addProblem(makeProblem(cfg, "duplicate_child", child, ""))
				result.addRule("WARN", "tree.duplicate_child", child, "duplicate child sitemap reference")
				continue
			}
			queue = append(queue, queueItem{URL: child, Depth: item.Depth + 1, Parent: item.URL})
			queued[child] = true
			parents[child] = item.URL
		}
	}

	if len(result.Problems) == 0 {
		result.addRule("PASS", "sitemap.tree", baseSiteOrHostname(baseSite, cfg.Hostname), "tree fetched and parsed successfully")
	}

	return result, nil
}
