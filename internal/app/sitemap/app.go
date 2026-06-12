package sitemapapp

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/buildinfo"
	"github.com/habralab/habr-nagios-plugins/internal/core/clihelp"
	"github.com/habralab/habr-nagios-plugins/internal/core/httpx"
	"github.com/habralab/habr-nagios-plugins/internal/probe/sitemap"
)

func Run(args []string) int {
	cfg, err := parseFlags(args)
	if err != nil {
		fmt.Printf("UNKNOWN - %v\n", err)
		return sitemap.ExitUnknown
	}

	if cfg.ShowVersion {
		fmt.Println(buildinfo.String(sitemap.Meta.DefaultBinaryName()))
		return sitemap.ExitOK
	}

	if cfg.ShowErrorSlugs {
		for _, slug := range sitemap.CatalogSlugs() {
			fmt.Println(slug)
		}
		return sitemap.ExitOK
	}

	if cfg.ShowHelp {
		printHelp()
		return sitemap.ExitOK
	}

	if cfg.Hostname == "" && cfg.URL == "" && cfg.Entrypoint == "" {
		fmt.Println("UNKNOWN - either -H/--hostname, -u/--url or --entrypoint is required")
		return sitemap.ExitUnknown
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	result, err := sitemap.Run(ctx, cfg)
	if err != nil {
		fmt.Printf("UNKNOWN - %v\n", err)
		return sitemap.ExitUnknown
	}

	if cfg.Verbosity > 0 {
		fmt.Print(result.Detail())
	} else {
		fmt.Println(result.Summary())
	}

	return result.ExitCode()
}

func parseFlags(args []string) (sitemap.Config, error) {
	normalizedArgs, baseVerbosity, err := normalizeVerbosityArgs(args)
	if err != nil {
		return sitemap.Config{}, err
	}

	fs := flag.NewFlagSet(sitemap.Meta.DefaultBinaryName(), flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	cfg := sitemap.DefaultConfig()
	var timeout string
	var fallbackPaths string
	var ignoreErrors string
	var verbosity int

	fs.StringVar(&cfg.Hostname, "H", "", "hostname used for discovery, e.g. example.com")
	fs.StringVar(&cfg.Hostname, "hostname", "", "hostname used for discovery, e.g. example.com")
	fs.StringVar(&cfg.URL, "u", "", "full base URL used for discovery, e.g. https://example.com")
	fs.StringVar(&cfg.URL, "url", "", "full base URL used for discovery, e.g. https://example.com")
	fs.StringVar(&cfg.Entrypoint, "entrypoint", "", "explicit sitemap entrypoint URL")
	fs.StringVar(&cfg.RobotsURL, "robots-url", "", "override robots.txt URL")
	fs.BoolVar(&cfg.Strict, "strict", false, "enforce stricter host/path expectations")
	fs.BoolVar(&cfg.FallbackProbe, "fallback", true, "probe default sitemap locations when robots.txt has no sitemap")
	fs.BoolVar(&cfg.AllowCrossHost, "allow-cross-host", false, "allow child sitemap URLs on hosts different from the parent sitemap host")
	fs.IntVar(&cfg.MaxDepth, "max-depth", 8, "maximum sitemap tree depth")
	fs.IntVar(&cfg.MaxFiles, "max-files", 500, "maximum number of sitemap documents to fetch")
	fs.IntVar(&cfg.MaxURLs, "max-urls", 0, "maximum number of url entries to parse across the tree, 0 disables the limit")
	fs.StringVar(&cfg.HTTP.UserAgent, "user-agent", sitemap.DefaultUserAgent, "HTTP User-Agent")
	fs.BoolVar(&cfg.HTTP.InsecureSkipVerify, "insecure-skip-verify", false, "disable TLS certificate verification for HTTP requests")
	fs.StringVar(&timeout, "t", "10s", "overall timeout")
	fs.StringVar(&timeout, "timeout", "10s", "overall timeout")
	fs.StringVar(&fallbackPaths, "fallback-paths", strings.Join(sitemap.DefaultFallbackPaths, ","), "comma-separated fallback paths")
	fs.StringVar(&cfg.FallbackStatus, "fallback-status", string(sitemap.FallbackWarn), "severity when sitemap is resolved only via fallback: ok|warn")
	fs.StringVar(&ignoreErrors, "ignore-errors", "", "comma-separated error slugs to suppress")
	fs.IntVar(&verbosity, "v", 0, "verbosity level 0..3")
	fs.IntVar(&verbosity, "verbose", 0, "verbosity level 0..3")
	fs.BoolVar(&cfg.ShowHelp, "h", false, "show help")
	fs.BoolVar(&cfg.ShowHelp, "help", false, "show help")
	fs.BoolVar(&cfg.ShowErrorSlugs, "list-error-slugs", false, "list suppressible error slugs and exit")
	fs.BoolVar(&cfg.ShowVersion, "V", false, "show version")
	fs.BoolVar(&cfg.ShowVersion, "version", false, "show version")

	if err := fs.Parse(normalizedArgs); err != nil {
		return sitemap.Config{}, err
	}

	d, err := time.ParseDuration(timeout)
	if err != nil {
		return sitemap.Config{}, fmt.Errorf("invalid --timeout: %w", err)
	}
	cfg.Timeout = d
	cfg.Verbosity = clampVerbosity(baseVerbosity + verbosity)

	cfg.FallbackPaths = nil
	for _, item := range strings.Split(fallbackPaths, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if !strings.HasPrefix(item, "/") {
			return sitemap.Config{}, errors.New("fallback paths must start with /")
		}
		cfg.FallbackPaths = append(cfg.FallbackPaths, item)
	}

	switch sitemap.FallbackSeverity(cfg.FallbackStatus) {
	case sitemap.FallbackOK, sitemap.FallbackWarn:
	default:
		return sitemap.Config{}, errors.New("fallback-status must be one of: ok, warn")
	}

	cfg.IgnoreErrorSet = map[string]bool{}
	for _, item := range strings.Split(ignoreErrors, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if !sitemap.CatalogHasSlug(item) {
			return sitemap.Config{}, fmt.Errorf("unknown ignored error slug %q", item)
		}
		cfg.IgnoreErrors = append(cfg.IgnoreErrors, item)
		cfg.IgnoreErrorSet[item] = true
	}

	return cfg, nil
}

func normalizeVerbosityArgs(args []string) ([]string, int, error) {
	out := make([]string, 0, len(args))
	verbosity := 0

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-v":
			verbosity++
		case arg == "-vv":
			verbosity += 2
		case arg == "-vvv":
			verbosity += 3
		case arg == "--verbose":
			if i+1 < len(args) && isInteger(args[i+1]) {
				n, _ := strconv.Atoi(args[i+1])
				verbosity += n
				i++
				continue
			}
			verbosity++
		case strings.HasPrefix(arg, "--verbose="):
			raw := strings.TrimPrefix(arg, "--verbose=")
			n, err := strconv.Atoi(raw)
			if err != nil {
				return nil, 0, fmt.Errorf("invalid --verbose value %q", raw)
			}
			verbosity += n
		default:
			out = append(out, arg)
		}
	}

	return out, verbosity, nil
}

func isInteger(s string) bool {
	if s == "" {
		return false
	}
	_, err := strconv.Atoi(s)
	return err == nil
}

func clampVerbosity(v int) int {
	if v < 0 {
		return 0
	}
	if v > 3 {
		return 3
	}
	return v
}

func printHelp() {
	binName := sitemap.Meta.DefaultBinaryName()
	options := []clihelp.Option{
		{
			Long: "--allow-cross-host",
			Description: "Allow child sitemap URLs on hosts different from the parent sitemap host.\n" +
				"Default: disabled.",
		},
		{
			Long:        "--entrypoint",
			Description: "Use an explicit sitemap URL and skip automatic entrypoint discovery.",
			Examples: []string{
				"--entrypoint https://example.com/sitemap.xml",
				"--entrypoint https://example.com/sitemap.xml.gz",
			},
		},
		{
			Long: "--fallback",
			Description: "Probe common sitemap paths when robots.txt has no Sitemap directive.\n" +
				"Default: enabled.",
		},
		{
			Long:        "--fallback-paths",
			Description: "Override the comma-separated fallback path list used after robots.txt discovery fails.",
			Examples: []string{
				"--fallback-paths /sitemap.xml,/sitemap_index.xml,/sitemap.xml.gz",
			},
		},
		{
			Long: "--fallback-status",
			Description: "Severity to use when sitemap discovery succeeds only through fallback probing.\n" +
				"Accepted values: ok, warn.\n" +
				"This only changes the severity of fallback_used.\n" +
				"Use --ignore-errors fallback_used to suppress that finding entirely.",
			Examples: []string{
				"--fallback-status warn",
				"--fallback-status ok",
			},
		},
		{
			Short: "-H",
			Long:  "--hostname",
			Description: "Hostname used for discovery.\n" +
				"Default scheme for hostname-based discovery is https.",
			Examples: []string{
				"-H example.com",
				"-H docs.example.net",
			},
		},
		{Short: "-h", Long: "--help", Description: "Show help"},
		{
			Long: "--ignore-errors",
			Description: "Comma-separated finding slugs to suppress from status aggregation.\n" +
				"Use --list-error-slugs to see the available values.",
			Examples: []string{
				"--ignore-errors fallback_used,content_type_unexpected",
			},
		},
		{Long: "--list-error-slugs", Description: "Print the available suppressible error slugs and exit."},
		{Long: "--max-depth", Description: "Maximum sitemap tree depth before traversal stops.", Examples: []string{"--max-depth 8"}},
		{Long: "--max-files", Description: "Maximum number of sitemap documents to fetch.", Examples: []string{"--max-files 500"}},
		{Long: "--max-urls", Description: "Maximum number of URL entries to parse across the whole tree.\nUse 0 to disable the limit.", Examples: []string{"--max-urls 0", "--max-urls 200000"}},
		{
			Long:        "--robots-url",
			Description: "Override the robots.txt URL used for sitemap discovery.",
			Examples: []string{
				"--robots-url https://example.com/robots.txt",
			},
		},
		{Long: "--strict", Description: "Enforce stricter host and path expectations for child sitemap validation.\n" +
			"Escalate selected scope validation findings from warning to critical."},
		{Short: "-t", Long: "--timeout", Description: "Overall check timeout.", Examples: []string{"-t 10s", "--timeout 30s"}},
		{
			Short: "-u",
			Long:  "--url",
			Description: "Full base URL used for discovery.\n" +
				"When both --url and --hostname are provided, --url wins.",
			Examples: []string{
				"-u https://example.com",
				"-u http://docs.example.net",
			},
		},
		{Short: "-v", Long: "--verbose", Description: "Increase output detail.\nRepeat up to 3 times for deeper diagnostics.", Examples: []string{"-v", "-vv", "-vvv", "--verbose=2"}},
		{Short: "-V", Long: "--version", Description: "Show version and build metadata"},
	}
	options = append(options, httpx.HelpOptions()...)

	fmt.Printf(`%s

%s

Usage:
  %s -H example.com [options]
  %s -u https://example.com [options]
  %s --entrypoint https://example.com/sitemap.xml [options]

Options:
%s`, binName, sitemap.Meta.Summary, binName, binName, binName, clihelp.RenderOptions(options))
}
