package sitemapapp

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/habralab/habr-nagios-plugins/internal/core/buildinfo"
	"github.com/habralab/habr-nagios-plugins/internal/core/clihelp"
	"github.com/habralab/habr-nagios-plugins/internal/core/httpx"
	"github.com/habralab/habr-nagios-plugins/internal/core/probecli"
	"github.com/habralab/habr-nagios-plugins/internal/core/verbosity"
	"github.com/habralab/habr-nagios-plugins/internal/probe/sitemap"
)

func Run(programName string, args []string) int {
	binName := probecli.EffectiveProgramName(programName, sitemap.Meta.DefaultBinaryName())

	cfg, err := parseFlags(binName, args)
	if err != nil {
		fmt.Printf("UNKNOWN - %v\n", err)
		return sitemap.ExitUnknown
	}

	if cfg.ShowVersion {
		fmt.Println(buildinfo.String(binName))
		return sitemap.ExitOK
	}

	if cfg.ShowErrorSlugs {
		for _, slug := range sitemap.CatalogSlugs() {
			fmt.Println(slug)
		}
		return sitemap.ExitOK
	}

	if cfg.ShowHelp {
		printHelp(binName)
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

func parseFlags(binName string, args []string) (sitemap.Config, error) {
	normalizedArgs, baseVerbosity, err := verbosity.NormalizeArgs(args)
	if err != nil {
		return sitemap.Config{}, err
	}

	fs := flag.NewFlagSet(binName, flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	cfg := sitemap.DefaultConfig()
	var timeout string
	var fallbackPaths string
	var ignoreErrors string
	var verbosityFlag int

	fs.StringVar(&cfg.Hostname, "H", "", "hostname used for discovery, e.g. example.com")
	fs.StringVar(&cfg.Hostname, "hostname", "", "hostname used for discovery, e.g. example.com")
	fs.StringVar(&cfg.URL, "u", "", "full base URL used for discovery, e.g. https://example.com")
	fs.StringVar(&cfg.URL, "url", "", "full base URL used for discovery, e.g. https://example.com")
	fs.StringVar(&cfg.Entrypoint, "entrypoint", "", "explicit sitemap entrypoint URL")
	fs.StringVar(&cfg.RobotsURL, "robots-url", "", "override robots.txt URL")
	fs.BoolVar(&cfg.Strict, "strict", false, "enforce stricter host/path expectations")
	fs.BoolVar(&cfg.FallbackProbe, "fallback", true, "probe default sitemap locations when robots.txt has no sitemap")
	fs.BoolVar(&cfg.AllowCrossHost, "allow-cross-host", false, "allow child sitemap URLs on hosts different from the parent sitemap host")
	fs.IntVar(&cfg.MaxDepth, "max-depth", 0, "maximum sitemap tree depth, 0 disables the limit")
	fs.IntVar(&cfg.MaxFiles, "max-files", 0, "maximum number of sitemap documents to fetch, 0 disables the limit")
	fs.IntVar(&cfg.MaxURLs, "max-urls", 0, "maximum number of url entries to parse across the tree, 0 disables the limit")
	fs.StringVar(&cfg.HTTP.UserAgent, "user-agent", httpx.DefaultUserAgent(), "HTTP User-Agent")
	fs.BoolVar(&cfg.HTTP.InsecureSkipVerify, "insecure-skip-verify", false, "disable TLS certificate verification for HTTP requests")
	fs.StringVar(&timeout, "t", "60s", "overall timeout")
	fs.StringVar(&timeout, "timeout", "60s", "overall timeout")
	fs.StringVar(&fallbackPaths, "fallback-paths", strings.Join(sitemap.DefaultFallbackPaths, ","), "comma-separated fallback paths")
	fs.StringVar(&cfg.FallbackStatus, "fallback-status", string(sitemap.FallbackWarn), "severity when sitemap is resolved only via fallback: ok|warn")
	fs.StringVar(&ignoreErrors, "ignore-errors", "", "comma-separated error slugs to suppress")
	fs.IntVar(&verbosityFlag, "v", 0, "verbosity level 0..3")
	fs.IntVar(&verbosityFlag, "verbose", 0, "verbosity level 0..3")
	fs.BoolVar(&cfg.ShowHelp, "h", false, "show help")
	fs.BoolVar(&cfg.ShowHelp, "help", false, "show help")
	fs.BoolVar(&cfg.ShowErrorSlugs, "list-error-slugs", false, "list suppressible error slugs and exit")
	fs.BoolVar(&cfg.ShowVersion, "V", false, "show version")
	fs.BoolVar(&cfg.ShowVersion, "version", false, "show version")

	if err := fs.Parse(normalizedArgs); err != nil {
		return sitemap.Config{}, err
	}

	d, err := probecli.ParseTimeout(timeout, "--timeout")
	if err != nil {
		return sitemap.Config{}, err
	}
	cfg.Timeout = d
	cfg.Verbosity = verbosity.Clamp(baseVerbosity + verbosityFlag)

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

	cfg.IgnoreErrors, cfg.IgnoreErrorSet, err = probecli.BuildIgnoreErrorSet(ignoreErrors, sitemap.CatalogHasSlug)
	if err != nil {
		return sitemap.Config{}, err
	}

	return cfg, nil
}

func printHelp(binName string) {
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
		{Long: "--max-depth", Description: "Maximum sitemap tree depth before traversal stops.\nUse 0 to disable the limit.", Examples: []string{"--max-depth 0", "--max-depth 8"}},
		{Long: "--max-files", Description: "Maximum number of sitemap documents to fetch.\nUse 0 to disable the limit.", Examples: []string{"--max-files 0", "--max-files 500"}},
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
		{Short: "-t", Long: "--timeout", Description: "Overall check timeout.\nDefault: 60s.", Examples: []string{"-t 60s", "--timeout 300s"}},
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
