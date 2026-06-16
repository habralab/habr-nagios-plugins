package sitemapapp

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/habralab/habr-nagios-plugins/internal/core/clihelp"
	"github.com/habralab/habr-nagios-plugins/internal/core/httpx"
	"github.com/habralab/habr-nagios-plugins/internal/core/probecli"
	"github.com/habralab/habr-nagios-plugins/internal/probe/sitemap"
)

var sitemapRun = sitemap.Run

func Run(programName string, args []string) int {
	binName := probecli.EffectiveProgramName(programName, sitemap.Meta.DefaultBinaryName())
	requestedOutputMode := probecli.DetectOutputMode(args)

	cfg, err := parseFlags(binName, args)
	if err != nil {
		fmt.Print(probecli.RenderEarlyError(sitemap.Meta.Slug, "", requestedOutputMode, err))
		return sitemap.ExitUnknown
	}

	if output, exitCode, handled := probecli.DispatchToggleActions(
		probecli.VersionAction(binName, cfg.ShowVersion, sitemap.ExitOK),
		probecli.ToggleAction{Enabled: cfg.ShowErrorSlugs, Output: probecli.RenderErrorSlugDescriptors(sitemap.CatalogEntries()), ExitCode: sitemap.ExitOK},
		probecli.ToggleAction{Enabled: cfg.ShowHelp, Output: renderHelp(binName), ExitCode: sitemap.ExitOK},
	); handled {
		fmt.Print(output)
		return exitCode
	}

	if cfg.Hostname == "" && cfg.URL == "" && cfg.Entrypoint == "" {
		fmt.Print(probecli.RenderEarlyError(sitemap.Meta.Slug, "", cfg.OutputMode, errors.New("either -H/--hostname, -u/--url or --entrypoint is required")))
		return sitemap.ExitUnknown
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	result, err := sitemapRun(ctx, cfg)
	if err != nil {
		fmt.Print(probecli.RenderEarlyError(sitemap.Meta.Slug, "", cfg.OutputMode, err))
		return sitemap.ExitUnknown
	}

	rendered, exitCode, err := probecli.RenderResult(result, cfg.OutputMode, cfg.Verbosity)
	if err != nil {
		fmt.Printf("UNKNOWN - %v\n", err)
		return sitemap.ExitUnknown
	}
	fmt.Print(rendered)
	return exitCode
}

func parseFlags(binName string, args []string) (sitemap.Config, error) {
	fs, common, err := probecli.NewCommonFlagSet(binName, args)
	if err != nil {
		return sitemap.Config{}, err
	}

	cfg := sitemap.DefaultConfig()
	var fallbackPaths string

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
	fs.StringVar(&fallbackPaths, "fallback-paths", strings.Join(sitemap.DefaultFallbackPaths, ","), "comma-separated fallback paths")
	fs.StringVar(&cfg.FallbackStatus, "fallback-status", string(sitemap.FallbackWarn), "severity when sitemap is resolved only via fallback: ok|warn")
	common.Register(fs, "60s")

	if err := fs.Parse(common.Args()); err != nil {
		return sitemap.Config{}, err
	}

	resolved, err := common.Resolve(sitemap.CatalogHasSlug)
	if err != nil {
		return sitemap.Config{}, err
	}
	cfg.Timeout = resolved.Timeout
	cfg.Verbosity = resolved.Verbosity
	cfg.OutputMode = resolved.OutputMode
	cfg.IgnoreErrors = resolved.IgnoreErrors
	cfg.IgnoreErrorSet = resolved.IgnoreErrorSet
	cfg.ShowHelp = resolved.ShowHelp
	cfg.ShowVersion = resolved.ShowVersion
	cfg.ShowErrorSlugs = resolved.ShowErrorSlugs

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

	return cfg, nil
}

func renderHelp(binName string) string {
	doc := clihelp.Document{
		ProgramName: binName,
		Summary:     sitemap.Meta.Summary,
		Usage: []string{
			binName + " -H example.com [options]",
			binName + " -u https://example.com [options]",
			binName + " --entrypoint https://example.com/sitemap.xml [options]",
		},
	}
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
			Long:        "--output",
			Description: probecli.OutputModeOptionDescription("json emits the structured sitemap waterfall report for external renderers."),
			Examples: []string{
				"--output nagios",
				"--output json",
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
				"This only changes the severity of sitemap_fallback_used.\n" +
				"Use --ignore-errors sitemap_fallback_used to suppress that finding entirely.",
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
		{Short: "-h", Long: "--help", Description: probecli.HelpOptionDescription()},
		{
			Long:        "--ignore-errors",
			Description: probecli.IgnoreErrorsOptionDescription(),
			Examples: []string{
				"--ignore-errors sitemap_fallback_used,sitemap_content_type_unexpected",
			},
		},
		{Long: "--list-error-slugs", Description: probecli.ListErrorSlugsOptionDescription()},
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
		{Short: "-t", Long: "--timeout", Description: probecli.TimeoutOptionDescription("60s"), Examples: []string{"-t 60s", "--timeout 300s"}},
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
		{Short: "-v", Long: "--verbose", Description: probecli.VerboseOptionDescription(), Examples: []string{"-v", "-vv", "-vvv", "--verbose=2"}},
		{Short: "-V", Long: "--version", Description: probecli.VersionOptionDescription()},
	}
	options = append(options, httpx.HelpOptions()...)
	doc.Options = options
	return clihelp.RenderDocument(doc)
}
