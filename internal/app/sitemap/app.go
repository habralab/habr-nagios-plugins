package sitemapapp

import (
	"strings"
	"time"

	"fmt"
	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/core/httpx"
	"github.com/habralab/habr-nagios-plugins/internal/core/probecli"
	"github.com/habralab/habr-nagios-plugins/internal/probe/sitemap"
)

var sitemapRun = sitemap.Run

func Run(programName string, args []string) int {
	return probecli.RunApp(probecli.AppSpec[sitemap.Config, *sitemap.Result]{
		ProgramName:       programName,
		Args:              args,
		Probe:             sitemap.Meta.Slug,
		DefaultBinaryName: sitemap.Meta.DefaultBinaryName(),
		Parse:             parseFlags,
		BuildToggles: func(binName string, cfg sitemap.Config) []probecli.ToggleAction {
			return []probecli.ToggleAction{
				probecli.VersionAction(binName, cfg.ShowVersion, sitemap.ExitOK),
				{Enabled: cfg.ShowErrorSlugs, Output: probecli.RenderErrorSlugDescriptors(sitemap.CatalogEntries()), ExitCode: sitemap.ExitOK},
				{Enabled: cfg.ShowHelp, Output: renderHelp(binName), ExitCode: sitemap.ExitOK},
			}
		},
		Timeout:         func(cfg sitemap.Config) time.Duration { return cfg.Timeout },
		Run:             sitemapRun,
		UnknownExitCode: sitemap.ExitUnknown,
		OutputMode:      func(cfg sitemap.Config) checkreport.OutputMode { return cfg.OutputMode },
		Verbosity:       func(cfg sitemap.Config) int { return cfg.Verbosity },
	})
}

func parseFlags(binName string, args []string) (sitemap.Config, error) {
	parser, err := probecli.NewParser(binName, args)
	if err != nil {
		return sitemap.Config{}, err
	}

	cfg := sitemap.DefaultConfig()
	parser.RegisterCommon("60s")
	specs := sitemapInputSpecs(cfg)
	err = parser.RegisterInputs(specs...)
	if err != nil {
		return sitemap.Config{}, err
	}

	resolved, inputs, err := parser.Parse(sitemap.CatalogHasSlug, nil)
	if err != nil {
		return sitemap.Config{}, err
	}
	cfg.Hostname = inputs.String("hostname")
	cfg.URL = inputs.String("url")
	cfg.Entrypoint = inputs.String("entrypoint")
	cfg.RobotsURL = inputs.String("robots_url")
	cfg.Strict = inputs.Bool("strict")
	cfg.FallbackProbe = inputs.Bool("fallback")
	cfg.AllowCrossHost = inputs.Bool("allow_cross_host")
	cfg.MaxDepth = inputs.Int("max_depth")
	cfg.MaxFiles = inputs.Int("max_files")
	cfg.MaxURLs = inputs.Int("max_urls")
	cfg.HTTP.UserAgent = inputs.String("user_agent")
	cfg.HTTP.InsecureSkipVerify = inputs.Bool("insecure_skip_verify")
	cfg.Timeout = resolved.Timeout
	cfg.Verbosity = resolved.Verbosity
	cfg.OutputMode = resolved.OutputMode
	cfg.IgnoreErrors = resolved.IgnoreErrors
	cfg.IgnoreErrorSet = resolved.IgnoreErrorSet
	cfg.ShowHelp = resolved.ShowHelp
	cfg.ShowVersion = resolved.ShowVersion
	cfg.ShowErrorSlugs = resolved.ShowErrorSlugs
	if !cfg.ShowHelp && !cfg.ShowVersion && !cfg.ShowErrorSlugs {
		if err := validateInputs(inputs); err != nil {
			return sitemap.Config{}, err
		}
	}
	cfg.FallbackStatus = inputs.String("fallback_status")
	cfg.FallbackPaths = nil
	for _, item := range probecli.DecodeCSVInput(inputs, "fallback_paths") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if !strings.HasPrefix(item, "/") {
			return sitemap.Config{}, probecli.ErrInputConstraint(probecli.InputRefFallbackPaths, "must start with /")
		}
		cfg.FallbackPaths = append(cfg.FallbackPaths, item)
	}

	fallbackStatus, err := probecli.DecodeEnumInput(
		inputs,
		"fallback_status",
		probecli.InputRefFallback,
		[]string{"ok", "warn"},
		func(raw string) (sitemap.FallbackSeverity, error) {
			switch value := sitemap.FallbackSeverity(strings.ToLower(strings.TrimSpace(raw))); value {
			case sitemap.FallbackOK, sitemap.FallbackWarn:
				return value, nil
			default:
				return "", fmt.Errorf("invalid fallback status")
			}
		},
	)
	if err != nil {
		return sitemap.Config{}, err
	}
	cfg.FallbackStatus = string(fallbackStatus)

	return cfg, nil
}

func sitemapInputSpecs(cfg sitemap.Config) []probecli.InputSpec {
	return []probecli.InputSpec{
		probecli.InputSpec{
			Key:  "hostname",
			Type: probecli.InputString,
			Aliases: []probecli.InputAlias{
				{Short: "H", Usage: "hostname used for discovery, e.g. example.com"},
				{Long: "hostname", Usage: "hostname used for discovery, e.g. example.com"},
			},
			Description: "Hostname used for discovery.\nDefault scheme for hostname-based discovery is https.",
			Examples:    []string{"-H example.com", "-H docs.example.net"},
		},
		probecli.InputSpec{
			Key:         "url",
			Type:        probecli.InputString,
			Aliases:     []probecli.InputAlias{{Short: "u", Usage: "full base URL used for discovery, e.g. https://example.com"}, {Long: "url", Usage: "full base URL used for discovery, e.g. https://example.com"}},
			Description: "Full base URL used for discovery.\nWhen both --url and --hostname are provided, --url wins.",
			Examples:    []string{"-u https://example.com", "-u http://docs.example.net"},
		},
		probecli.InputSpec{
			Key:         "entrypoint",
			Type:        probecli.InputString,
			Aliases:     []probecli.InputAlias{{Long: "entrypoint", Usage: "explicit sitemap entrypoint URL"}},
			Description: "Use an explicit sitemap URL and skip automatic entrypoint discovery.",
			Examples:    []string{"--entrypoint https://example.com/sitemap.xml", "--entrypoint https://example.com/sitemap.xml.gz"},
		},
		probecli.InputSpec{
			Key:         "robots_url",
			Type:        probecli.InputString,
			Aliases:     []probecli.InputAlias{{Long: "robots-url", Usage: "override robots.txt URL"}},
			Description: "Override the robots.txt URL used for sitemap discovery.",
			Examples:    []string{"--robots-url https://example.com/robots.txt"},
		},
		probecli.InputSpec{
			Key:         "strict",
			Type:        probecli.InputBool,
			Aliases:     []probecli.InputAlias{{Long: "strict", Usage: "enforce stricter host/path expectations"}},
			Description: "Enforce stricter host and path expectations for child sitemap validation.\nEscalate selected scope validation findings from warning to critical.",
		},
		probecli.InputSpec{
			Key:         "fallback",
			Type:        probecli.InputBool,
			Default:     "true",
			Aliases:     []probecli.InputAlias{{Long: "fallback", Usage: "probe default sitemap locations when robots.txt has no sitemap"}},
			Description: "Probe common sitemap paths when robots.txt has no Sitemap directive.\nDefault: enabled.",
		},
		probecli.InputSpec{
			Key:         "allow_cross_host",
			Type:        probecli.InputBool,
			Aliases:     []probecli.InputAlias{{Long: "allow-cross-host", Usage: "allow child sitemap URLs on hosts different from the parent sitemap host"}},
			Description: "Allow child sitemap URLs on hosts different from the parent sitemap host.\nDefault: disabled.",
		},
		probecli.InputSpec{
			Key:         "max_depth",
			Type:        probecli.InputInt,
			Default:     "0",
			Aliases:     []probecli.InputAlias{{Long: "max-depth", Usage: "maximum sitemap tree depth, 0 disables the limit"}},
			Description: "Maximum sitemap tree depth before traversal stops.\nUse 0 to disable the limit.",
			Examples:    []string{"--max-depth 0", "--max-depth 8"},
		},
		probecli.InputSpec{
			Key:         "max_files",
			Type:        probecli.InputInt,
			Default:     "0",
			Aliases:     []probecli.InputAlias{{Long: "max-files", Usage: "maximum number of sitemap documents to fetch, 0 disables the limit"}},
			Description: "Maximum number of sitemap documents to fetch.\nUse 0 to disable the limit.",
			Examples:    []string{"--max-files 0", "--max-files 500"},
		},
		probecli.InputSpec{
			Key:         "max_urls",
			Type:        probecli.InputInt,
			Default:     "0",
			Aliases:     []probecli.InputAlias{{Long: "max-urls", Usage: "maximum number of url entries to parse across the tree, 0 disables the limit"}},
			Description: "Maximum number of URL entries to parse across the whole tree.\nUse 0 to disable the limit.",
			Examples:    []string{"--max-urls 0", "--max-urls 200000"},
		},
		probecli.InputSpec{
			Key:         "user_agent",
			Type:        probecli.InputString,
			Default:     httpx.DefaultUserAgent(),
			Aliases:     []probecli.InputAlias{{Long: "user-agent", Usage: "HTTP User-Agent"}},
			Description: "Override the HTTP User-Agent header sent by the probe's HTTP requests.",
			Examples:    []string{fmt.Sprintf(`--user-agent "%s"`, httpx.DefaultUserAgent())},
		},
		probecli.InputSpec{
			Key:         "insecure_skip_verify",
			Type:        probecli.InputBool,
			Aliases:     []probecli.InputAlias{{Long: "insecure-skip-verify", Usage: "disable TLS certificate verification for HTTP requests"}},
			Description: "Disable TLS certificate verification for HTTP requests.\nUse only for diagnostics or when you intentionally want to inspect payload behavior behind broken TLS.",
		},
		probecli.InputSpec{
			Key:         "fallback_paths",
			Type:        probecli.InputString,
			Default:     strings.Join(sitemap.DefaultFallbackPaths, ","),
			Aliases:     []probecli.InputAlias{{Long: "fallback-paths", Usage: "comma-separated fallback paths"}},
			Description: "Override the comma-separated fallback path list used after robots.txt discovery fails.",
			Examples:    []string{"--fallback-paths /sitemap.xml,/sitemap_index.xml,/sitemap.xml.gz"},
		},
		probecli.InputSpec{
			Key:         "fallback_status",
			Type:        probecli.InputString,
			Default:     string(sitemap.FallbackWarn),
			Aliases:     []probecli.InputAlias{{Long: "fallback-status", Usage: "severity when sitemap is resolved only via fallback: ok|warn"}},
			Description: "Severity to use when sitemap discovery succeeds only through fallback probing.\nAccepted values: ok, warn.\nThis only changes the severity of sitemap_fallback_used.\nUse --ignore-errors sitemap_fallback_used to suppress that finding entirely.",
			Examples:    []string{"--fallback-status warn", "--fallback-status ok"},
		},
	}
}

func sitemapHelpConfig() probecli.CommonHelpConfig {
	cfg := probecli.DefaultCommonHelpConfig(
		"60s",
		"json emits the structured sitemap waterfall report for external renderers.",
		"--ignore-errors sitemap_fallback_used,sitemap_content_type_unexpected",
	)
	cfg.TimeoutExamples = []string{"-t 60s", "--timeout 300s"}
	return cfg
}

func validateInputs(inputs *probecli.Inputs) error {
	if inputs.String("hostname") == "" && inputs.String("url") == "" && inputs.String("entrypoint") == "" {
		return probecli.ErrInputRequiredAny(
			probecli.InputRefHostname,
			probecli.InputRefURL,
			probecli.InputRefEntrypoint,
		)
	}
	if err := probecli.ValidateMinInt(inputs.Int("max_depth"), probecli.InputRefMaxDepth, 0); err != nil {
		return err
	}
	if err := probecli.ValidateMinInt(inputs.Int("max_files"), probecli.InputRefMaxFiles, 0); err != nil {
		return err
	}
	if err := probecli.ValidateMinInt(inputs.Int("max_urls"), probecli.InputRefMaxURLs, 0); err != nil {
		return err
	}
	return nil
}

func renderHelp(binName string) string {
	return probecli.RenderHelpDocument(probecli.HelpDocument{
		ProgramName: binName,
		Summary:     sitemap.Meta.Summary,
		Usage: []string{
			binName + " -H example.com [options]",
			binName + " -u https://example.com [options]",
			binName + " --entrypoint https://example.com/sitemap.xml [options]",
		},
		InputOptions: sitemapInputSpecs(sitemap.DefaultConfig()),
		Common:       sitemapHelpConfig(),
	})
}
