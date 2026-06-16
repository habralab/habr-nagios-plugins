package robotsapp

import (
	"context"
	"fmt"
	"github.com/habralab/habr-nagios-plugins/internal/core/clihelp"
	"github.com/habralab/habr-nagios-plugins/internal/core/httpx"
	"github.com/habralab/habr-nagios-plugins/internal/core/probecli"
	"github.com/habralab/habr-nagios-plugins/internal/probe/robots"
	"strings"
)

var robotsRun = robots.Run

func Run(programName string, args []string) int {
	binName := probecli.EffectiveProgramName(programName, robots.Meta.DefaultBinaryName())
	requestedOutputMode := probecli.DetectOutputMode(args)

	cfg, err := parseFlags(binName, args)
	if err != nil {
		fmt.Print(probecli.RenderEarlyError(robots.Meta.Slug, "", requestedOutputMode, err))
		return robots.ExitUnknown
	}

	if output, exitCode, handled := probecli.DispatchToggleActions(
		probecli.VersionAction(binName, cfg.ShowVersion, robots.ExitOK),
		probecli.ToggleAction{Enabled: cfg.ShowErrorSlugs, Output: probecli.RenderErrorSlugDescriptors(robots.CatalogEntries()), ExitCode: robots.ExitOK},
		probecli.ToggleAction{Enabled: cfg.ShowKnownDirectives, Output: renderKnownDirectives(), ExitCode: robots.ExitOK},
		probecli.ToggleAction{Enabled: cfg.ShowKnownAgents, Output: renderKnownAgents(), ExitCode: robots.ExitOK},
		probecli.ToggleAction{Enabled: cfg.ShowKnownAgentBehaviors, Output: renderKnownAgentBehaviors(), ExitCode: robots.ExitOK},
		probecli.ToggleAction{Enabled: cfg.ShowHelp, Output: renderHelp(binName), ExitCode: robots.ExitOK},
	); handled {
		fmt.Print(output)
		return exitCode
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	result, err := robotsRun(ctx, cfg)
	if err != nil {
		fmt.Print(probecli.RenderEarlyError(robots.Meta.Slug, "", cfg.OutputMode, err))
		return robots.ExitUnknown
	}

	rendered, exitCode, err := probecli.RenderResult(result, cfg.OutputMode, cfg.Verbosity)
	if err != nil {
		fmt.Printf("UNKNOWN - %v\n", err)
		return robots.ExitUnknown
	}
	fmt.Print(rendered)
	return exitCode
}

func parseFlags(binName string, args []string) (robots.Config, error) {
	fs, common, err := probecli.NewCommonFlagSet(binName, args)
	if err != nil {
		return robots.Config{}, err
	}

	cfg := robots.DefaultConfig()
	var requireUserAgents string
	var requireDisallows string
	var forbidDisallows string
	var behaviorProfile string

	fs.StringVar(&cfg.Hostname, "H", "", "hostname used for discovery, e.g. example.com")
	fs.StringVar(&cfg.Hostname, "hostname", "", "hostname used for discovery, e.g. example.com")
	fs.StringVar(&cfg.URL, "u", "", "full base URL used for discovery, e.g. https://example.com")
	fs.StringVar(&cfg.URL, "url", "", "full base URL used for discovery, e.g. https://example.com")
	fs.StringVar(&cfg.RobotsURL, "robots-url", "", "explicit robots.txt URL")
	fs.BoolVar(&cfg.Strict, "strict", false, "enable stricter policy interpretation")
	fs.StringVar(&behaviorProfile, "behavior-profile", string(robots.BehaviorProfileRFC), "documented crawler behavior profile: rfc, vendor-aware, strict")
	fs.BoolVar(&cfg.RequireSitemap, "require-sitemap", false, "require at least one Sitemap directive")
	fs.StringVar(&requireUserAgents, "require-user-agent", "", "comma-separated User-agent values that must exist")
	fs.StringVar(&requireDisallows, "require-disallow", "", "comma-separated Disallow values that must exist")
	fs.StringVar(&forbidDisallows, "forbid-disallow", "", "comma-separated Disallow values that must not exist")
	fs.StringVar(&cfg.HTTP.UserAgent, "user-agent", httpx.DefaultUserAgent(), "HTTP User-Agent")
	fs.BoolVar(&cfg.HTTP.InsecureSkipVerify, "insecure-skip-verify", false, "disable TLS certificate verification for HTTP requests")
	common.Register(fs, "30s")
	fs.BoolVar(&cfg.ShowKnownDirectives, "list-known-directives", false, "list built-in known robots.txt directives and exit")
	fs.BoolVar(&cfg.ShowKnownAgents, "list-known-agents", false, "list built-in known crawler and AI agent tokens and exit")
	fs.BoolVar(&cfg.ShowKnownAgentBehaviors, "list-agent-behaviors", false, "list built-in documented crawler behavior claims and exit")

	if err := fs.Parse(common.Args()); err != nil {
		return robots.Config{}, err
	}

	resolved, err := common.Resolve(robots.CatalogHasSlug)
	if err != nil {
		return robots.Config{}, err
	}
	cfg.Timeout = resolved.Timeout
	cfg.Verbosity = resolved.Verbosity
	cfg.OutputMode = resolved.OutputMode
	cfg.IgnoreErrors = resolved.IgnoreErrors
	cfg.IgnoreErrorSet = resolved.IgnoreErrorSet
	cfg.ShowHelp = resolved.ShowHelp
	cfg.ShowVersion = resolved.ShowVersion
	cfg.ShowErrorSlugs = resolved.ShowErrorSlugs
	cfg.BehaviorProfile, err = parseBehaviorProfile(behaviorProfile)
	if err != nil {
		return robots.Config{}, err
	}
	cfg.RequireUserAgents = probecli.SplitCSV(requireUserAgents)
	cfg.RequireDisallows = probecli.SplitCSV(requireDisallows)
	cfg.ForbidDisallows = probecli.SplitCSV(forbidDisallows)

	return cfg, nil
}

func renderHelp(binName string) string {
	doc := clihelp.Document{
		ProgramName: binName,
		Summary:     robots.Meta.Summary,
		Usage: []string{
			binName + " -H example.com [options]",
			binName + " -u https://example.com [options]",
			binName + " --robots-url https://example.com/robots.txt [options]",
		},
	}
	options := []clihelp.Option{
		{
			Short: "-H",
			Long:  "--hostname",
			Description: "Hostname used for robots.txt discovery.\n" +
				"Default scheme for hostname-based discovery is https.",
			Examples: []string{
				"-H example.com",
				"-H docs.example.net",
			},
		},
		{Short: "-h", Long: "--help", Description: probecli.HelpOptionDescription()},
		{
			Short: "-u",
			Long:  "--url",
			Description: "Full base URL used for robots.txt discovery.\n" +
				"When both --url and --hostname are provided, --url wins.",
			Examples: []string{
				"-u https://example.com",
				"-u http://docs.example.net",
			},
		},
		{
			Long: "--robots-url",
			Description: "Use an explicit robots.txt URL and skip base URL construction.\n" +
				"This is the most direct mode when the file is not located at /robots.txt.",
			Examples: []string{
				"--robots-url https://example.com/robots.txt",
				"--robots-url https://cdn.example.net/static/robots.txt",
			},
		},
		{
			Long:        "--output",
			Description: probecli.OutputModeOptionDescription("json emits the structured robots waterfall report for external renderers."),
			Examples: []string{
				"--output nagios",
				"--output json",
			},
		},
		{
			Long: "--require-sitemap",
			Description: "Require at least one Sitemap directive.\n" +
				"Use this when robots.txt must advertise sitemap discovery explicitly.",
		},
		{
			Long: "--require-user-agent",
			Description: "Require one or more User-agent values to exist.\n" +
				"Matching is done against the literal User-agent tokens present in the file.",
			Examples: []string{
				"--require-user-agent Googlebot,*",
			},
		},
		{
			Long: "--require-disallow",
			Description: "Require one or more Disallow rules to exist exactly as written.\n" +
				"Matching is exact and ignores group context.",
			Examples: []string{
				"--require-disallow /admin,/private",
			},
		},
		{
			Long: "--forbid-disallow",
			Description: "Fail when one or more Disallow rules are present exactly as written.\n" +
				"Matching is exact and ignores group context.",
			Examples: []string{
				"--forbid-disallow /",
			},
		},
		{
			Long:        "--ignore-errors",
			Description: probecli.IgnoreErrorsOptionDescription(),
			Examples: []string{
				"--ignore-errors robots_content_type_unexpected,robots_invalid_line",
			},
		},
		{
			Long: "--strict",
			Description: "Warn when known non-standard extension directives are in use.\n" +
				"This is independent from --behavior-profile.",
		},
		{
			Long: "--behavior-profile",
			Description: "Apply documented crawler behavior checks.\n" +
				"rfc: only RFC-oriented transport and syntax validation.\n" +
				"vendor-aware: also warn when a documented crawler ignores rules or directives present in its group.\n" +
				"strict: vendor-aware plus warnings for extension directives whose support is undocumented for a known crawler.\n" +
				"Default: rfc.",
			Examples: []string{
				"--behavior-profile vendor-aware",
				"--behavior-profile strict",
			},
		},
		{Short: "-t", Long: "--timeout", Description: probecli.TimeoutOptionDescription("30s"), Examples: []string{"-t 30s", "--timeout 120s"}},
		{Short: "-v", Long: "--verbose", Description: probecli.VerboseOptionDescription(), Examples: []string{"-v", "-vv", "-vvv", "--verbose=2"}},
		{Long: "--list-error-slugs", Description: probecli.ListErrorSlugsOptionDescription()},
		{Long: "--list-known-directives", Description: "Print the built-in robots.txt directive registry and exit.\nIncludes core, well-known, vendor, and observed extensions."},
		{Long: "--list-known-agents", Description: "Print the built-in crawler and AI agent registry and exit."},
		{Long: "--list-agent-behaviors", Description: "Print the built-in documented crawler behavior matrix and exit.\nUse this to inspect what vendor-aware and strict mode can reason about."},
		{Short: "-V", Long: "--version", Description: probecli.VersionOptionDescription()},
	}
	options = append(options, httpx.HelpOptions()...)
	doc.Options = options
	return clihelp.RenderDocument(doc)
}

func renderKnownDirectives() string {
	var b strings.Builder
	for _, spec := range robots.KnownDirectives() {
		fmt.Fprintf(&b, "%s\tclass=%s\tscope=%s\tprovenance=%s\treference=%s\treference_url=%s\n",
			spec.Name,
			spec.Class,
			spec.Scope,
			spec.Provenance,
			spec.Reference,
			emptyAsDash(spec.ReferenceURL),
		)
	}
	return b.String()
}

func renderKnownAgents() string {
	var b strings.Builder
	for _, spec := range robots.KnownAgents() {
		fmt.Fprintf(&b, "%s\tvendor=%s\tkind=%s\tprovenance=%s\treference=%s\treference_url=%s\n",
			spec.Token,
			spec.Vendor,
			spec.Kind,
			spec.Provenance,
			spec.Reference,
			emptyAsDash(spec.ReferenceURL),
		)
	}
	return b.String()
}

func renderKnownAgentBehaviors() string {
	var b strings.Builder
	for _, spec := range robots.KnownAgentBehaviors() {
		for _, claim := range spec.Claims {
			fmt.Fprintf(&b, "%s\tcategory=%s\tsubject=%s\tdisposition=%s\tvalue=%s\treference=%s\treference_url=%s\tnote=%s\n",
				spec.Token,
				claim.Category,
				claim.Subject,
				claim.Disposition,
				emptyAsDash(claim.Value),
				claim.Reference,
				emptyAsDash(claim.ReferenceURL),
				emptyAsDash(claim.Note),
			)
		}
	}
	return b.String()
}

func emptyAsDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func parseBehaviorProfile(raw string) (robots.BehaviorProfile, error) {
	switch strings.TrimSpace(strings.ToLower(raw)) {
	case "", string(robots.BehaviorProfileRFC):
		return robots.BehaviorProfileRFC, nil
	case string(robots.BehaviorProfileVendorAware):
		return robots.BehaviorProfileVendorAware, nil
	case string(robots.BehaviorProfileStrict):
		return robots.BehaviorProfileStrict, nil
	default:
		return "", fmt.Errorf("invalid --behavior-profile %q: want rfc, vendor-aware or strict", raw)
	}
}
