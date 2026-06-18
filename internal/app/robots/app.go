package robotsapp

import (
	"context"
	"fmt"
	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/core/httpx"
	"github.com/habralab/habr-nagios-plugins/internal/core/probecli"
	"github.com/habralab/habr-nagios-plugins/internal/probe/robots"
	"strings"
	"time"
)

var robotsRun = robots.Run

func Run(programName string, args []string) int {
	return probecli.RunApp(probecli.AppSpec[robots.Config, *robots.Result]{
		ProgramName:       programName,
		Args:              args,
		Probe:             robots.Meta.Slug,
		DefaultBinaryName: robots.Meta.DefaultBinaryName(),
		Parse:             parseFlags,
		BuildToggles: func(binName string, cfg robots.Config) []probecli.ToggleAction {
			return []probecli.ToggleAction{
				probecli.VersionAction(binName, cfg.ShowVersion, robots.ExitOK),
				{Enabled: cfg.ShowErrorSlugs, Output: probecli.RenderErrorSlugDescriptors(robots.CatalogEntries()), ExitCode: robots.ExitOK},
				{Enabled: cfg.ShowKnownDirectives, Output: renderKnownDirectives(), ExitCode: robots.ExitOK},
				{Enabled: cfg.ShowKnownAgents, Output: renderKnownAgents(), ExitCode: robots.ExitOK},
				{Enabled: cfg.ShowKnownAgentBehaviors, Output: renderKnownAgentBehaviors(), ExitCode: robots.ExitOK},
				{Enabled: cfg.ShowHelp, Output: renderHelp(binName), ExitCode: robots.ExitOK},
			}
		},
		Timeout:         func(cfg robots.Config) time.Duration { return cfg.Timeout },
		Run:             robotsRun,
		UnknownExitCode: robots.ExitUnknown,
		OutputMode:      func(cfg robots.Config) checkreport.OutputMode { return cfg.OutputMode },
		Verbosity:       func(cfg robots.Config) int { return cfg.Verbosity },
		DecorateReport: func(ctx context.Context, cfg robots.Config, report *checkreport.Report) {
			probecli.DecorateReportWithCacheBackendInspection(ctx, cfg.CacheBackend, cfg.HTTPClient == nil, report)
			probecli.DecorateReportWithTransportFamilyRuntime(ctx, cfg.HTTP.TransportFamilyPolicy, cfg.Timeout, report)
		},
	})
}

func parseFlags(binName string, args []string) (robots.Config, error) {
	parser, err := probecli.NewParser(binName, args)
	if err != nil {
		return robots.Config{}, err
	}

	cfg := robots.DefaultConfig()
	parser.RegisterCommon("30s")
	specs := robotsInputSpecs(cfg)
	err = parser.RegisterInputs(specs...)
	if err != nil {
		return robots.Config{}, err
	}

	resolved, inputs, err := parser.Parse(robots.CatalogHasSlug, nil)
	if err != nil {
		return robots.Config{}, err
	}
	cfg.Hostname = inputs.String("hostname")
	cfg.URL = inputs.String("url")
	cfg.RobotsURL = inputs.String("robots_url")
	cfg.Strict = inputs.Bool("strict")
	cfg.RequireSitemap = inputs.Bool("require_sitemap")
	cfg.RequireUserAgents = probecli.DecodeCSVInput(inputs, "require_user_agent")
	cfg.RequireDisallows = probecli.DecodeCSVInput(inputs, "require_disallow")
	cfg.ForbidDisallows = probecli.DecodeCSVInput(inputs, "forbid_disallow")
	cfg.HTTP.UserAgent = inputs.String("user_agent")
	cfg.HTTP.InsecureSkipVerify = inputs.Bool("insecure_skip_verify")
	cfg.HTTP.TransportFamilyPolicy = resolved.TransportFamilyPolicy
	cfg.Timeout = resolved.Timeout
	cfg.CacheBackend = resolved.CacheBackend
	cfg.Verbosity = resolved.Verbosity
	cfg.OutputMode = resolved.OutputMode
	cfg.IgnoreErrors = resolved.IgnoreErrors
	cfg.IgnoreErrorSet = resolved.IgnoreErrorSet
	cfg.ShowHelp = resolved.ShowHelp
	cfg.ShowVersion = resolved.ShowVersion
	cfg.ShowErrorSlugs = resolved.ShowErrorSlugs
	cfg.ShowKnownDirectives = inputs.Bool("list_known_directives")
	cfg.ShowKnownAgents = inputs.Bool("list_known_agents")
	cfg.ShowKnownAgentBehaviors = inputs.Bool("list_agent_behaviors")
	cfg.BehaviorProfile, err = probecli.DecodeEnumInput(
		inputs,
		"behavior_profile",
		probecli.InputRefBehavior,
		[]string{"rfc", "vendor-aware", "strict"},
		parseBehaviorProfile,
	)
	if err != nil {
		return robots.Config{}, err
	}
	if !cfg.ShowHelp && !cfg.ShowVersion && !cfg.ShowErrorSlugs && !cfg.ShowKnownDirectives && !cfg.ShowKnownAgents && !cfg.ShowKnownAgentBehaviors {
		if err := validateInputs(inputs); err != nil {
			return robots.Config{}, err
		}
	}

	return cfg, nil
}

func robotsInputSpecs(cfg robots.Config) []probecli.InputSpec {
	return []probecli.InputSpec{
		probecli.InputSpec{
			Key:  "hostname",
			Type: probecli.InputString,
			Aliases: []probecli.InputAlias{
				{Short: "H", Usage: "hostname used for discovery, e.g. example.com"},
				{Long: "hostname", Usage: "hostname used for discovery, e.g. example.com"},
			},
			Description: "Hostname used for robots.txt discovery.\nDefault scheme for hostname-based discovery is https.",
			Examples:    []string{"-H example.com", "-H docs.example.net"},
		},
		probecli.InputSpec{
			Key:         "url",
			Type:        probecli.InputString,
			Aliases:     []probecli.InputAlias{{Short: "u", Usage: "full base URL used for discovery, e.g. https://example.com"}, {Long: "url", Usage: "full base URL used for discovery, e.g. https://example.com"}},
			Description: "Full base URL used for robots.txt discovery.\nWhen both --url and --hostname are provided, --url wins.",
			Examples:    []string{"-u https://example.com", "-u http://docs.example.net"},
		},
		probecli.InputSpec{
			Key:         "robots_url",
			Type:        probecli.InputString,
			Aliases:     []probecli.InputAlias{{Long: "robots-url", Usage: "explicit robots.txt URL"}},
			Description: "Use an explicit robots.txt URL and skip base URL construction.\nThis is the most direct mode when the file is not located at /robots.txt.",
			Examples:    []string{"--robots-url https://example.com/robots.txt", "--robots-url https://cdn.example.net/static/robots.txt"},
		},
		probecli.InputSpec{
			Key:         "strict",
			Type:        probecli.InputBool,
			Aliases:     []probecli.InputAlias{{Long: "strict", Usage: "enable stricter policy interpretation"}},
			Description: "Warn when known non-standard extension directives are in use.\nThis is independent from --behavior-profile.",
		},
		probecli.InputSpec{
			Key:         "behavior_profile",
			Type:        probecli.InputString,
			Default:     string(robots.BehaviorProfileRFC),
			Aliases:     []probecli.InputAlias{{Long: "behavior-profile", Usage: "documented crawler behavior profile: rfc, vendor-aware, strict"}},
			Description: "Apply documented crawler behavior checks.\nrfc: only RFC-oriented transport and syntax validation.\nvendor-aware: also warn when a documented crawler ignores rules or directives present in its group.\nstrict: vendor-aware plus warnings for extension directives whose support is undocumented for a known crawler.\nDefault: rfc.",
			Examples:    []string{"--behavior-profile vendor-aware", "--behavior-profile strict"},
		},
		probecli.InputSpec{
			Key:         "require_sitemap",
			Type:        probecli.InputBool,
			Aliases:     []probecli.InputAlias{{Long: "require-sitemap", Usage: "require at least one Sitemap directive"}},
			Description: "Require at least one Sitemap directive.\nUse this when robots.txt must advertise sitemap discovery explicitly.",
		},
		probecli.InputSpec{
			Key:         "require_user_agent",
			Type:        probecli.InputString,
			Aliases:     []probecli.InputAlias{{Long: "require-user-agent", Usage: "comma-separated User-agent values that must exist"}},
			Description: "Require one or more User-agent values to exist.\nMatching is done against the literal User-agent tokens present in the file.",
			Examples:    []string{"--require-user-agent Googlebot,*"},
		},
		probecli.InputSpec{
			Key:         "require_disallow",
			Type:        probecli.InputString,
			Aliases:     []probecli.InputAlias{{Long: "require-disallow", Usage: "comma-separated Disallow values that must exist"}},
			Description: "Require one or more Disallow rules to exist exactly as written.\nMatching is exact and ignores group context.",
			Examples:    []string{"--require-disallow /admin,/private"},
		},
		probecli.InputSpec{
			Key:         "forbid_disallow",
			Type:        probecli.InputString,
			Aliases:     []probecli.InputAlias{{Long: "forbid-disallow", Usage: "comma-separated Disallow values that must not exist"}},
			Description: "Fail when one or more Disallow rules are present exactly as written.\nMatching is exact and ignores group context.",
			Examples:    []string{"--forbid-disallow /"},
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
			Key:         "list_known_directives",
			Type:        probecli.InputBool,
			Aliases:     []probecli.InputAlias{{Long: "list-known-directives", Usage: "list built-in known robots.txt directives and exit"}},
			Description: "Print the built-in robots.txt directive registry and exit.\nIncludes core, well-known, vendor, and observed extensions.",
		},
		probecli.InputSpec{
			Key:         "list_known_agents",
			Type:        probecli.InputBool,
			Aliases:     []probecli.InputAlias{{Long: "list-known-agents", Usage: "list built-in known crawler and AI agent tokens and exit"}},
			Description: "Print the built-in crawler and AI agent registry and exit.",
		},
		probecli.InputSpec{
			Key:         "list_agent_behaviors",
			Type:        probecli.InputBool,
			Aliases:     []probecli.InputAlias{{Long: "list-agent-behaviors", Usage: "list built-in documented crawler behavior claims and exit"}},
			Description: "Print the built-in documented crawler behavior matrix and exit.\nUse this to inspect what vendor-aware and strict mode can reason about.",
		},
	}
}

func robotsHelpConfig() probecli.CommonHelpConfig {
	cfg := probecli.DefaultCommonHelpConfig(
		"30s",
		"json emits the structured robots waterfall report for external renderers.",
		"--ignore-errors robots_content_type_unexpected,robots_invalid_line",
	)
	cfg.TimeoutExamples = []string{"-t 30s", "--timeout 120s"}
	return cfg
}

func validateInputs(inputs *probecli.Inputs) error {
	if inputs.String("hostname") == "" && inputs.String("url") == "" && inputs.String("robots_url") == "" {
		return probecli.ErrInputRequiredAny(
			probecli.InputRefHostname,
			probecli.InputRefURL,
			probecli.InputRefRobotsURL,
		)
	}
	return nil
}

func renderHelp(binName string) string {
	return probecli.RenderHelpDocument(probecli.HelpDocument{
		ProgramName: binName,
		Summary:     robots.Meta.Summary,
		Usage: []string{
			binName + " -H example.com [options]",
			binName + " -u https://example.com [options]",
			binName + " --robots-url https://example.com/robots.txt [options]",
		},
		InputOptions: robotsInputSpecs(robots.DefaultConfig()),
		Common:       robotsHelpConfig(),
	})
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
		return "", probecli.ErrInvalidEnum(
			probecli.InputRefBehavior,
			raw,
			"rfc", "vendor-aware", "strict",
		)
	}
}
