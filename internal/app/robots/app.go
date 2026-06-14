package robotsapp

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/habralab/habr-nagios-plugins/internal/core/buildinfo"
	"github.com/habralab/habr-nagios-plugins/internal/core/clihelp"
	"github.com/habralab/habr-nagios-plugins/internal/core/httpx"
	"github.com/habralab/habr-nagios-plugins/internal/core/probecli"
	"github.com/habralab/habr-nagios-plugins/internal/core/verbosity"
	"github.com/habralab/habr-nagios-plugins/internal/probe/robots"
)

func Run(programName string, args []string) int {
	binName := probecli.EffectiveProgramName(programName, robots.Meta.DefaultBinaryName())

	cfg, err := parseFlags(binName, args)
	if err != nil {
		fmt.Printf("UNKNOWN - %v\n", err)
		return robots.ExitUnknown
	}

	if cfg.ShowVersion {
		fmt.Println(buildinfo.String(binName))
		return robots.ExitOK
	}
	if cfg.ShowErrorSlugs {
		fmt.Print(probecli.RenderErrorSlugDescriptors(robots.CatalogEntries()))
		return robots.ExitOK
	}
	if cfg.ShowKnownDirectives {
		printKnownDirectives()
		return robots.ExitOK
	}
	if cfg.ShowKnownAgents {
		printKnownAgents()
		return robots.ExitOK
	}
	if cfg.ShowKnownAgentBehaviors {
		printKnownAgentBehaviors()
		return robots.ExitOK
	}
	if cfg.ShowHelp {
		printHelp(binName)
		return robots.ExitOK
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	result, err := robots.Run(ctx, cfg)
	if err != nil {
		fmt.Printf("UNKNOWN - %v\n", err)
		return robots.ExitUnknown
	}

	if cfg.Verbosity > 0 {
		fmt.Print(result.Detail())
	} else {
		fmt.Println(result.Summary())
	}
	return result.ExitCode()
}

func parseFlags(binName string, args []string) (robots.Config, error) {
	normalizedArgs, baseVerbosity, err := verbosity.NormalizeArgs(args)
	if err != nil {
		return robots.Config{}, err
	}

	fs := flag.NewFlagSet(binName, flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	cfg := robots.DefaultConfig()
	var timeout string
	var verbosityFlag int
	var requireUserAgents string
	var requireDisallows string
	var forbidDisallows string
	var ignoreErrors string
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
	fs.StringVar(&timeout, "t", "30s", "overall timeout")
	fs.StringVar(&timeout, "timeout", "30s", "overall timeout")
	fs.StringVar(&ignoreErrors, "ignore-errors", "", "comma-separated error slugs to suppress")
	fs.IntVar(&verbosityFlag, "v", 0, "verbosity level 0..3")
	fs.IntVar(&verbosityFlag, "verbose", 0, "verbosity level 0..3")
	fs.BoolVar(&cfg.ShowHelp, "h", false, "show help")
	fs.BoolVar(&cfg.ShowHelp, "help", false, "show help")
	fs.BoolVar(&cfg.ShowErrorSlugs, "list-error-slugs", false, "list suppressible error slugs and exit")
	fs.BoolVar(&cfg.ShowKnownDirectives, "list-known-directives", false, "list built-in known robots.txt directives and exit")
	fs.BoolVar(&cfg.ShowKnownAgents, "list-known-agents", false, "list built-in known crawler and AI agent tokens and exit")
	fs.BoolVar(&cfg.ShowKnownAgentBehaviors, "list-agent-behaviors", false, "list built-in documented crawler behavior claims and exit")
	fs.BoolVar(&cfg.ShowVersion, "V", false, "show version")
	fs.BoolVar(&cfg.ShowVersion, "version", false, "show version")

	if err := fs.Parse(normalizedArgs); err != nil {
		return robots.Config{}, err
	}

	d, err := probecli.ParseTimeout(timeout, "--timeout")
	if err != nil {
		return robots.Config{}, err
	}
	cfg.Timeout = d
	cfg.Verbosity = verbosity.Clamp(baseVerbosity + verbosityFlag)
	cfg.BehaviorProfile, err = parseBehaviorProfile(behaviorProfile)
	if err != nil {
		return robots.Config{}, err
	}
	cfg.RequireUserAgents = probecli.SplitCSV(requireUserAgents)
	cfg.RequireDisallows = probecli.SplitCSV(requireDisallows)
	cfg.ForbidDisallows = probecli.SplitCSV(forbidDisallows)
	cfg.IgnoreErrors, cfg.IgnoreErrorSet, err = probecli.BuildIgnoreErrorSet(ignoreErrors, robots.CatalogHasSlug)
	if err != nil {
		return robots.Config{}, err
	}

	return cfg, nil
}

func printHelp(binName string) {
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
		{Short: "-h", Long: "--help", Description: "Show help"},
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
			Long: "--ignore-errors",
			Description: "Comma-separated finding slugs to suppress from status aggregation.\n" +
				"Use --list-error-slugs to see the available values.",
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
		{Short: "-t", Long: "--timeout", Description: "Overall check timeout.\nDefault: 30s.", Examples: []string{"-t 30s", "--timeout 120s"}},
		{Short: "-v", Long: "--verbose", Description: "Increase output detail.\nRepeat up to 3 times for deeper diagnostics.", Examples: []string{"-v", "-vv", "-vvv", "--verbose=2"}},
		{Long: "--list-error-slugs", Description: "Print the available suppressible error slugs with category, default severity, and message, then exit."},
		{Long: "--list-known-directives", Description: "Print the built-in robots.txt directive registry and exit.\nIncludes core, well-known, vendor, and observed extensions."},
		{Long: "--list-known-agents", Description: "Print the built-in crawler and AI agent registry and exit."},
		{Long: "--list-agent-behaviors", Description: "Print the built-in documented crawler behavior matrix and exit.\nUse this to inspect what vendor-aware and strict mode can reason about."},
		{Short: "-V", Long: "--version", Description: "Show version and build metadata"},
	}
	options = append(options, httpx.HelpOptions()...)

	fmt.Printf(`%s

%s

Usage:
  %s -H example.com [options]
  %s -u https://example.com [options]
  %s --robots-url https://example.com/robots.txt [options]

Options:
%s`, binName, robots.Meta.Summary, binName, binName, binName, clihelp.RenderOptions(options))
}

func printKnownDirectives() {
	for _, spec := range robots.KnownDirectives() {
		fmt.Printf("%s\tclass=%s\tscope=%s\tprovenance=%s\treference=%s\treference_url=%s\n",
			spec.Name,
			spec.Class,
			spec.Scope,
			spec.Provenance,
			spec.Reference,
			emptyAsDash(spec.ReferenceURL),
		)
	}
}

func printKnownAgents() {
	for _, spec := range robots.KnownAgents() {
		fmt.Printf("%s\tvendor=%s\tkind=%s\tprovenance=%s\treference=%s\treference_url=%s\n",
			spec.Token,
			spec.Vendor,
			spec.Kind,
			spec.Provenance,
			spec.Reference,
			emptyAsDash(spec.ReferenceURL),
		)
	}
}

func printKnownAgentBehaviors() {
	for _, spec := range robots.KnownAgentBehaviors() {
		for _, claim := range spec.Claims {
			fmt.Printf("%s\tcategory=%s\tsubject=%s\tdisposition=%s\tvalue=%s\treference=%s\treference_url=%s\tnote=%s\n",
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
