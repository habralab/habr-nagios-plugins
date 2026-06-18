package dnschainapp

import (
	"context"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/core/probecli"
	"github.com/habralab/habr-nagios-plugins/internal/probe/dnschain"
)

func Run(programName string, args []string) int {
	return probecli.RunApp(probecli.AppSpec[dnschain.Config, *dnschain.Result]{
		ProgramName:       programName,
		Args:              args,
		Probe:             dnschain.Meta.Slug,
		DefaultBinaryName: dnschain.Meta.DefaultBinaryName(),
		Parse:             parseFlags,
		BuildToggles: func(binName string, cfg dnschain.Config) []probecli.ToggleAction {
			return []probecli.ToggleAction{
				probecli.VersionAction(binName, cfg.ShowVersion, 0),
				{Enabled: cfg.ShowErrorSlugs, Output: probecli.RenderErrorSlugDescriptors(dnschain.CatalogEntries()), ExitCode: 0},
				{Enabled: cfg.ShowHelp, Output: renderHelp(binName), ExitCode: 0},
			}
		},
		Timeout:         func(cfg dnschain.Config) time.Duration { return cfg.Timeout },
		Run:             dnschain.Run,
		UnknownExitCode: 3,
		OutputMode:      func(cfg dnschain.Config) checkreport.OutputMode { return cfg.OutputMode },
		Verbosity:       func(cfg dnschain.Config) int { return cfg.Verbosity },
		DecorateReport: func(ctx context.Context, cfg dnschain.Config, report *checkreport.Report) {
			probecli.DecorateReportWithCacheBackendInspection(ctx, cfg.CacheBackend, true, report)
			probecli.DecorateReportWithTransportFamilyRuntime(ctx, cfg.TransportFamilyPolicy, cfg.QueryTimeout, report)
		},
	})
}

func parseFlags(binName string, args []string) (dnschain.Config, error) {
	parser, err := probecli.NewParser(binName, args)
	if err != nil {
		return dnschain.Config{}, err
	}
	cfg := dnschain.DefaultConfig()
	parser.RegisterCommon("60s")
	specs := dnschainInputSpecs()
	err = parser.RegisterInputs(specs...)
	if err != nil {
		return dnschain.Config{}, err
	}
	resolved, inputs, err := parser.Parse(dnschain.CatalogHasSlug, nil)
	if err != nil {
		return dnschain.Config{}, err
	}
	cfg.Hostname = inputs.String("hostname")
	cfg.Zone = inputs.String("zone")
	cfg.Timeout = resolved.Timeout
	cfg.TransportFamilyPolicy = resolved.TransportFamilyPolicy
	cfg.CacheBackend = resolved.CacheBackend
	cfg.OutputMode = resolved.OutputMode
	cfg.Verbosity = resolved.Verbosity
	cfg.IgnoreErrors = resolved.IgnoreErrors
	cfg.IgnoreErrorSet = resolved.IgnoreErrorSet
	cfg.ShowHelp = resolved.ShowHelp
	cfg.ShowVersion = resolved.ShowVersion
	cfg.ShowErrorSlugs = resolved.ShowErrorSlugs
	cfg.QueryTimeout, err = probecli.ParseTimeout(inputs.String("query_timeout"), "--query-timeout")
	if err != nil {
		return dnschain.Config{}, err
	}

	return cfg, nil
}

func dnschainInputSpecs() []probecli.InputSpec {
	return []probecli.InputSpec{
		probecli.InputSpec{
			Key:  "hostname",
			Type: probecli.InputString,
			Aliases: []probecli.InputAlias{
				{Short: "H", Usage: "hostname used as the DNS target"},
				{Long: "hostname", Usage: "hostname used as the DNS target"},
			},
			Description: "Hostname used as the target name for authoritative DNS integrity analysis.\nThe checker derives and analyzes the enclosing zone from this target, then verifies owner-level CNAME/A/AAAA presence on the final zone authoritative servers.\nSame-zone CNAME chains are followed to terminal A/AAAA data; foreign-zone CNAME targets are recognized but not recursively validated yet.",
			Examples:    []string{"-H www.example.com"},
		},
		probecli.InputSpec{
			Key:         "zone",
			Type:        probecli.InputString,
			Aliases:     []probecli.InputAlias{{Long: "zone", Usage: "explicit DNS zone target"}},
			Description: "Explicit zone target.\nUse this when you want to analyze a zone cut directly instead of starting from a hostname.",
			Examples:    []string{"--zone example.com"},
		},
		probecli.InputSpec{
			Key:         "query_timeout",
			Type:        probecli.InputString,
			Default:     "3s",
			Aliases:     []probecli.InputAlias{{Long: "query-timeout", Usage: "per DNS query timeout"}},
			Description: "Per-DNS-exchange timeout.\nUse this to cap individual authoritative queries without shrinking the whole check budget.\nThis is especially useful for flapping or half-dead authoritative endpoints in dual-stack sets.\nDefault: 3s.",
			Examples:    []string{"--query-timeout 3s", "--query-timeout 1500ms"},
		},
	}
}

func dnschainHelpConfig() probecli.CommonHelpConfig {
	return probecli.DefaultCommonHelpConfig(
		"60s",
		"json emits the structured waterfall report for external renderers.",
		"--ignore-errors dnschain_child_soa_inconsistent,dnschain_nsec3param_not_recommended",
	)
}

func renderHelp(binName string) string {
	return probecli.RenderHelpDocument(probecli.HelpDocument{
		ProgramName: binName,
		Summary:     dnschain.Meta.Summary,
		Usage: []string{
			binName + " -H www.example.com [options]",
			binName + " --zone example.com [options]",
		},
		InputOptions: dnschainInputSpecs(),
		Common:       dnschainHelpConfig(),
	})
}
