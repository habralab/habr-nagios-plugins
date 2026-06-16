package dnschainapp

import (
	"context"
	"fmt"

	"github.com/habralab/habr-nagios-plugins/internal/core/clihelp"
	"github.com/habralab/habr-nagios-plugins/internal/core/probecli"
	"github.com/habralab/habr-nagios-plugins/internal/probe/dnschain"
)

func Run(programName string, args []string) int {
	binName := probecli.EffectiveProgramName(programName, dnschain.Meta.DefaultBinaryName())
	requestedOutputMode := probecli.DetectOutputMode(args)

	cfg, err := parseFlags(binName, args)
	if err != nil {
		fmt.Print(probecli.RenderEarlyError(dnschain.Meta.Slug, "", requestedOutputMode, err))
		return 3
	}
	if output, exitCode, handled := probecli.DispatchToggleActions(
		probecli.VersionAction(binName, cfg.ShowVersion, 0),
		probecli.ToggleAction{Enabled: cfg.ShowErrorSlugs, Output: probecli.RenderErrorSlugDescriptors(dnschain.CatalogEntries()), ExitCode: 0},
		probecli.ToggleAction{Enabled: cfg.ShowHelp, Output: renderHelp(binName), ExitCode: 0},
	); handled {
		fmt.Print(output)
		return exitCode
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	result, err := dnschain.Run(ctx, cfg)
	if err != nil {
		fmt.Print(probecli.RenderEarlyError(dnschain.Meta.Slug, "", cfg.OutputMode, err))
		return 3
	}

	rendered, exitCode, err := probecli.RenderResult(result, cfg.OutputMode, cfg.Verbosity)
	if err != nil {
		fmt.Printf("UNKNOWN - %v\n", err)
		return 3
	}
	fmt.Print(rendered)
	return exitCode
}

func parseFlags(binName string, args []string) (dnschain.Config, error) {
	fs, common, err := probecli.NewCommonFlagSet(binName, args)
	if err != nil {
		return dnschain.Config{}, err
	}

	cfg := dnschain.DefaultConfig()
	var queryTimeout string

	fs.StringVar(&cfg.Hostname, "H", "", "hostname used as the DNS target")
	fs.StringVar(&cfg.Hostname, "hostname", "", "hostname used as the DNS target")
	fs.StringVar(&cfg.Zone, "zone", "", "explicit DNS zone target")
	fs.StringVar(&queryTimeout, "query-timeout", "3s", "per DNS query timeout")
	common.Register(fs, "60s")

	if err := fs.Parse(common.Args()); err != nil {
		return dnschain.Config{}, err
	}

	resolved, err := common.Resolve(dnschain.CatalogHasSlug)
	if err != nil {
		return dnschain.Config{}, err
	}
	cfg.Timeout = resolved.Timeout
	cfg.OutputMode = resolved.OutputMode
	cfg.Verbosity = resolved.Verbosity
	cfg.IgnoreErrors = resolved.IgnoreErrors
	cfg.IgnoreErrorSet = resolved.IgnoreErrorSet
	cfg.ShowHelp = resolved.ShowHelp
	cfg.ShowVersion = resolved.ShowVersion
	cfg.ShowErrorSlugs = resolved.ShowErrorSlugs
	cfg.QueryTimeout, err = probecli.ParseTimeout(queryTimeout, "--query-timeout")
	if err != nil {
		return dnschain.Config{}, err
	}

	return cfg, nil
}

func renderHelp(binName string) string {
	doc := clihelp.Document{
		ProgramName: binName,
		Summary:     dnschain.Meta.Summary,
		Usage: []string{
			binName + " -H www.example.com [options]",
			binName + " --zone example.com [options]",
		},
	}
	options := []clihelp.Option{
		{
			Short: "-H",
			Long:  "--hostname",
			Description: "Hostname used as the target name for authoritative DNS integrity analysis.\n" +
				"The checker derives and analyzes the enclosing zone from this target, then verifies owner-level CNAME/A/AAAA presence on the final zone authoritative servers.\n" +
				"Same-zone CNAME chains are followed to terminal A/AAAA data; foreign-zone CNAME targets are recognized but not recursively validated yet.",
			Examples: []string{
				"-H www.example.com",
			},
		},
		{
			Long: "--zone",
			Description: "Explicit zone target.\n" +
				"Use this when you want to analyze a zone cut directly instead of starting from a hostname.",
			Examples: []string{
				"--zone example.com",
			},
		},
		{
			Long:        "--output",
			Description: probecli.OutputModeOptionDescription("json emits the structured waterfall report for external renderers."),
			Examples: []string{
				"--output nagios",
				"--output json",
			},
		},
		{
			Long: "--query-timeout",
			Description: "Per-DNS-exchange timeout.\n" +
				"Use this to cap individual authoritative queries without shrinking the whole check budget.\n" +
				"This is especially useful for flapping or half-dead authoritative endpoints in dual-stack sets.\n" +
				"Default: 3s.",
			Examples: []string{
				"--query-timeout 3s",
				"--query-timeout 1500ms",
			},
		},
		{
			Long:        "--ignore-errors",
			Description: probecli.IgnoreErrorsOptionDescription(),
			Examples: []string{
				"--ignore-errors dnschain_child_soa_inconsistent,dnschain_nsec3param_not_recommended",
			},
		},
		{Long: "--list-error-slugs", Description: probecli.ListErrorSlugsOptionDescription()},
		{Short: "-t", Long: "--timeout", Description: probecli.TimeoutOptionDescription("60s"), Examples: []string{"-t 60s", "--timeout 120s"}},
		{Short: "-v", Long: "--verbose", Description: probecli.VerboseOptionDescription(), Examples: []string{"-v", "-vv", "-vvv", "--verbose=2"}},
		{Short: "-h", Long: "--help", Description: probecli.HelpOptionDescription()},
		{Short: "-V", Long: "--version", Description: probecli.VersionOptionDescription()},
	}
	doc.Options = options
	return clihelp.RenderDocument(doc)
}
