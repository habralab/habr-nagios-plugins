package dnschainapp

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/habralab/habr-nagios-plugins/internal/core/buildinfo"
	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/core/clihelp"
	"github.com/habralab/habr-nagios-plugins/internal/core/probecli"
	"github.com/habralab/habr-nagios-plugins/internal/core/verbosity"
	"github.com/habralab/habr-nagios-plugins/internal/probe/dnschain"
)

func Run(programName string, args []string) int {
	binName := probecli.EffectiveProgramName(programName, dnschain.Meta.DefaultBinaryName())

	cfg, showHelp, showVersion, err := parseFlags(binName, args)
	if err != nil {
		fmt.Printf("UNKNOWN - %v\n", err)
		return 3
	}
	if showVersion {
		fmt.Println(buildinfo.String(binName))
		return 0
	}
	if cfg.ShowErrorSlugs {
		fmt.Print(probecli.RenderErrorSlugDescriptors(dnschain.CatalogEntries()))
		return 0
	}
	if showHelp {
		printHelp(binName)
		return 0
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	result, err := dnschain.Run(ctx, cfg)
	if err != nil {
		fmt.Printf("UNKNOWN - %v\n", err)
		return 3
	}

	if cfg.OutputMode == checkreport.OutputJSON {
		data, err := result.JSON()
		if err != nil {
			fmt.Printf("UNKNOWN - failed to encode JSON output: %v\n", err)
			return 3
		}
		fmt.Println(string(data))
		return result.ExitCode()
	}

	if cfg.Verbosity > 0 {
		fmt.Print(result.Detail())
	} else {
		fmt.Println(result.Summary())
	}
	return result.ExitCode()
}

func parseFlags(binName string, args []string) (dnschain.Config, bool, bool, error) {
	normalizedArgs, baseVerbosity, err := verbosity.NormalizeArgs(args)
	if err != nil {
		return dnschain.Config{}, false, false, err
	}

	fs := flag.NewFlagSet(binName, flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	cfg := dnschain.DefaultConfig()
	var timeout string
	var queryTimeout string
	var output string
	var ignoreErrors string
	var verbosityFlag int
	var showHelp bool
	var showVersion bool

	fs.StringVar(&cfg.Hostname, "H", "", "hostname used as the DNS target")
	fs.StringVar(&cfg.Hostname, "hostname", "", "hostname used as the DNS target")
	fs.StringVar(&cfg.Zone, "zone", "", "explicit DNS zone target")
	fs.StringVar(&timeout, "t", "30s", "overall timeout")
	fs.StringVar(&timeout, "timeout", "30s", "overall timeout")
	fs.StringVar(&queryTimeout, "query-timeout", "3s", "per DNS query timeout")
	fs.StringVar(&output, "output", "nagios", "output mode: nagios|json")
	fs.StringVar(&ignoreErrors, "ignore-errors", "", "comma-separated error slugs to suppress")
	fs.IntVar(&verbosityFlag, "v", 0, "verbosity level 0..3")
	fs.IntVar(&verbosityFlag, "verbose", 0, "verbosity level 0..3")
	fs.BoolVar(&showHelp, "h", false, "show help")
	fs.BoolVar(&showHelp, "help", false, "show help")
	fs.BoolVar(&cfg.ShowErrorSlugs, "list-error-slugs", false, "list suppressible error slugs and exit")
	fs.BoolVar(&showVersion, "V", false, "show version")
	fs.BoolVar(&showVersion, "version", false, "show version")

	if err := fs.Parse(normalizedArgs); err != nil {
		return dnschain.Config{}, false, false, err
	}

	cfg.Timeout, err = probecli.ParseTimeout(timeout, "--timeout")
	if err != nil {
		return dnschain.Config{}, false, false, err
	}
	cfg.QueryTimeout, err = probecli.ParseTimeout(queryTimeout, "--query-timeout")
	if err != nil {
		return dnschain.Config{}, false, false, err
	}
	cfg.OutputMode, err = dnschain.ParseOutputMode(output)
	if err != nil {
		return dnschain.Config{}, false, false, err
	}
	cfg.Verbosity = verbosity.Clamp(baseVerbosity + verbosityFlag)
	cfg.IgnoreErrors, cfg.IgnoreErrorSet, err = probecli.BuildIgnoreErrorSet(ignoreErrors, dnschain.CatalogHasSlug)
	if err != nil {
		return dnschain.Config{}, false, false, err
	}

	return cfg, showHelp, showVersion, nil
}

func printHelp(binName string) {
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
			Long: "--output",
			Description: "Output mode.\n" +
				"nagios emits classic monitoring text.\n" +
				"json emits the structured waterfall report for external renderers.\n" +
				"Default: nagios.",
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
			Long: "--ignore-errors",
			Description: "Comma-separated finding slugs to suppress from status aggregation.\n" +
				"Use --list-error-slugs to see the available values.",
			Examples: []string{
				"--ignore-errors dnschain_child_soa_inconsistent,dnschain_nsec3param_not_recommended",
			},
		},
		{Long: "--list-error-slugs", Description: "Print the available suppressible error slugs with category, default severity, and message, then exit."},
		{Short: "-t", Long: "--timeout", Description: "Overall check timeout.\nDefault: 30s.", Examples: []string{"-t 30s", "--timeout 120s"}},
		{Short: "-v", Long: "--verbose", Description: "Increase output detail.\nRepeat up to 3 times for deeper diagnostics.", Examples: []string{"-v", "-vv", "-vvv", "--verbose=2"}},
		{Short: "-h", Long: "--help", Description: "Show help"},
		{Short: "-V", Long: "--version", Description: "Show version and build metadata"},
	}

	fmt.Printf(`%s

%s

Usage:
  %s -H www.example.com [options]
  %s --zone example.com [options]

Options:
%s`, binName, dnschain.Meta.Summary, binName, binName, clihelp.RenderOptions(options))
}
