package dnsrrapp

import (
	"context"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/core/dnsprobe"
	"github.com/habralab/habr-nagios-plugins/internal/core/probecli"
	"github.com/habralab/habr-nagios-plugins/internal/probe/dnsrr"
)

var dnsrrRun = dnsrr.Run

func Run(programName string, args []string) int {
	return probecli.RunApp(probecli.AppSpec[dnsrr.Config, *dnsrr.Result]{
		ProgramName:       programName,
		Args:              args,
		Probe:             dnsrr.Meta.Slug,
		DefaultBinaryName: dnsrr.Meta.DefaultBinaryName(),
		Parse:             parseFlags,
		BuildToggles: func(binName string, cfg dnsrr.Config) []probecli.ToggleAction {
			return []probecli.ToggleAction{
				probecli.VersionAction(binName, cfg.ShowVersion, 0),
				{Enabled: cfg.ShowErrorSlugs, Output: probecli.RenderErrorSlugDescriptors(dnsrr.CatalogEntries()), ExitCode: 0},
				{Enabled: cfg.ShowHelp, Output: renderHelp(binName), ExitCode: 0},
			}
		},
		Timeout:         func(cfg dnsrr.Config) time.Duration { return cfg.Timeout },
		Run:             dnsrrRun,
		UnknownExitCode: 3,
		OutputMode:      func(cfg dnsrr.Config) checkreport.OutputMode { return cfg.OutputMode },
		Verbosity:       func(cfg dnsrr.Config) int { return cfg.Verbosity },
		DecorateReport: func(ctx context.Context, cfg dnsrr.Config, report *checkreport.Report) {
			probecli.DecorateReportWithCacheBackendInspection(ctx, cfg.CacheBackend, true, report)
			probecli.DecorateReportWithTransportFamilyRuntime(ctx, cfg.TransportFamilyPolicy, cfg.QueryTimeout, report)
		},
	})
}

func parseFlags(binName string, args []string) (dnsrr.Config, error) {
	parser, err := probecli.NewParser(binName, args)
	if err != nil {
		return dnsrr.Config{}, err
	}
	cfg := dnsrr.DefaultConfig()
	parser.RegisterCommon("30s")
	specs := dnsrrInputSpecs(cfg)
	err = parser.RegisterInputs(specs...)
	if err != nil {
		return dnsrr.Config{}, err
	}
	resolved, inputs, err := parser.Parse(dnsrr.CatalogHasSlug, validateInputs)
	if err != nil {
		return dnsrr.Config{}, err
	}
	cfg.Hostname = inputs.String("hostname")
	cfg.Zone = inputs.String("zone")
	cfg.Owner = inputs.String("owner")
	cfg.RRType = inputs.String("rrtype")
	cfg.ExpectValue = inputs.String("expect_value")
	cfg.ContainsValue = inputs.String("contains_value")
	cfg.RegexValue = inputs.String("regex_value")
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
		return dnsrr.Config{}, err
	}
	cfg.Mode = dnsprobe.PresenceMode(inputs.String("mode"))
	cfg.DNSSECMode = dnsprobe.DNSSECMode(inputs.String("dnssec_mode"))
	return cfg, nil
}

func dnsrrInputSpecs(cfg dnsrr.Config) []probecli.InputSpec {
	return []probecli.InputSpec{
		probecli.InputSpec{
			Key:  "hostname",
			Type: probecli.InputString,
			Aliases: []probecli.InputAlias{
				{Short: "H", Usage: "hostname used as the owner target"},
				{Long: "hostname", Usage: "hostname used as the owner target"},
			},
			Description: "Hostname-derived owner target.\nWhen --owner is omitted, the hostname itself becomes the queried owner name.",
		},
		probecli.InputSpec{
			Key:         "zone",
			Type:        probecli.InputString,
			Aliases:     []probecli.InputAlias{{Long: "zone", Usage: "explicit DNS zone target"}},
			Description: "Explicit zone target.\nWhen --owner is omitted, the zone apex becomes the queried owner name.",
		},
		probecli.InputSpec{
			Key:         "owner",
			Type:        probecli.InputString,
			Aliases:     []probecli.InputAlias{{Long: "owner", Usage: "explicit owner name to query"}},
			Description: "Explicit owner name to query within or alongside the selected zone.\nUseful for records such as _dmarc, _acme-challenge, or service-prefixed TXT entries.",
		},
		probecli.InputSpec{
			Key:         "rrtype",
			Type:        probecli.InputString,
			Aliases:     []probecli.InputAlias{{Long: "rrtype", Usage: "RR type to query authoritatively"}},
			Description: "RR type to query on authoritative servers.\nExamples include A, AAAA, TXT, MX, CAA, NS, CNAME, DS, and DNSKEY.",
		},
		probecli.InputSpec{
			Key:         "expect_value",
			Type:        probecli.InputString,
			Aliases:     []probecli.InputAlias{{Long: "expect-value", Usage: "exact RR string that must appear on at least one authoritative endpoint"}},
			Description: "Require an exact RR string match on authoritative answers.\nUse this when the complete rendered RR value must be present.",
			Examples:    []string{"--expect-value \"v=spf1 include:_spf.example.net -all\""},
		},
		probecli.InputSpec{
			Key:         "contains_value",
			Type:        probecli.InputString,
			Aliases:     []probecli.InputAlias{{Long: "contains", Usage: "substring that must appear in an RR string on at least one authoritative endpoint"}},
			Description: "Require a substring match inside an authoritative RR string.\nUseful for TXT-based rollout checks such as SPF, DMARC, or ACME tokens.",
			Examples:    []string{"--contains spf1", "--contains v=DMARC1"},
		},
		probecli.InputSpec{
			Key:         "regex_value",
			Type:        probecli.InputString,
			Aliases:     []probecli.InputAlias{{Long: "regex", Usage: "regular expression that must match an RR string on at least one authoritative endpoint"}},
			Description: "Require a regular expression match against an authoritative RR string.\nOnly one of --expect-value, --contains, or --regex may be used per run.",
			Examples:    []string{"--regex \"include:[^ ]+\\.example\\.net\""},
		},
		probecli.InputSpec{
			Key:         "mode",
			Type:        probecli.InputString,
			Default:     string(cfg.Mode),
			Aliases:     []probecli.InputAlias{{Long: "mode", Usage: "presence mode: any|master|all|none"}},
			Description: "Presence evaluation mode.\nany: present on at least one authoritative endpoint.\nmaster: present on the formal master from SOA MNAME.\nall: present on every authoritative endpoint.\nnone: absent on every authoritative endpoint.",
			Examples:    []string{"--mode any", "--mode master", "--mode all", "--mode none"},
		},
		probecli.InputSpec{
			Key:         "dnssec_mode",
			Type:        probecli.InputString,
			Default:     string(cfg.DNSSECMode),
			Aliases:     []probecli.InputAlias{{Long: "dnssec-mode", Usage: "DNSSEC policy: ignore|prefer|require"}},
			Description: "How to treat DNSSEC state for the queried RRset.\nignore: do not evaluate DNSSEC.\nprefer: surface insecure or inconclusive DNSSEC as non-fatal findings.\nrequire: require a secure DNSSEC state for success.\nDefault: prefer.\nPerfdata dnssec_status uses -1=disabled, 0=indeterminate, 1=bogus, 2=insecure, 3=secure.",
			Examples:    []string{"--dnssec-mode ignore", "--dnssec-mode prefer", "--dnssec-mode require"},
		},
		probecli.InputSpec{
			Key:         "query_timeout",
			Type:        probecli.InputString,
			Default:     "3s",
			Aliases:     []probecli.InputAlias{{Long: "query-timeout", Usage: "per DNS query timeout"}},
			Description: "Per-DNS-exchange timeout.\nDefault: 3s.",
			Examples:    []string{"--query-timeout 3s", "--query-timeout 1500ms"},
		},
	}
}

func dnsrrHelpConfig() probecli.CommonHelpConfig {
	return probecli.DefaultCommonHelpConfig(
		"30s",
		"json emits the structured authoritative RR evaluation report for external renderers.",
		"--ignore-errors dnsrr_endpoint_failed,dnsrr_rrset_inconsistent",
	)
}

func validateInputs(inputs *probecli.Inputs) error {
	if !dnsprobe.IsValidPresenceMode(dnsprobe.PresenceMode(inputs.String("mode"))) {
		return probecli.ErrInvalidEnum(
			probecli.InputRefMode,
			inputs.String("mode"),
			dnsprobe.PresenceModeAllowed()...,
		)
	}
	if !dnsprobe.IsValidDNSSECMode(dnsprobe.DNSSECMode(inputs.String("dnssec_mode"))) {
		return probecli.ErrInvalidEnum(
			probecli.InputRefDNSSECMode,
			inputs.String("dnssec_mode"),
			dnsprobe.DNSSECModeAllowed()...,
		)
	}
	return nil
}

func renderHelp(binName string) string {
	return probecli.RenderHelpDocument(probecli.HelpDocument{
		ProgramName: binName,
		Summary:     dnsrr.Meta.Summary,
		Usage: []string{
			binName + " -H www.example.com --rrtype A [options]",
			binName + " --zone example.com --owner _dmarc.example.com --rrtype TXT --mode all [options]",
			binName + " --zone example.com --owner example.com --rrtype TXT --contains spf1 [options]",
		},
		InputOptions: dnsrrInputSpecs(dnsrr.DefaultConfig()),
		Common:       dnsrrHelpConfig(),
	})
}
