package tlsapp

import (
	"context"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/core/pkix"
	"github.com/habralab/habr-nagios-plugins/internal/core/probecli"
	"github.com/habralab/habr-nagios-plugins/internal/core/tlsx"
	tlsprobe "github.com/habralab/habr-nagios-plugins/internal/probe/tls"
)

var tlsRun = tlsprobe.Run

func Run(programName string, args []string) int {
	return probecli.RunApp(probecli.AppSpec[tlsprobe.Config, *tlsprobe.Result]{
		ProgramName:       programName,
		Args:              args,
		Probe:             tlsprobe.Meta.Slug,
		DefaultBinaryName: tlsprobe.Meta.DefaultBinaryName(),
		Parse:             parseFlags,
		BuildToggles: func(binName string, cfg tlsprobe.Config) []probecli.ToggleAction {
			return []probecli.ToggleAction{
				probecli.VersionAction(binName, cfg.ShowVersion, 0),
				{Enabled: cfg.ShowErrorSlugs, Output: probecli.RenderErrorSlugDescriptors(tlsprobe.CatalogEntries()), ExitCode: 0},
				{Enabled: cfg.ShowHelp, Output: renderHelp(binName), ExitCode: 0},
			}
		},
		Timeout:         func(cfg tlsprobe.Config) time.Duration { return cfg.Timeout },
		Run:             tlsRun,
		UnknownExitCode: 3,
		OutputMode:      func(cfg tlsprobe.Config) checkreport.OutputMode { return cfg.OutputMode },
		Verbosity:       func(cfg tlsprobe.Config) int { return cfg.Verbosity },
		DecorateReport: func(ctx context.Context, cfg tlsprobe.Config, report *checkreport.Report) {
			probecli.DecorateReportWithCacheBackendInspection(ctx, cfg.CacheBackend, true, report)
			probecli.DecorateReportWithTransportFamilyRuntime(ctx, cfg.TransportFamilyPolicy, cfg.HandshakeTimeout, report)
		},
	})
}

func parseFlags(binName string, args []string) (tlsprobe.Config, error) {
	parser, err := probecli.NewParser(binName, args)
	if err != nil {
		return tlsprobe.Config{}, err
	}

	cfg := tlsprobe.DefaultConfig()
	parser.RegisterCommon("30s")
	specs := tlsInputSpecs(cfg)
	err = parser.RegisterInputs(specs...)
	if err != nil {
		return tlsprobe.Config{}, err
	}
	resolved, inputs, err := parser.Parse(tlsprobe.CatalogHasSlug, nil)
	if err != nil {
		return tlsprobe.Config{}, err
	}
	cfg.Hostname = inputs.String("hostname")
	cfg.Port = inputs.Int("port")
	cfg.CAFile = inputs.String("ca_file")
	cfg.CAPath = inputs.String("ca_path")
	cfg.IgnoreExpiredAlternative = inputs.Bool("ignore_expired_alternative")
	cfg.WarnExpiryDays = inputs.Int("warn_expiry_days")
	cfg.Timeout = resolved.Timeout
	cfg.CacheBackend = resolved.CacheBackend
	cfg.TransportFamilyPolicy = resolved.TransportFamilyPolicy
	cfg.OutputMode = resolved.OutputMode
	cfg.Verbosity = resolved.Verbosity
	cfg.IgnoreErrors = resolved.IgnoreErrors
	cfg.IgnoreErrorSet = resolved.IgnoreErrorSet
	cfg.ShowHelp = resolved.ShowHelp
	cfg.ShowVersion = resolved.ShowVersion
	cfg.ShowErrorSlugs = resolved.ShowErrorSlugs
	cfg.DNSTimeout, err = probecli.DecodeTimeoutInput(inputs, "dns_timeout", probecli.InputRefDNSTimeout)
	if err != nil {
		return tlsprobe.Config{}, err
	}
	cfg.HandshakeTimeout, err = probecli.DecodeTimeoutInput(inputs, "handshake_timeout", probecli.InputRefTLSHSKTO)
	if err != nil {
		return tlsprobe.Config{}, err
	}
	cfg.Transport, err = probecli.DecodeEnumInput(inputs, "transport", probecli.InputRefTransport, []string{"tcp"}, tlsx.ParseTransport)
	if err != nil {
		return tlsprobe.Config{}, err
	}
	cfg.STARTTLS, err = probecli.DecodeEnumInput(inputs, "starttls", probecli.InputRefSTARTTLS, []string{"smtp", "imap"}, tlsx.ParseSTARTTLSProfile)
	if err != nil {
		return tlsprobe.Config{}, err
	}
	cfg.PolicyUntrustedRoot, err = probecli.DecodeEnumInput(inputs, "policy_untrusted_root", probecli.InputRefPolicyRoot, []string{"critical", "warning", "ok"}, pkix.ParseUntrustedRootPolicy)
	if err != nil {
		return tlsprobe.Config{}, err
	}
	cfg.PolicyDualStack, err = probecli.DecodeEnumInput(inputs, "policy_dual_stack", probecli.InputRefPolicyDual, []string{"strict", "degraded"}, pkix.ParseDualStackPolicy)
	if err != nil {
		return tlsprobe.Config{}, err
	}
	cfg.OCSPMode, err = probecli.DecodeEnumInput(inputs, "ocsp_mode", probecli.InputRefOCSPMode, []string{"off", "stapled", "active", "strict"}, pkix.ParseOCSPMode)
	if err != nil {
		return tlsprobe.Config{}, err
	}
	cfg.ExpectALPN = probecli.DecodeCSVInput(inputs, "expect_alpn")
	if err := probecli.ValidateMinInt(cfg.WarnExpiryDays, probecli.InputRefWarnExpiry, 0); err != nil {
		return tlsprobe.Config{}, err
	}

	return cfg, nil
}

func tlsInputSpecs(cfg tlsprobe.Config) []probecli.InputSpec {
	specs := append(probecli.ServiceTargetInputSpecs(cfg.Port),
		probecli.InputSpec{
			Key:         "transport",
			Type:        probecli.InputString,
			Default:     string(tlsx.TransportTCP),
			Aliases:     []probecli.InputAlias{{Long: "transport", Usage: "transport: tcp"}},
			Description: "Transport mode.\ntcp is the current TLS-over-TCP mode.\nHTTP/3 and QUIC stay outside the current probe contract.",
			Examples:    []string{"--transport tcp"},
		},
		probecli.InputSpec{
			Key:         "starttls",
			Type:        probecli.InputString,
			Aliases:     []probecli.InputAlias{{Long: "starttls", Usage: "STARTTLS preflight profile: smtp|imap"}},
			Description: "STARTTLS pre-flight profile.\nUse this for services that begin in cleartext and upgrade to TLS.\nSupported scaffolds: smtp, imap.",
			Examples:    []string{"--starttls smtp", "--starttls imap"},
		},
		probecli.InputSpec{
			Key:         "expect_alpn",
			Type:        probecli.InputString,
			Aliases:     []probecli.InputAlias{{Long: "expect-alpn", Usage: "comma-separated expected ALPN identifiers"}},
			Description: "Comma-separated ALPN identifiers expected from the service.\nExamples include h2 and http/1.1.",
			Examples:    []string{"--expect-alpn h2,http/1.1"},
		},
		probecli.InputSpec{
			Key:         "ca_file",
			Type:        probecli.InputString,
			Aliases:     []probecli.InputAlias{{Long: "ca-file", Usage: "path to a custom CA bundle file"}},
			Description: "Path to a custom CA bundle file.\nUse this to trust internal or non-public roots.",
		},
		probecli.InputSpec{
			Key:         "ca_path",
			Type:        probecli.InputString,
			Aliases:     []probecli.InputAlias{{Long: "ca-path", Usage: "path to a custom CA certificate directory"}},
			Description: "Path to a custom CA certificate directory.\nUse this to augment or replace system trust roots.",
		},
		probecli.InputSpec{
			Key:         "policy_untrusted_root",
			Type:        probecli.InputString,
			Default:     string(pkix.UntrustedRootCritical),
			Aliases:     []probecli.InputAlias{{Long: "policy-untrusted-root", Usage: "policy when the chain reaches an untrusted root: critical|warning|ok"}},
			Description: "Policy when a chain is otherwise valid but the trust anchor is missing locally.\nAccepted values: critical, warning, ok.\nDefault: critical.",
			Examples:    []string{"--policy-untrusted-root warning"},
		},
		probecli.InputSpec{
			Key:         "policy_dual_stack",
			Type:        probecli.InputString,
			Default:     string(pkix.DualStackDegraded),
			Aliases:     []probecli.InputAlias{{Long: "policy-dual-stack", Usage: "policy when one TLS branch is degraded: strict|degraded"}},
			Description: "Policy when one TLS certificate branch is degraded but another remains valid.\nAccepted values: strict, degraded.\nDefault: degraded.",
			Examples:    []string{"--policy-dual-stack degraded", "--policy-dual-stack strict"},
		},
		probecli.InputSpec{
			Key:         "ocsp_mode",
			Type:        probecli.InputString,
			Default:     string(pkix.OCSPStapled),
			Aliases:     []probecli.InputAlias{{Long: "ocsp-mode", Usage: "OCSP validation mode: off|stapled|active|strict"}},
			Description: "OCSP validation mode.\noff disables OCSP checks.\nstapled validates only stapled OCSP responses.\nactive fetches from the responder when no staple is present.\nstrict validates stapled data and also fetches from the responder.\nDefault: stapled.",
			Examples:    []string{"--ocsp-mode stapled", "--ocsp-mode active", "--ocsp-mode strict"},
		},
		probecli.InputSpec{
			Key:         "ignore_expired_alternative",
			Type:        probecli.InputBool,
			Aliases:     []probecli.InputAlias{{Long: "ignore-expired-alternative", Usage: "allow expired alternative paths when another valid path exists"}},
			Description: "Allow expired alternative paths or chain tails when another valid trust path exists.",
		},
		probecli.InputSpec{
			Key:         "warn_expiry_days",
			Type:        probecli.InputInt,
			Default:     "30",
			Aliases:     []probecli.InputAlias{{Long: "warn-expiry-days", Usage: "warning threshold for certificate expiry in days"}},
			Description: "Warning threshold for certificate expiry.\nDefault: 30 days.",
			Examples:    []string{"--warn-expiry-days 30", "--warn-expiry-days 14"},
		},
		probecli.InputSpec{
			Key:         "dns_timeout",
			Type:        probecli.InputString,
			Default:     "5s",
			Aliases:     []probecli.InputAlias{{Long: "dns-timeout", Usage: "per DNS lookup timeout"}},
			Description: "Per DNS lookup timeout for CAA, DANE, and supporting DNS operations.\nDefault: 5s.",
			Examples:    []string{"--dns-timeout 5s"},
		},
		probecli.InputSpec{
			Key:         "handshake_timeout",
			Type:        probecli.InputString,
			Default:     "5s",
			Aliases:     []probecli.InputAlias{{Long: "handshake-timeout", Usage: "per handshake timeout"}},
			Description: "Per transport handshake timeout.\nDefault: 5s.",
			Examples:    []string{"--handshake-timeout 5s"},
		},
	)
	specs = probecli.MustSetInputHelp(specs, "hostname", "Target hostname for TLS analysis.\nThe probe currently treats this as the SNI and certificate identity target.", "-H www.example.com")
	specs = probecli.MustSetInputHelp(specs, "port", "Target service port.\nDefault: 443.", "-p 443", "--port 587")
	return specs
}

func tlsHelpConfig() probecli.CommonHelpConfig {
	cfg := probecli.DefaultCommonHelpConfig(
		"30s",
		"json emits the structured TLS waterfall report for external renderers.",
		"--ignore-errors tls_sct_missing,tls_caa_dnssec_invalid",
	)
	cfg.TimeoutExamples = []string{"-t 30s", "--timeout 120s"}
	return cfg
}

func renderHelp(binName string) string {
	return probecli.RenderHelpDocument(probecli.HelpDocument{
		ProgramName: binName,
		Summary:     tlsprobe.Meta.Summary,
		Usage: []string{
			binName + " -H www.example.com [options]",
		},
		InputOptions: tlsInputSpecs(tlsprobe.DefaultConfig()),
		Common:       tlsHelpConfig(),
	})
}
