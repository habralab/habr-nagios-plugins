package probecli

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
)

func TestEffectiveProgramNameFallsBack(t *testing.T) {
	if got, want := EffectiveProgramName("", "check_probe"), "check_probe"; got != want {
		t.Fatalf("EffectiveProgramName() = %q, want %q", got, want)
	}
}

func TestSplitCSVTrimsAndSkipsEmpty(t *testing.T) {
	got := SplitCSV(" a, ,b ,, c ")
	want := []string{"a", "b", "c"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("SplitCSV() = %v, want %v", got, want)
	}
}

func TestBuildIgnoreErrorSetValidatesSlugs(t *testing.T) {
	_, _, err := BuildIgnoreErrorSet("ok,bad", func(slug string) bool {
		return slug == "ok"
	})
	if err == nil || !strings.Contains(err.Error(), `unknown ignored error slug "bad"`) {
		t.Fatalf("BuildIgnoreErrorSet() error = %v, want unknown slug", err)
	}
}

func TestRenderErrorSlugDescriptorsProducesTabularOutput(t *testing.T) {
	out := RenderErrorSlugDescriptors([]ErrorSlugDescriptor{
		{Slug: "slug_one", Category: "transport", Severity: "WARNING", Message: "endpoint timed out"},
		{Slug: "slug_two", Message: "message only"},
	})
	for _, snippet := range []string{
		"slug_one",
		"transport",
		"WARNING",
		"endpoint timed out",
		"slug_two",
		"message only",
	} {
		if !strings.Contains(out, snippet) {
			t.Fatalf("RenderErrorSlugDescriptors() output missing %q in:\n%s", snippet, out)
		}
	}
}

func TestDetectOutputModeRecognizesJSON(t *testing.T) {
	for _, args := range [][]string{
		{"--output", "json"},
		{"-H", "example.com", "--output=json"},
	} {
		if got, want := DetectOutputMode(args), checkreport.OutputJSON; got != want {
			t.Fatalf("DetectOutputMode(%v) = %q, want %q", args, got, want)
		}
	}
}

func TestParseOutputMode(t *testing.T) {
	mode, err := ParseOutputMode("json")
	if err != nil {
		t.Fatalf("ParseOutputMode() error = %v", err)
	}
	if got, want := mode, checkreport.OutputJSON; got != want {
		t.Fatalf("ParseOutputMode() = %q, want %q", got, want)
	}
	if _, err := ParseOutputMode("yaml"); err == nil {
		t.Fatal("ParseOutputMode() error = nil, want invalid output mode error")
	}
}

func TestRenderEarlyError(t *testing.T) {
	err := strings.NewReplacer("\n", "", "\r", "").Replace("boom")

	nagios := RenderEarlyError("check_probe", "", checkreport.OutputNagios, fmt.Errorf("%s", err))
	if got, want := nagios, "UNKNOWN - boom\n"; got != want {
		t.Fatalf("RenderEarlyError() nagios = %q, want %q", got, want)
	}

	jsonOut := RenderEarlyError("check_probe", "example.test", checkreport.OutputJSON, fmt.Errorf("%s", err))
	for _, snippet := range []string{`"probe": "check_probe"`, `"status": "unknown"`, `"summary": "boom"`} {
		if !strings.Contains(jsonOut, snippet) {
			t.Fatalf("RenderEarlyError() JSON missing %q in:\n%s", snippet, jsonOut)
		}
	}
}

func TestRenderEarlyErrorFormatsStructuredInputErrors(t *testing.T) {
	err := ErrInputRequiredAny(InputRefHostname, InputRefZone)

	nagios := RenderEarlyError("check_probe", "", checkreport.OutputNagios, err)
	if got, want := nagios, "UNKNOWN - either -H/--hostname or --zone is required\n"; got != want {
		t.Fatalf("RenderEarlyError() nagios = %q, want %q", got, want)
	}

	jsonOut := RenderEarlyError("check_probe", "example.test", checkreport.OutputJSON, err)
	if !strings.Contains(jsonOut, `"summary": "either -H/--hostname or --zone is required"`) {
		t.Fatalf("RenderEarlyError() JSON missing formatted summary in:\n%s", jsonOut)
	}
}

func TestSharedHelpDescriptions(t *testing.T) {
	if got, want := HelpOptionDescription(), "Show help"; got != want {
		t.Fatalf("HelpOptionDescription() = %q, want %q", got, want)
	}
	if got, want := VersionOptionDescription(), "Show version and build metadata"; got != want {
		t.Fatalf("VersionOptionDescription() = %q, want %q", got, want)
	}
	if got := TimeoutOptionDescription("60s"); !strings.Contains(got, "Default: 60s.") {
		t.Fatalf("TimeoutOptionDescription() = %q, want default suffix", got)
	}
	if got := TimeoutOptionDescription("60s"); !strings.Contains(got, "Bare integers are interpreted as seconds.") {
		t.Fatalf("TimeoutOptionDescription() = %q, want bare-integer note", got)
	}
	if got := OutputModeOptionDescription("json emits the structured report."); !strings.Contains(got, "nagios emits classic monitoring text.") {
		t.Fatalf("OutputModeOptionDescription() = %q, want shared nagios line", got)
	}
}

func TestHelpOptionsFromInputSpecsUsesMetadata(t *testing.T) {
	options := HelpOptionsFromInputSpecs([]InputSpec{
		{
			Key:         "hostname",
			Type:        InputString,
			Aliases:     []InputAlias{{Short: "H", Usage: "target host"}, {Long: "hostname", Usage: "target host"}},
			Description: "Target hostname.",
			Examples:    []string{"-H example.com"},
		},
	})
	if got, want := len(options), 1; got != want {
		t.Fatalf("len(options) = %d, want %d", got, want)
	}
	if got, want := options[0].Short, "-H"; got != want {
		t.Fatalf("options[0].Short = %q, want %q", got, want)
	}
	if got, want := options[0].Long, "--hostname"; got != want {
		t.Fatalf("options[0].Long = %q, want %q", got, want)
	}
	if got, want := options[0].Description, "Target hostname."; got != want {
		t.Fatalf("options[0].Description = %q, want %q", got, want)
	}
}

func TestRenderHelpDocumentIncludesCommonOptions(t *testing.T) {
	out := RenderHelpDocument(HelpDocument{
		ProgramName: "check_example",
		Summary:     "Example",
		Usage:       []string{"check_example -H example.com [options]"},
		InputOptions: []InputSpec{
			{
				Key:         "hostname",
				Type:        InputString,
				Aliases:     []InputAlias{{Short: "H", Usage: "target host"}, {Long: "hostname", Usage: "target host"}},
				Description: "Target hostname.",
			},
		},
		Common: DefaultCommonHelpConfig("30s", "json emits the structured report.", "--ignore-errors example_slug"),
	})
	for _, snippet := range []string{
		"--hostname",
		"--output",
		"--ignore-errors",
		"--list-error-slugs",
		"--timeout",
		"Bare integers are interpreted as seconds.",
	} {
		if !strings.Contains(out, snippet) {
			t.Fatalf("RenderHelpDocument() missing %q in:\n%s", snippet, out)
		}
	}
}

type stubResult struct {
	summary string
	detail  string
	json    string
	exit    int
	err     error
}

func (r stubResult) JSON() ([]byte, error) { return []byte(r.json), r.err }
func (r stubResult) Summary() string       { return r.summary }
func (r stubResult) Detail() string        { return r.detail }
func (r stubResult) ExitCode() int         { return r.exit }

func TestRenderResult(t *testing.T) {
	jsonOut, exitCode, err := RenderResult(stubResult{json: `{"ok":true}`, exit: 1}, checkreport.OutputJSON, 0)
	if err != nil {
		t.Fatalf("RenderResult() json error = %v", err)
	}
	if got, want := jsonOut, "{\"ok\":true}\n"; got != want {
		t.Fatalf("RenderResult() json = %q, want %q", got, want)
	}
	if got, want := exitCode, 1; got != want {
		t.Fatalf("RenderResult() exitCode = %d, want %d", got, want)
	}

	detailOut, _, err := RenderResult(stubResult{detail: "DETAIL", exit: 2}, checkreport.OutputNagios, 1)
	if err != nil {
		t.Fatalf("RenderResult() detail error = %v", err)
	}
	if got, want := detailOut, "DETAIL"; got != want {
		t.Fatalf("RenderResult() detail = %q, want %q", got, want)
	}

	summaryOut, _, err := RenderResult(stubResult{summary: "SUMMARY", exit: 0}, checkreport.OutputNagios, 0)
	if err != nil {
		t.Fatalf("RenderResult() summary error = %v", err)
	}
	if got, want := summaryOut, "SUMMARY\n"; got != want {
		t.Fatalf("RenderResult() summary = %q, want %q", got, want)
	}
}

func TestRenderResultJSONError(t *testing.T) {
	_, exitCode, err := RenderResult(stubResult{err: fmt.Errorf("boom")}, checkreport.OutputJSON, 0)
	if err == nil || !strings.Contains(err.Error(), "failed to encode JSON output") {
		t.Fatalf("RenderResult() error = %v, want wrapped JSON error", err)
	}
	if got, want := exitCode, 3; got != want {
		t.Fatalf("RenderResult() exitCode = %d, want %d", got, want)
	}
}

func TestDispatchToggleActions(t *testing.T) {
	output, exitCode, handled := DispatchToggleActions(
		ToggleAction{Enabled: false, Output: "skip", ExitCode: 1},
		ToggleAction{Enabled: true, Output: "show", ExitCode: 2},
		ToggleAction{Enabled: true, Output: "later", ExitCode: 3},
	)
	if !handled {
		t.Fatal("DispatchToggleActions() handled = false, want true")
	}
	if got, want := output, "show"; got != want {
		t.Fatalf("DispatchToggleActions() output = %q, want %q", got, want)
	}
	if got, want := exitCode, 2; got != want {
		t.Fatalf("DispatchToggleActions() exitCode = %d, want %d", got, want)
	}
}

type stubAppConfig struct {
	timeout    time.Duration
	outputMode checkreport.OutputMode
	verbosity  int
	showHelp   bool
}

func TestRunAppHandlesParseErrorUsingRequestedOutputMode(t *testing.T) {
	exitCode, output := captureStdout(t, func() int {
		return RunApp(AppSpec[stubAppConfig, stubResult]{
			ProgramName:       "check_probe",
			Args:              []string{"--output", "json"},
			Probe:             "check_probe",
			DefaultBinaryName: "check_probe",
			Parse: func(string, []string) (stubAppConfig, error) {
				return stubAppConfig{}, ErrInputRequired(InputRefHostname)
			},
			Timeout:         func(cfg stubAppConfig) time.Duration { return cfg.timeout },
			Run:             func(context.Context, stubAppConfig) (stubResult, error) { return stubResult{}, nil },
			UnknownExitCode: 3,
			OutputMode:      func(cfg stubAppConfig) checkreport.OutputMode { return cfg.outputMode },
			Verbosity:       func(cfg stubAppConfig) int { return cfg.verbosity },
		})
	})
	if got, want := exitCode, 3; got != want {
		t.Fatalf("RunApp() exitCode = %d, want %d", got, want)
	}
	if !strings.Contains(output, `"status": "unknown"`) {
		t.Fatalf("RunApp() output = %q, want JSON early error", output)
	}
}

func TestRunAppDispatchesTogglesBeforeRunningProbe(t *testing.T) {
	called := false
	exitCode, output := captureStdout(t, func() int {
		return RunApp(AppSpec[stubAppConfig, stubResult]{
			ProgramName:       "check_probe",
			Args:              nil,
			Probe:             "check_probe",
			DefaultBinaryName: "check_probe",
			Parse: func(string, []string) (stubAppConfig, error) {
				return stubAppConfig{showHelp: true}, nil
			},
			BuildToggles: func(_ string, cfg stubAppConfig) []ToggleAction {
				return []ToggleAction{{Enabled: cfg.showHelp, Output: "HELP\n", ExitCode: 0}}
			},
			Timeout: func(cfg stubAppConfig) time.Duration { return cfg.timeout },
			Run: func(context.Context, stubAppConfig) (stubResult, error) {
				called = true
				return stubResult{}, nil
			},
			UnknownExitCode: 3,
			OutputMode:      func(cfg stubAppConfig) checkreport.OutputMode { return cfg.outputMode },
			Verbosity:       func(cfg stubAppConfig) int { return cfg.verbosity },
		})
	})
	if got, want := exitCode, 0; got != want {
		t.Fatalf("RunApp() exitCode = %d, want %d", got, want)
	}
	if got, want := output, "HELP\n"; got != want {
		t.Fatalf("RunApp() output = %q, want %q", got, want)
	}
	if called {
		t.Fatal("RunApp() executed probe runner despite handled toggle")
	}
}

func TestRunAppRendersResultAndUsesVerbosity(t *testing.T) {
	exitCode, output := captureStdout(t, func() int {
		return RunApp(AppSpec[stubAppConfig, stubResult]{
			ProgramName:       "check_probe",
			Args:              nil,
			Probe:             "check_probe",
			DefaultBinaryName: "check_probe",
			Parse: func(string, []string) (stubAppConfig, error) {
				return stubAppConfig{timeout: time.Second, outputMode: checkreport.OutputNagios, verbosity: 1}, nil
			},
			Timeout: func(cfg stubAppConfig) time.Duration { return cfg.timeout },
			Run: func(context.Context, stubAppConfig) (stubResult, error) {
				return stubResult{summary: "SUMMARY", detail: "DETAIL", exit: 2}, nil
			},
			UnknownExitCode: 3,
			OutputMode:      func(cfg stubAppConfig) checkreport.OutputMode { return cfg.outputMode },
			Verbosity:       func(cfg stubAppConfig) int { return cfg.verbosity },
		})
	})
	if got, want := exitCode, 2; got != want {
		t.Fatalf("RunApp() exitCode = %d, want %d", got, want)
	}
	if got, want := output, "DETAIL"; got != want {
		t.Fatalf("RunApp() output = %q, want %q", got, want)
	}
}

func TestRunAppHandlesRunnerErrorUsingResolvedOutputMode(t *testing.T) {
	exitCode, output := captureStdout(t, func() int {
		return RunApp(AppSpec[stubAppConfig, stubResult]{
			ProgramName:       "check_probe",
			Args:              nil,
			Probe:             "check_probe",
			DefaultBinaryName: "check_probe",
			Parse: func(string, []string) (stubAppConfig, error) {
				return stubAppConfig{timeout: time.Second, outputMode: checkreport.OutputNagios}, nil
			},
			Timeout: func(cfg stubAppConfig) time.Duration { return cfg.timeout },
			Run: func(context.Context, stubAppConfig) (stubResult, error) {
				return stubResult{}, ErrInputRequired(InputRefHostname)
			},
			UnknownExitCode: 3,
			OutputMode:      func(cfg stubAppConfig) checkreport.OutputMode { return cfg.outputMode },
			Verbosity:       func(cfg stubAppConfig) int { return cfg.verbosity },
		})
	})
	if got, want := exitCode, 3; got != want {
		t.Fatalf("RunApp() exitCode = %d, want %d", got, want)
	}
	if got, want := output, "UNKNOWN - -H/--hostname is required\n"; got != want {
		t.Fatalf("RunApp() output = %q, want %q", got, want)
	}
}

func TestCommonFlagsRegisterAndResolve(t *testing.T) {
	fs, common, err := NewCommonFlagSet("check_probe", []string{"-vv", "--output", "json", "--timeout", "45s", "--ignore-errors", "slug_one"})
	if err != nil {
		t.Fatalf("NewCommonFlagSet() error = %v", err)
	}
	common.Register(fs, "30s")
	if err := fs.Parse(common.Args()); err != nil {
		t.Fatalf("FlagSet.Parse() error = %v", err)
	}

	opts, err := common.Resolve(func(slug string) bool { return slug == "slug_one" })
	if err != nil {
		t.Fatalf("CommonFlags.Resolve() error = %v", err)
	}
	if got, want := opts.Timeout.String(), "45s"; got != want {
		t.Fatalf("CommonFlags.Resolve() timeout = %q, want %q", got, want)
	}
	if got, want := opts.OutputMode, checkreport.OutputJSON; got != want {
		t.Fatalf("CommonFlags.Resolve() outputMode = %q, want %q", got, want)
	}
	if got, want := opts.Verbosity, 2; got != want {
		t.Fatalf("CommonFlags.Resolve() verbosity = %d, want %d", got, want)
	}
	if !opts.IgnoreErrorSet["slug_one"] {
		t.Fatalf("CommonFlags.Resolve() ignore set = %+v, want slug_one", opts.IgnoreErrorSet)
	}
}

func TestCommonFlagsResolveBareIntegerTimeoutAsSeconds(t *testing.T) {
	fs, common, err := NewCommonFlagSet("check_probe", []string{"--timeout", "45"})
	if err != nil {
		t.Fatalf("NewCommonFlagSet() error = %v", err)
	}
	common.Register(fs, "30s")
	if err := fs.Parse(common.Args()); err != nil {
		t.Fatalf("FlagSet.Parse() error = %v", err)
	}

	opts, err := common.Resolve(func(string) bool { return true })
	if err != nil {
		t.Fatalf("CommonFlags.Resolve() error = %v", err)
	}
	if got, want := opts.Timeout, 45*time.Second; got != want {
		t.Fatalf("CommonFlags.Resolve() timeout = %v, want %v", got, want)
	}
}

func captureStdout(t *testing.T, run func() int) (int, string) {
	t.Helper()

	var b strings.Builder
	orig := stdoutWriter
	stdoutWriter = &b
	defer func() { stdoutWriter = orig }()

	exitCode := run()
	return exitCode, b.String()
}

func TestCommonFlagsRejectUnknownIgnoredSlug(t *testing.T) {
	fs, common, err := NewCommonFlagSet("check_probe", []string{"--ignore-errors", "bad"})
	if err != nil {
		t.Fatalf("NewCommonFlagSet() error = %v", err)
	}
	common.Register(fs, "30s")
	if err := fs.Parse(common.Args()); err != nil {
		t.Fatalf("FlagSet.Parse() error = %v", err)
	}
	if _, err := common.Resolve(func(string) bool { return false }); err == nil || !strings.Contains(err.Error(), `unknown ignored error slug "bad"`) {
		t.Fatalf("CommonFlags.Resolve() error = %v, want unknown slug error", err)
	}
}

func TestCommonFlagsSetOutputDiscard(t *testing.T) {
	fs, _, err := NewCommonFlagSet("check_probe", nil)
	if err != nil {
		t.Fatalf("NewCommonFlagSet() error = %v", err)
	}
	if got, want := fs.ErrorHandling(), flag.ContinueOnError; got != want {
		t.Fatalf("FlagSet.ErrorHandling() = %v, want %v", got, want)
	}
}

func TestParserRegistersProbeSpecificInputsAndResolvesCommonOptions(t *testing.T) {
	parser, err := NewParser("check_probe", []string{"-H", "example.com", "--rrtype", "TXT", "--output", "json", "-vv"})
	if err != nil {
		t.Fatalf("NewParser() error = %v", err)
	}
	parser.RegisterCommon("30s")
	if err := parser.RegisterInputs(
		InputSpec{
			Key:  "hostname",
			Type: InputString,
			Aliases: []InputAlias{
				{Short: "H", Usage: "hostname"},
				{Long: "hostname", Usage: "hostname"},
			},
		},
		InputSpec{
			Key:     "rrtype",
			Type:    InputString,
			Aliases: []InputAlias{{Long: "rrtype", Usage: "rrtype"}},
		},
	); err != nil {
		t.Fatalf("RegisterInputs() error = %v", err)
	}

	common, inputs, err := parser.Parse(func(string) bool { return true }, nil)
	if err != nil {
		t.Fatalf("Parser.Parse() error = %v", err)
	}
	if got, want := inputs.String("hostname"), "example.com"; got != want {
		t.Fatalf("inputs.String(hostname) = %q, want %q", got, want)
	}
	if got, want := inputs.String("rrtype"), "TXT"; got != want {
		t.Fatalf("inputs.String(rrtype) = %q, want %q", got, want)
	}
	if got, want := common.OutputMode, checkreport.OutputJSON; got != want {
		t.Fatalf("common.OutputMode = %q, want %q", got, want)
	}
	if got, want := common.Verbosity, 2; got != want {
		t.Fatalf("common.Verbosity = %d, want %d", got, want)
	}
}

func TestParserSupportsDefaultsAndValidation(t *testing.T) {
	parser, err := NewParser("check_probe", []string{"--mode", "bad"})
	if err != nil {
		t.Fatalf("NewParser() error = %v", err)
	}
	parser.RegisterCommon("30s")
	if err := parser.RegisterInputs(
		InputSpec{
			Key:     "mode",
			Type:    InputString,
			Default: "any",
			Aliases: []InputAlias{{Long: "mode", Usage: "mode"}},
		},
		InputSpec{
			Key:     "enabled",
			Type:    InputBool,
			Default: "true",
			Aliases: []InputAlias{{Long: "enabled", Usage: "enabled"}},
		},
		InputSpec{
			Key:     "retries",
			Type:    InputInt,
			Default: "2",
			Aliases: []InputAlias{{Long: "retries", Usage: "retries"}},
		},
	); err != nil {
		t.Fatalf("RegisterInputs() error = %v", err)
	}

	_, _, err = parser.Parse(func(string) bool { return true }, func(inputs *Inputs) error {
		if inputs.String("mode") != "any" && inputs.String("mode") != "all" {
			return fmt.Errorf("bad mode %q", inputs.String("mode"))
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), `bad mode "bad"`) {
		t.Fatalf("Parser.Parse() error = %v, want validation failure", err)
	}

	parser, err = NewParser("check_probe", nil)
	if err != nil {
		t.Fatalf("NewParser() error = %v", err)
	}
	parser.RegisterCommon("30s")
	if err := parser.RegisterInputs(
		InputSpec{
			Key:     "enabled",
			Type:    InputBool,
			Default: "true",
			Aliases: []InputAlias{{Long: "enabled", Usage: "enabled"}},
		},
		InputSpec{
			Key:     "retries",
			Type:    InputInt,
			Default: "2",
			Aliases: []InputAlias{{Long: "retries", Usage: "retries"}},
		},
	); err != nil {
		t.Fatalf("RegisterInputs() error = %v", err)
	}
	_, inputs, err := parser.Parse(func(string) bool { return true }, nil)
	if err != nil {
		t.Fatalf("Parser.Parse() error = %v", err)
	}
	if !inputs.Bool("enabled") {
		t.Fatalf("inputs.Bool(enabled) = false, want true")
	}
	if got, want := inputs.Int("retries"), 2; got != want {
		t.Fatalf("inputs.Int(retries) = %d, want %d", got, want)
	}
}

func TestResolveDNSTargetInput(t *testing.T) {
	target, err := ResolveDNSTargetInput(DNSTargetInput{
		Hostname:      "www.example.com.",
		RRType:        "A",
		RequireRRType: true,
	})
	if err != nil {
		t.Fatalf("ResolveDNSTargetInput() error = %v", err)
	}
	if got, want := target.Mode, DNSTargetHostname; got != want {
		t.Fatalf("target.Mode = %q, want %q", got, want)
	}
	if got, want := target.Target, "www.example.com"; got != want {
		t.Fatalf("target.Target = %q, want %q", got, want)
	}
	if got, want := target.Owner, "www.example.com"; got != want {
		t.Fatalf("target.Owner = %q, want %q", got, want)
	}
	if got, want := target.RRTypeRaw, "A"; got != want {
		t.Fatalf("target.RRTypeRaw = %q, want %q", got, want)
	}

	target, err = ResolveDNSTargetInput(DNSTargetInput{
		Zone:  "example.com.",
		Owner: "_dmarc.example.com.",
	})
	if err != nil {
		t.Fatalf("ResolveDNSTargetInput() zone error = %v", err)
	}
	if got, want := target.Mode, DNSTargetZone; got != want {
		t.Fatalf("target.Mode = %q, want %q", got, want)
	}
	if got, want := target.Target, "example.com"; got != want {
		t.Fatalf("target.Target = %q, want %q", got, want)
	}
	if got, want := target.Owner, "_dmarc.example.com"; got != want {
		t.Fatalf("target.Owner = %q, want %q", got, want)
	}
}

func TestResolveDNSTargetInputRejectsMissingOrBadRRType(t *testing.T) {
	_, err := ResolveDNSTargetInput(DNSTargetInput{})
	if err == nil || !strings.Contains(err.Error(), "either -H/--hostname or --zone is required") {
		t.Fatalf("ResolveDNSTargetInput() error = %v, want missing target error", err)
	}

	_, err = ResolveDNSTargetInput(DNSTargetInput{Hostname: "example.com", RequireRRType: true})
	if err == nil || !strings.Contains(err.Error(), "--rrtype is required") {
		t.Fatalf("ResolveDNSTargetInput() error = %v, want missing rrtype error", err)
	}

	_, err = ResolveDNSTargetInput(DNSTargetInput{Hostname: "example.com", RRType: "BAD", RequireRRType: true})
	if err == nil || !strings.Contains(err.Error(), `unsupported --rrtype "BAD"`) {
		t.Fatalf("ResolveDNSTargetInput() error = %v, want unsupported rrtype error", err)
	}
}

func TestResolveServiceTargetInput(t *testing.T) {
	target, err := ResolveServiceTargetInput(ServiceTargetInput{
		Hostname: "www.example.com.",
		Port:     443,
	})
	if err != nil {
		t.Fatalf("ResolveServiceTargetInput() error = %v", err)
	}
	if got, want := target.Hostname, "www.example.com"; got != want {
		t.Fatalf("target.Hostname = %q, want %q", got, want)
	}
	if got, want := target.Service, "www.example.com:443"; got != want {
		t.Fatalf("target.Service = %q, want %q", got, want)
	}
}

func TestResolveServiceTargetInputRejectsMissingOrBadPort(t *testing.T) {
	_, err := ResolveServiceTargetInput(ServiceTargetInput{})
	if err == nil || !strings.Contains(err.Error(), "-H/--hostname is required") {
		t.Fatalf("ResolveServiceTargetInput() error = %v, want missing hostname error", err)
	}
	_, err = ResolveServiceTargetInput(ServiceTargetInput{Hostname: "example.com", Port: 0})
	if err == nil || !strings.Contains(err.Error(), "--port must be in range 1..65535") {
		t.Fatalf("ResolveServiceTargetInput() error = %v, want bad port error", err)
	}
}

func TestServiceTargetInputSpecs(t *testing.T) {
	specs := ServiceTargetInputSpecs(443)
	if got, want := len(specs), 2; got != want {
		t.Fatalf("len(ServiceTargetInputSpecs()) = %d, want %d", got, want)
	}
	if got, want := specs[0].Key, "hostname"; got != want {
		t.Fatalf("specs[0].Key = %q, want %q", got, want)
	}
	if got, want := specs[1].Key, "port"; got != want {
		t.Fatalf("specs[1].Key = %q, want %q", got, want)
	}
	if got, want := specs[1].Default, "443"; got != want {
		t.Fatalf("specs[1].Default = %q, want %q", got, want)
	}
}

func TestDecodeHelpers(t *testing.T) {
	parser, err := NewParser("check_probe", []string{
		"--mode", "all",
		"--timeout-like", "1500ms",
		"--list", "a, b,,c",
	})
	if err != nil {
		t.Fatalf("NewParser() error = %v", err)
	}
	parser.RegisterCommon("30s")
	if err := parser.RegisterInputs(
		InputSpec{Key: "mode", Type: InputString, Aliases: []InputAlias{{Long: "mode", Usage: "mode"}}},
		InputSpec{Key: "timeout_like", Type: InputString, Aliases: []InputAlias{{Long: "timeout-like", Usage: "timeout"}}},
		InputSpec{Key: "list", Type: InputString, Aliases: []InputAlias{{Long: "list", Usage: "list"}}},
	); err != nil {
		t.Fatalf("RegisterInputs() error = %v", err)
	}
	_, inputs, err := parser.Parse(func(string) bool { return true }, nil)
	if err != nil {
		t.Fatalf("Parser.Parse() error = %v", err)
	}

	mode, err := DecodeEnumInput(inputs, "mode", InputRefMode, []string{"any", "all"}, func(raw string) (string, error) {
		if raw == "any" || raw == "all" {
			return raw, nil
		}
		return "", fmt.Errorf("bad")
	})
	if err != nil {
		t.Fatalf("DecodeEnumInput() error = %v", err)
	}
	if got, want := mode, "all"; got != want {
		t.Fatalf("DecodeEnumInput() = %q, want %q", got, want)
	}

	timeout, err := DecodeTimeoutInput(inputs, "timeout_like", InputRefTimeout)
	if err != nil {
		t.Fatalf("DecodeTimeoutInput() error = %v", err)
	}
	if got, want := timeout, 1500*time.Millisecond; got != want {
		t.Fatalf("DecodeTimeoutInput() = %v, want %v", got, want)
	}

	items := DecodeCSVInput(inputs, "list")
	if got, want := strings.Join(items, ","), "a,b,c"; got != want {
		t.Fatalf("DecodeCSVInput() = %q, want %q", got, want)
	}

	if err := ValidateMinInt(-1, InputRefWarnExpiry, 0); err == nil || !strings.Contains(err.Error(), "--warn-expiry-days must be >= 0") {
		t.Fatalf("ValidateMinInt() error = %v, want constraint error", err)
	}
}

func TestDecodeTimeoutInputTreatsBareIntegersAsSeconds(t *testing.T) {
	parser, err := NewParser("check_probe", []string{"--timeout-like", "12"})
	if err != nil {
		t.Fatalf("NewParser() error = %v", err)
	}
	parser.RegisterCommon("30s")
	if err := parser.RegisterInputs(
		InputSpec{Key: "timeout_like", Type: InputString, Aliases: []InputAlias{{Long: "timeout-like", Usage: "timeout"}}},
	); err != nil {
		t.Fatalf("RegisterInputs() error = %v", err)
	}
	_, inputs, err := parser.Parse(func(string) bool { return true }, nil)
	if err != nil {
		t.Fatalf("Parser.Parse() error = %v", err)
	}

	timeout, err := DecodeTimeoutInput(inputs, "timeout_like", InputRefTimeout)
	if err != nil {
		t.Fatalf("DecodeTimeoutInput() error = %v", err)
	}
	if got, want := timeout, 12*time.Second; got != want {
		t.Fatalf("DecodeTimeoutInput() = %v, want %v", got, want)
	}
}
