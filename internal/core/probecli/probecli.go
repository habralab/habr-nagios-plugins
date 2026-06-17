package probecli

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/buildinfo"
	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/core/msgcatalog"
	"github.com/habralab/habr-nagios-plugins/internal/core/verbosity"
)

type ErrorSlugDescriptor struct {
	Slug     string
	Category string
	Severity string
	Message  string
}

type ResultOutput interface {
	JSON() ([]byte, error)
	Summary() string
	Detail() string
	ExitCode() int
}

type ToggleAction struct {
	Enabled  bool
	Output   string
	ExitCode int
}

type AppSpec[C any, R ResultOutput] struct {
	ProgramName       string
	Args              []string
	Probe             string
	DefaultBinaryName string
	Parse             func(binName string, args []string) (C, error)
	BuildToggles      func(binName string, cfg C) []ToggleAction
	Timeout           func(cfg C) time.Duration
	Run               func(ctx context.Context, cfg C) (R, error)
	UnknownExitCode   int
	OutputMode        func(cfg C) checkreport.OutputMode
	Verbosity         func(cfg C) int
	DecorateReport    func(ctx context.Context, cfg C, report *checkreport.Report)
}

type CommonFlags struct {
	normalizedArgs  []string
	baseVerbosity   int
	Timeout         string
	Output          string
	CacheBackend    string
	IgnoreErrorsRaw string
	Verbosity       int
	ShowHelp        bool
	ShowVersion     bool
	ShowErrorSlugs  bool
}

type CommonOptions struct {
	Timeout        time.Duration
	OutputMode     checkreport.OutputMode
	CacheBackend   string
	IgnoreErrors   []string
	IgnoreErrorSet map[string]bool
	Verbosity      int
	ShowHelp       bool
	ShowVersion    bool
	ShowErrorSlugs bool
}

var stdoutWriter io.Writer

func outputWriter() io.Writer {
	if stdoutWriter != nil {
		return stdoutWriter
	}
	return os.Stdout
}

func IgnoreErrorsOptionDescription() string {
	return "Comma-separated finding slugs to suppress from status aggregation.\n" +
		"Use --list-error-slugs to see the available values."
}

func ListErrorSlugsOptionDescription() string {
	return "Print the available suppressible error slugs with category, default severity, and message, then exit."
}

func HelpOptionDescription() string {
	return msgcatalog.DefaultSummaryOrKey("common_help_show_help")
}

func VersionOptionDescription() string {
	return msgcatalog.DefaultSummaryOrKey("common_help_show_version")
}

func VerboseOptionDescription() string {
	return msgcatalog.DefaultSummaryOrKey("common_help_verbose")
}

func TimeoutOptionDescription(defaultValue string) string {
	return msgcatalog.DefaultSummaryOrKey("common_help_timeout_prefix") + "\nDefault: " + strings.TrimSpace(defaultValue) + ".\nBare integers are interpreted as seconds."
}

func OutputModeOptionDescription(jsonLine string) string {
	return msgcatalog.DefaultSummaryOrKey("common_help_output_prefix") + "\n" +
		msgcatalog.DefaultSummaryOrKey("common_help_output_nagios") + "\n" +
		strings.TrimSpace(jsonLine) + "\n" +
		"Default: nagios."
}

func CacheBackendOptionDescription() string {
	return "Optional shared cache backend DSN.\n" +
		"internal:// keeps only per-run in-process cache state.\n" +
		"redis://host:port[/db] uses Redis over TCP.\n" +
		"redis+unix:///path/to/redis.sock?db=N uses Redis over a Unix socket.\n" +
		"Unsupported or unreachable backends are reported in runtime diagnostics and do not change probe status."
}

func EffectiveProgramName(programName, defaultBinaryName string) string {
	name := strings.TrimSpace(filepath.Base(programName))
	if name == "" || name == "." || name == string(filepath.Separator) {
		return defaultBinaryName
	}
	return name
}

func NewCommonFlagSet(binName string, args []string) (*flag.FlagSet, *CommonFlags, error) {
	normalizedArgs, baseVerbosity, err := verbosity.NormalizeArgs(args)
	if err != nil {
		return nil, nil, err
	}

	fs := flag.NewFlagSet(binName, flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	return fs, &CommonFlags{
		normalizedArgs: normalizedArgs,
		baseVerbosity:  baseVerbosity,
	}, nil
}

func (f *CommonFlags) Args() []string {
	return f.normalizedArgs
}

func (f *CommonFlags) Register(fs *flag.FlagSet, defaultTimeout string) {
	fs.StringVar(&f.Timeout, "t", defaultTimeout, "overall timeout")
	fs.StringVar(&f.Timeout, "timeout", defaultTimeout, "overall timeout")
	fs.StringVar(&f.Output, "output", "nagios", "output mode: nagios|json")
	fs.StringVar(&f.CacheBackend, "cache-backend", "", "shared cache backend DSN")
	fs.StringVar(&f.IgnoreErrorsRaw, "ignore-errors", "", "comma-separated error slugs to suppress")
	fs.IntVar(&f.Verbosity, "v", 0, "verbosity level 0..3")
	fs.IntVar(&f.Verbosity, "verbose", 0, "verbosity level 0..3")
	fs.BoolVar(&f.ShowHelp, "h", false, "show help")
	fs.BoolVar(&f.ShowHelp, "help", false, "show help")
	fs.BoolVar(&f.ShowErrorSlugs, "list-error-slugs", false, "list suppressible error slugs and exit")
	fs.BoolVar(&f.ShowVersion, "V", false, "show version")
	fs.BoolVar(&f.ShowVersion, "version", false, "show version")
}

func (f *CommonFlags) Resolve(hasSlug func(string) bool) (CommonOptions, error) {
	timeout, err := ParseTimeout(f.Timeout, "--timeout")
	if err != nil {
		return CommonOptions{}, err
	}
	outputMode, err := ParseOutputMode(f.Output)
	if err != nil {
		return CommonOptions{}, err
	}
	ignoreErrors, ignoreErrorSet, err := BuildIgnoreErrorSet(f.IgnoreErrorsRaw, hasSlug)
	if err != nil {
		return CommonOptions{}, err
	}

	return CommonOptions{
		Timeout:        timeout,
		OutputMode:     outputMode,
		CacheBackend:   strings.TrimSpace(f.CacheBackend),
		IgnoreErrors:   ignoreErrors,
		IgnoreErrorSet: ignoreErrorSet,
		Verbosity:      verbosity.Clamp(f.baseVerbosity + f.Verbosity),
		ShowHelp:       f.ShowHelp,
		ShowVersion:    f.ShowVersion,
		ShowErrorSlugs: f.ShowErrorSlugs,
	}, nil
}

func ParseTimeout(raw, flagName string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if seconds, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return time.Duration(seconds) * time.Second, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", flagName, err)
	}
	return d, nil
}

func SplitCSV(raw string) []string {
	if raw == "" {
		return nil
	}
	items := strings.Split(raw, ",")
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		out = append(out, item)
	}
	return out
}

func BuildIgnoreErrorSet(raw string, hasSlug func(string) bool) ([]string, map[string]bool, error) {
	items := SplitCSV(raw)
	out := make(map[string]bool, len(items))
	for _, item := range items {
		if !hasSlug(item) {
			return nil, nil, fmt.Errorf("unknown ignored error slug %q", item)
		}
		out[item] = true
	}
	return items, out, nil
}

func RenderErrorSlugDescriptors(items []ErrorSlugDescriptor) string {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	for _, item := range items {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", item.Slug, emptyDescriptorField(item.Category), emptyDescriptorField(item.Severity), emptyDescriptorField(item.Message))
	}
	_ = w.Flush()
	return buf.String()
}

func emptyDescriptorField(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func DetectOutputMode(args []string) checkreport.OutputMode {
	for i := 0; i < len(args); i++ {
		arg := strings.TrimSpace(args[i])
		if arg == "" {
			continue
		}
		if arg == "--output" && i+1 < len(args) {
			if strings.EqualFold(strings.TrimSpace(args[i+1]), string(checkreport.OutputJSON)) {
				return checkreport.OutputJSON
			}
			continue
		}
		if value, ok := strings.CutPrefix(arg, "--output="); ok {
			if strings.EqualFold(strings.TrimSpace(value), string(checkreport.OutputJSON)) {
				return checkreport.OutputJSON
			}
		}
	}
	return checkreport.OutputNagios
}

func ParseOutputMode(raw string) (checkreport.OutputMode, error) {
	switch strings.TrimSpace(strings.ToLower(raw)) {
	case "", string(checkreport.OutputNagios):
		return checkreport.OutputNagios, nil
	case string(checkreport.OutputJSON):
		return checkreport.OutputJSON, nil
	default:
		return "", ErrInvalidEnum(InputRefOutput, raw, "nagios", "json")
	}
}

func RenderEarlyError(probe, target string, outputMode checkreport.OutputMode, err error) string {
	message := FormatInputError(err, DefaultInputLabels())
	if outputMode == checkreport.OutputJSON {
		data, jsonErr := checkreport.EarlyErrorReport(probe, target, message, outputMode).JSON()
		if jsonErr == nil {
			return string(data) + "\n"
		}
		return fmt.Sprintf("{\"probe\":%q,\"status\":\"unknown\",\"summary\":%q}\n", probe, message)
	}
	return fmt.Sprintf("UNKNOWN - %s\n", message)
}

func RenderResult(result ResultOutput, outputMode checkreport.OutputMode, verbosity int) (string, int, error) {
	if outputMode == checkreport.OutputJSON {
		data, err := result.JSON()
		if err != nil {
			return "", 3, fmt.Errorf("failed to encode JSON output: %w", err)
		}
		return string(data) + "\n", result.ExitCode(), nil
	}
	if verbosity > 0 {
		return result.Detail(), result.ExitCode(), nil
	}
	return result.Summary() + "\n", result.ExitCode(), nil
}

func DispatchToggleActions(actions ...ToggleAction) (string, int, bool) {
	for _, action := range actions {
		if action.Enabled {
			return action.Output, action.ExitCode, true
		}
	}
	return "", 0, false
}

func VersionAction(binName string, enabled bool, exitCode int) ToggleAction {
	return ToggleAction{
		Enabled:  enabled,
		Output:   buildinfo.String(binName) + "\n",
		ExitCode: exitCode,
	}
}

func RunApp[C any, R ResultOutput](spec AppSpec[C, R]) int {
	binName := EffectiveProgramName(spec.ProgramName, spec.DefaultBinaryName)
	requestedOutputMode := DetectOutputMode(spec.Args)

	cfg, err := spec.Parse(binName, spec.Args)
	if err != nil {
		fmt.Fprint(outputWriter(), RenderEarlyError(spec.Probe, "", requestedOutputMode, err))
		return spec.UnknownExitCode
	}

	if spec.BuildToggles != nil {
		if output, exitCode, handled := DispatchToggleActions(spec.BuildToggles(binName, cfg)...); handled {
			fmt.Fprint(outputWriter(), output)
			return exitCode
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), spec.Timeout(cfg))
	defer cancel()

	result, err := spec.Run(ctx, cfg)
	if err != nil {
		fmt.Fprint(outputWriter(), RenderEarlyError(spec.Probe, "", spec.OutputMode(cfg), err))
		return spec.UnknownExitCode
	}
	if spec.DecorateReport != nil {
		if carrier, ok := any(result).(interface{ ProbeReport() *checkreport.Report }); ok {
			spec.DecorateReport(ctx, cfg, carrier.ProbeReport())
		}
	}

	rendered, exitCode, err := RenderResult(result, spec.OutputMode(cfg), spec.Verbosity(cfg))
	if err != nil {
		fmt.Fprintf(outputWriter(), "UNKNOWN - %v\n", err)
		return spec.UnknownExitCode
	}
	fmt.Fprint(outputWriter(), rendered)
	return exitCode
}
