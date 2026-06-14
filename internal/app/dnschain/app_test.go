package dnschainapp

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/probe/dnschain"
)

const testProgramName = "check_dnschain"

func TestParseFlagsSupportsJSONOutput(t *testing.T) {
	cfg, showHelp, showVersion, err := parseFlags(testProgramName, []string{
		"-H", "www.example.com",
		"--output", "json",
		"--timeout", "45s",
		"--query-timeout", "2s",
		"--verbose=2",
	})
	if err != nil {
		t.Fatalf("parseFlags() error = %v", err)
	}
	if showHelp {
		t.Fatalf("showHelp = true, want false")
	}
	if showVersion {
		t.Fatalf("showVersion = true, want false")
	}
	if got, want := string(cfg.OutputMode), "json"; got != want {
		t.Fatalf("OutputMode = %q, want %q", got, want)
	}
	if got, want := cfg.Verbosity, 2; got != want {
		t.Fatalf("Verbosity = %d, want %d", got, want)
	}
	if got, want := cfg.QueryTimeout.String(), "2s"; got != want {
		t.Fatalf("QueryTimeout = %q, want %q", got, want)
	}
}

func TestParseFlagsSupportsIgnoreErrors(t *testing.T) {
	cfg, showHelp, showVersion, err := parseFlags(testProgramName, []string{
		"--zone", "example.com",
		"--ignore-errors", "dnschain_child_soa_inconsistent,dnschain_nsec3param_not_recommended",
	})
	if err != nil {
		t.Fatalf("parseFlags() error = %v", err)
	}
	if showHelp || showVersion {
		t.Fatalf("unexpected help/version flags: help=%t version=%t", showHelp, showVersion)
	}
	if got, want := len(cfg.IgnoreErrors), 2; got != want {
		t.Fatalf("IgnoreErrors len = %d, want %d", got, want)
	}
	if !cfg.IgnoreErrorSet["dnschain_child_soa_inconsistent"] || !cfg.IgnoreErrorSet["dnschain_nsec3param_not_recommended"] {
		t.Fatalf("IgnoreErrorSet missing expected slugs: %+v", cfg.IgnoreErrorSet)
	}
}

func TestParseFlagsListErrorSlugs(t *testing.T) {
	cfg, showHelp, showVersion, err := parseFlags(testProgramName, []string{"--list-error-slugs"})
	if err != nil {
		t.Fatalf("parseFlags() error = %v", err)
	}
	if showHelp || showVersion {
		t.Fatalf("unexpected help/version flags: help=%t version=%t", showHelp, showVersion)
	}
	if !cfg.ShowErrorSlugs {
		t.Fatalf("ShowErrorSlugs = false, want true")
	}
}

func TestParseFlagsRejectsUnknownIgnoredSlug(t *testing.T) {
	_, _, _, err := parseFlags(testProgramName, []string{
		"--zone", "example.com",
		"--ignore-errors", "unknown_slug",
	})
	if err == nil || !strings.Contains(err.Error(), `unknown ignored error slug "unknown_slug"`) {
		t.Fatalf("parseFlags() error = %v, want unknown slug error", err)
	}
}

func TestRunJSONOutput(t *testing.T) {
	prev := dnschain.DefaultAnalyzerFactory
	dnschain.DefaultAnalyzerFactory = func() dnschain.Analyzer { return placeholderAnalyzerShim{} }
	defer func() { dnschain.DefaultAnalyzerFactory = prev }()

	exitCode, output := runWithCapturedStdout(t, testProgramName, []string{
		"-H", "www.example.com",
		"--output", "json",
	})
	if exitCode != 3 {
		t.Fatalf("Run() exitCode = %d, want 3", exitCode)
	}
	for _, snippet := range []string{
		`"probe": "dnschain"`,
		`"status": "unknown"`,
		`"id": "engine.status"`,
	} {
		if !strings.Contains(output, snippet) {
			t.Fatalf("Run() output missing %q in:\n%s", snippet, output)
		}
	}
}

func TestRunHelpMentionsStructuredOutputs(t *testing.T) {
	exitCode, output := runWithCapturedStdout(t, "check_habr_dnschain", []string{"--help"})
	if exitCode != 0 {
		t.Fatalf("Run() exitCode = %d, want 0", exitCode)
	}
	for _, snippet := range []string{
		"nagios emits classic monitoring text.",
		"json emits the structured waterfall report for external renderers.",
		"Per-DNS-exchange timeout.",
		"Use --list-error-slugs to see the available values.",
		"check_habr_dnschain",
	} {
		if !strings.Contains(output, snippet) {
			t.Fatalf("Run() help output missing %q in:\n%s", snippet, output)
		}
	}
}

func TestRunListErrorSlugs(t *testing.T) {
	exitCode, output := runWithCapturedStdout(t, testProgramName, []string{"--list-error-slugs"})
	if exitCode != 0 {
		t.Fatalf("Run() exitCode = %d, want 0", exitCode)
	}
	for _, snippet := range []string{
		"dnschain_child_soa_inconsistent",
		"consistency",
		"dnschain_ds_dnskey_mismatch",
		"dnssec",
	} {
		if !strings.Contains(output, snippet) {
			t.Fatalf("Run() output missing %q in:\n%s", snippet, output)
		}
	}
}

type placeholderAnalyzerShim struct{}

func (placeholderAnalyzerShim) Analyze(ctx context.Context, cfg dnschain.Config, target string) (checkreport.Report, error) {
	return checkreport.Report{
		Probe:         dnschain.Meta.Slug,
		Target:        target,
		PrimaryTarget: target,
		Status:        checkreport.StatusUnknown,
		Summary:       "dnschain placeholder analyzer was used instead of the live authoritative engine",
		Stages: []checkreport.Stage{
			{
				ID:     "engine.status",
				Title:  "Engine Status",
				Status: checkreport.StatusUnknown,
			},
		},
	}, nil
}

func runWithCapturedStdout(t *testing.T, programName string, args []string) (int, string) {
	t.Helper()

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	defer r.Close()
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	exitCode := Run(programName, args)
	w.Close()

	var out bytes.Buffer
	if _, err := io.Copy(&out, r); err != nil {
		t.Fatalf("io.Copy() error = %v", err)
	}
	return exitCode, out.String()
}
