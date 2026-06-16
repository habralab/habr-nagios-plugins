package probecli

import (
	"flag"
	"fmt"
	"strings"
	"testing"

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
	if got := OutputModeOptionDescription("json emits the structured report."); !strings.Contains(got, "nagios emits classic monitoring text.") {
		t.Fatalf("OutputModeOptionDescription() = %q, want shared nagios line", got)
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
