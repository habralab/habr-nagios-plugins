package probecli

import (
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
