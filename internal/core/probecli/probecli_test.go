package probecli

import (
	"strings"
	"testing"
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
