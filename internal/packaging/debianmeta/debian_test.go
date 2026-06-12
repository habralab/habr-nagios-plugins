package debianmeta

import (
	"strings"
	"testing"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/packaging/catalog"
)

func TestDebianUpstreamVersion(t *testing.T) {
	now := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)

	tests := []struct {
		version string
		commit  string
		want    string
	}{
		{version: "v1.2.3", commit: "abc123", want: "1.2.3"},
		{version: "1.2.3", commit: "abc123", want: "1.2.3"},
		{version: "packaging", commit: "abc123-dirty", want: "0~git20260612.abc123dirty"},
		{version: "", commit: "unknown", want: "0~git20260612.nogit"},
	}

	for _, tt := range tests {
		if got := DebianUpstreamVersion(tt.version, tt.commit, now); got != tt.want {
			t.Fatalf("DebianUpstreamVersion(%q, %q) = %q, want %q", tt.version, tt.commit, got, tt.want)
		}
	}
}

func TestRenderIncludesProbeInstallName(t *testing.T) {
	spec := BuildSpec(Options{
		Version:     "v1.0.0",
		Commit:      "abc123",
		GeneratedAt: time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC),
	}, catalog.All)

	files, err := Render(spec)
	if err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	var install string
	var docs string
	for _, file := range files {
		switch file.Path {
		case "debian/habr-nagios-plugin-sitemap.install":
			install = file.Content
		case "debian/habr-nagios-plugin-sitemap.docs":
			docs = file.Content
		}
	}

	if !strings.Contains(install, "build/check_habr_sitemap usr/lib/nagios/plugins/") {
		t.Fatalf("install missing direct namespaced binary mapping:\n%s", install)
	}
	if !strings.Contains(docs, "README.md") || !strings.Contains(docs, "LICENSE") {
		t.Fatalf("docs file missing expected entries:\n%s", docs)
	}
}

func TestBuildSpecUsesSafeDefaultMaintainerEmail(t *testing.T) {
	spec := BuildSpec(Options{
		Version:     "v1.0.0",
		GeneratedAt: time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC),
	}, catalog.All)

	if !strings.Contains(spec.Maintainer, "<builder@example.org>") {
		t.Fatalf("unexpected maintainer fallback: %q", spec.Maintainer)
	}
}

func TestRenderChangelogIncludesVersionAndMaintainer(t *testing.T) {
	spec := BuildSpec(Options{
		Version:         "v1.0.0",
		MaintainerName:  "Maintainer Example",
		MaintainerEmail: "maintainer@example.org",
		GeneratedAt:     time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC),
	}, catalog.All)

	changelog := RenderChangelog(spec)
	if !strings.Contains(changelog, "habr-nagios-plugins (1.0.0-1)") {
		t.Fatalf("changelog missing version:\n%s", changelog)
	}
	if !strings.Contains(changelog, "Maintainer Example <maintainer@example.org>") {
		t.Fatalf("changelog missing maintainer:\n%s", changelog)
	}
}
