package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSourceDateEpoch(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1793062620")
	got, err := sourceDateEpoch()
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Unix(1793062620, 0).UTC(); !got.Equal(want) {
		t.Fatalf("sourceDateEpoch() = %s, want %s", got, want)
	}
	t.Setenv("SOURCE_DATE_EPOCH", "invalid")
	if _, err := sourceDateEpoch(); err == nil {
		t.Fatal("invalid SOURCE_DATE_EPOCH should fail")
	}
}

func TestRunChangelogPreservesHistory(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1793062620")
	path := filepath.Join(t.TempDir(), "changelog")
	old := "habr-nagios-plugins (1.0.0-1) unstable; urgency=medium\n\n -- Maintainer <m@example.org>  Fri, 12 Jun 2026 12:00:00 +0000\n"
	if err := os.WriteFile(path, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	args := []string{"--output", path, "--version", "v1.1.0"}
	if err := runChangelog(args); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "habr-nagios-plugins (1.1.0-1)") || !strings.Contains(string(data), old) {
		t.Fatalf("changelog did not preserve history: %s", data)
	}
	if err := runChangelog(args); err == nil {
		t.Fatal("duplicate changelog version should be rejected")
	}
}
