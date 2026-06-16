package clihelp

import (
	"strings"
	"testing"
)

func TestRenderDocument(t *testing.T) {
	out := RenderDocument(Document{
		ProgramName: "check_example",
		Summary:     "Example summary",
		Usage: []string{
			"check_example -H example.com [options]",
			"check_example --mode test [options]",
		},
		Options: []Option{
			{Short: "-h", Long: "--help", Description: "Show help"},
			{Long: "--mode", Description: "Mode selector", Examples: []string{"--mode test"}},
		},
	})

	for _, snippet := range []string{
		"check_example",
		"Example summary",
		"Usage:\n  check_example -H example.com [options]",
		"Options:\n",
		"-h, --help",
		"Show help",
		"e.g. --mode test",
	} {
		if !strings.Contains(out, snippet) {
			t.Fatalf("RenderDocument() output missing %q in:\n%s", snippet, out)
		}
	}
}
