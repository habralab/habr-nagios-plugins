package probecli

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

func EffectiveProgramName(programName, defaultBinaryName string) string {
	name := strings.TrimSpace(filepath.Base(programName))
	if name == "" || name == "." || name == string(filepath.Separator) {
		return defaultBinaryName
	}
	return name
}

func ParseTimeout(raw, flagName string) (time.Duration, error) {
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
