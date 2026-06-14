package probecli

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"
)

type ErrorSlugDescriptor struct {
	Slug     string
	Category string
	Severity string
	Message  string
}

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
