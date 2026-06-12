package clihelp

import (
	"fmt"
	"sort"
	"strings"
)

type Option struct {
	Short       string
	Long        string
	Name        string
	Description string
	Examples    []string
}

func RenderOptions(options []Option) string {
	items := append([]Option(nil), options...)
	sort.Slice(items, func(i, j int) bool {
		return items[i].sortKey() < items[j].sortKey()
	})

	width := 0
	for _, item := range items {
		if l := len(item.label()); l > width {
			width = l
		}
	}

	var b strings.Builder
	for _, item := range items {
		descLines := splitLines(item.Description)
		if len(descLines) == 0 {
			descLines = []string{""}
		}
		fmt.Fprintf(&b, "  %-*s  %s\n", width, item.label(), descLines[0])
		for _, line := range descLines[1:] {
			fmt.Fprintf(&b, "  %-*s  %s\n", width, "", line)
		}
		for _, example := range item.Examples {
			fmt.Fprintf(&b, "  %-*s  e.g. %s\n", width, "", example)
		}
	}
	return b.String()
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	raw := strings.Split(s, "\n")
	out := make([]string, 0, len(raw))
	for _, line := range raw {
		out = append(out, strings.TrimSpace(line))
	}
	return out
}

func (o Option) label() string {
	if o.Name != "" {
		return o.Name
	}
	switch {
	case o.Short != "" && o.Long != "":
		return fmt.Sprintf("%s, %s", o.Short, o.Long)
	case o.Long != "":
		return "    " + o.Long
	case o.Short != "":
		return o.Short
	default:
		return ""
	}
}

func (o Option) sortKey() string {
	if o.Long != "" {
		return o.Long
	}
	if o.Name != "" {
		return o.Name
	}
	return o.Short
}
