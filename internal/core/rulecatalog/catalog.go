package rulecatalog

import (
	"sort"

	"github.com/habralab/habr-nagios-plugins/internal/core/probecli"
)

type Entry[S comparable] struct {
	Slug     string
	Category string
	Severity S
	Message  string
}

type Registry[S comparable] struct {
	entries        map[string]Entry[S]
	formatSeverity func(S) string
}

func New[S comparable](entries map[string]Entry[S], formatSeverity func(S) string) Registry[S] {
	cloned := make(map[string]Entry[S], len(entries))
	for slug, entry := range entries {
		cloned[slug] = entry
	}
	return Registry[S]{
		entries:        cloned,
		formatSeverity: formatSeverity,
	}
}

func (r Registry[S]) HasSlug(slug string) bool {
	_, ok := r.entries[slug]
	return ok
}

func (r Registry[S]) Lookup(slug string) (Entry[S], bool) {
	entry, ok := r.entries[slug]
	return entry, ok
}

func (r Registry[S]) Slugs() []string {
	out := make([]string, 0, len(r.entries))
	for slug := range r.entries {
		out = append(out, slug)
	}
	sort.Strings(out)
	return out
}

func (r Registry[S]) Entries() []probecli.ErrorSlugDescriptor {
	slugs := r.Slugs()
	out := make([]probecli.ErrorSlugDescriptor, 0, len(slugs))
	for _, slug := range slugs {
		entry := r.entries[slug]
		out = append(out, probecli.ErrorSlugDescriptor{
			Slug:     entry.Slug,
			Category: entry.Category,
			Severity: r.formatSeverity(entry.Severity),
			Message:  entry.Message,
		})
	}
	return out
}
