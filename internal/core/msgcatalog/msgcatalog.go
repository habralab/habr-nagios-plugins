package msgcatalog

import (
	"sort"
	"strings"
)

type Key string

type Variant string

const (
	VariantTitle   Variant = "title"
	VariantSummary Variant = "summary"
	VariantDetail  Variant = "detail"
	VariantHint    Variant = "hint"
)

type Params map[string]string

type Message struct {
	Title   string
	Summary string
	Detail  string
	Hint    string
}

type Catalog struct {
	locale string
	items  map[Key]Message
}

func New(locale string, items map[Key]Message) Catalog {
	cloned := make(map[Key]Message, len(items))
	for key, message := range items {
		cloned[key] = message
	}
	return Catalog{
		locale: strings.TrimSpace(locale),
		items:  cloned,
	}
}

func (c Catalog) Locale() string {
	if c.locale == "" {
		return "en"
	}
	return c.locale
}

func (c Catalog) Lookup(key Key) (Message, bool) {
	message, ok := c.items[key]
	return message, ok
}

func (c Catalog) Has(key Key) bool {
	_, ok := c.items[key]
	return ok
}

func (c Catalog) Keys() []Key {
	out := make([]Key, 0, len(c.items))
	for key := range c.items {
		out = append(out, key)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (c Catalog) Render(key Key, variant Variant, params Params) (string, bool) {
	message, ok := c.Lookup(key)
	if !ok {
		return "", false
	}
	return RenderVariant(message, variant, params), true
}

func RenderVariant(message Message, variant Variant, params Params) string {
	return RenderTemplate(message.Template(variant), params)
}

func RenderTemplate(template string, params Params) string {
	if template == "" || len(params) == 0 {
		return template
	}

	var replacements []string
	for key, value := range params {
		placeholder := "{{ " + strings.TrimSpace(key) + " }}"
		replacements = append(replacements, placeholder, value)
		compact := "{{" + strings.TrimSpace(key) + "}}"
		if compact != placeholder {
			replacements = append(replacements, compact, value)
		}
	}
	replacer := strings.NewReplacer(replacements...)
	return replacer.Replace(template)
}

func (m Message) Template(variant Variant) string {
	switch variant {
	case VariantTitle:
		return m.Title
	case VariantDetail:
		return m.Detail
	case VariantHint:
		return m.Hint
	default:
		return m.Summary
	}
}
