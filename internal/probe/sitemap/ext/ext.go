package ext

import (
	"encoding/xml"
	"net/url"
	"strings"
)

type Severity int

const (
	SeverityWarning Severity = iota + 1
	SeverityCritical
)

type Issue struct {
	Code     string
	Message  string
	Severity Severity
}

type Element struct {
	Name     xml.Name
	Attrs    []xml.Attr
	Text     string
	Children []Element
}

type URLEntry struct {
	Loc      string
	Children []Element
}

type Observation struct {
	ID           string
	NamespaceURI string
	Count        int
	IssueCount   int
}

type Validator interface {
	ID() string
	NamespaceURI() string
	Validate(entry URLEntry) []Issue
}

func Validate(entry URLEntry) ([]Observation, []Issue) {
	grouped := map[string][]Element{}
	for _, child := range entry.Children {
		if child.Name.Space == "" {
			continue
		}
		grouped[child.Name.Space] = append(grouped[child.Name.Space], child)
	}

	var observations []Observation
	var issues []Issue
	for namespace, children := range grouped {
		validator, ok := registry[namespace]
		if !ok {
			continue
		}
		found := validator.Validate(URLEntry{Loc: entry.Loc, Children: children})
		observations = append(observations, Observation{
			ID:           validator.ID(),
			NamespaceURI: namespace,
			Count:        len(children),
			IssueCount:   len(found),
		})
		issues = append(issues, found...)
	}

	return observations, issues
}

func attrValue(attrs []xml.Attr, local string) string {
	for _, attr := range attrs {
		if attr.Name.Local == local {
			return strings.TrimSpace(attr.Value)
		}
	}
	return ""
}

func childText(el Element, namespace, local string) string {
	for _, child := range el.Children {
		if child.Name.Space == namespace && child.Name.Local == local {
			return strings.TrimSpace(child.Text)
		}
	}
	return ""
}

func hasChild(el Element, namespace, local string) bool {
	for _, child := range el.Children {
		if child.Name.Space == namespace && child.Name.Local == local {
			return true
		}
	}
	return false
}

func isAbsoluteHTTPURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	if u.Scheme == "" || u.Host == "" {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

