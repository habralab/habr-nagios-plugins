package ext

type xhtmlHreflangValidator struct{}

func (xhtmlHreflangValidator) ID() string { return "xhtml_hreflang" }

func (xhtmlHreflangValidator) NamespaceURI() string { return NamespaceXHTML }

func (xhtmlHreflangValidator) Validate(entry URLEntry) []Issue {
	var issues []Issue
	seen := map[string]bool{}
	selfFound := false

	for _, child := range entry.Children {
		if child.Name.Space != NamespaceXHTML || child.Name.Local != "link" {
			continue
		}
		rel := attrValue(child.Attrs, "rel")
		lang := attrValue(child.Attrs, "hreflang")
		href := attrValue(child.Attrs, "href")

		if rel != "alternate" || lang == "" || href == "" {
			issues = append(issues, Issue{
				Code:     "extension_hreflang_invalid",
				Message:  "xhtml hreflang entry must have rel=\"alternate\", hreflang, and href",
				Severity: SeverityWarning,
			})
			continue
		}
		if !isAbsoluteHTTPURL(href) {
			issues = append(issues, Issue{
				Code:     "extension_hreflang_invalid",
				Message:  "xhtml hreflang href must be an absolute http/https URL",
				Severity: SeverityWarning,
			})
		}
		if seen[lang] {
			issues = append(issues, Issue{
				Code:     "extension_hreflang_invalid",
				Message:  "xhtml hreflang entry duplicates a hreflang value within the same url entry",
				Severity: SeverityWarning,
			})
		}
		seen[lang] = true
		if href == entry.Loc {
			selfFound = true
		}
	}

	if len(seen) > 0 && !selfFound {
		issues = append(issues, Issue{
			Code:     "extension_hreflang_invalid",
			Message:  "xhtml hreflang set does not include a self-referencing href",
			Severity: SeverityWarning,
		})
	}

	return issues
}
