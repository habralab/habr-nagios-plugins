package ext

type imageValidator struct{}

func (imageValidator) ID() string { return "image" }

func (imageValidator) NamespaceURI() string { return NamespaceImage }

func (imageValidator) Validate(entry URLEntry) []Issue {
	var issues []Issue
	for _, child := range entry.Children {
		if child.Name.Space != NamespaceImage || child.Name.Local != "image" {
			continue
		}
		loc := childText(child, NamespaceImage, "loc")
		if loc == "" {
			issues = append(issues, Issue{
				Code:     "extension_image_invalid",
				Message:  "image extension entry missing image:loc",
				Severity: SeverityWarning,
			})
			continue
		}
		if !isAbsoluteHTTPURL(loc) {
			issues = append(issues, Issue{
				Code:     "extension_image_invalid",
				Message:  "image extension image:loc must be an absolute http/https URL",
				Severity: SeverityWarning,
			})
		}
	}
	return issues
}

