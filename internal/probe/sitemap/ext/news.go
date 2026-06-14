package ext

type newsValidator struct{}

func (newsValidator) ID() string { return "news" }

func (newsValidator) NamespaceURI() string { return NamespaceNews }

func (newsValidator) Validate(entry URLEntry) []Issue {
	var issues []Issue
	count := 0
	for _, child := range entry.Children {
		if child.Name.Space != NamespaceNews || child.Name.Local != "news" {
			continue
		}
		count++
		publicationFound := false
		publicationName := ""
		publicationLang := ""
		publicationDate := childText(child, NamespaceNews, "publication_date")
		title := childText(child, NamespaceNews, "title")

		for _, grandchild := range child.Children {
			if grandchild.Name.Space == NamespaceNews && grandchild.Name.Local == "publication" {
				publicationFound = true
				publicationName = childText(grandchild, NamespaceNews, "name")
				publicationLang = childText(grandchild, NamespaceNews, "language")
				break
			}
		}

		if !publicationFound || publicationName == "" || publicationLang == "" || publicationDate == "" || title == "" {
			issues = append(issues, Issue{
				Code:     "extension_news_invalid",
				Message:  "news extension entry missing one or more required tags",
				Severity: SeverityWarning,
			})
		}
	}
	if count > 1 {
		issues = append(issues, Issue{
			Code:     "extension_news_invalid",
			Message:  "news extension allows at most one news:news element per url entry",
			Severity: SeverityWarning,
		})
	}
	return issues
}

