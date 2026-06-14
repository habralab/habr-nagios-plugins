package ext

type videoValidator struct{}

func (videoValidator) ID() string { return "video" }

func (videoValidator) NamespaceURI() string { return NamespaceVideo }

func (videoValidator) Validate(entry URLEntry) []Issue {
	var issues []Issue
	for _, child := range entry.Children {
		if child.Name.Space != NamespaceVideo || child.Name.Local != "video" {
			continue
		}
		thumbnail := childText(child, NamespaceVideo, "thumbnail_loc")
		title := childText(child, NamespaceVideo, "title")
		description := childText(child, NamespaceVideo, "description")
		contentLoc := childText(child, NamespaceVideo, "content_loc")
		playerLoc := childText(child, NamespaceVideo, "player_loc")

		if thumbnail == "" || title == "" || description == "" || (contentLoc == "" && playerLoc == "") {
			issues = append(issues, Issue{
				Code:     "extension_video_invalid",
				Message:  "video extension entry missing one or more required tags",
				Severity: SeverityWarning,
			})
			continue
		}
		if !isAbsoluteHTTPURL(thumbnail) {
			issues = append(issues, Issue{
				Code:     "extension_video_invalid",
				Message:  "video extension thumbnail_loc must be an absolute http/https URL",
				Severity: SeverityWarning,
			})
		}
		if contentLoc != "" && !isAbsoluteHTTPURL(contentLoc) {
			issues = append(issues, Issue{
				Code:     "extension_video_invalid",
				Message:  "video extension content_loc must be an absolute http/https URL",
				Severity: SeverityWarning,
			})
		}
		if playerLoc != "" && !isAbsoluteHTTPURL(playerLoc) {
			issues = append(issues, Issue{
				Code:     "extension_video_invalid",
				Message:  "video extension player_loc must be an absolute http/https URL",
				Severity: SeverityWarning,
			})
		}
	}
	return issues
}

