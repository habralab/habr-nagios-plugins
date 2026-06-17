package probecli

const (
	InputRefBehavior      InputRef = "behavior_profile"
	InputRefFallback      InputRef = "fallback_status"
	InputRefFallbackPaths InputRef = "fallback_paths"
	InputRefMaxDepth      InputRef = "max_depth"
	InputRefMaxFiles      InputRef = "max_files"
	InputRefMaxURLs       InputRef = "max_urls"
	InputRefURL           InputRef = "url"
	InputRefRobotsURL     InputRef = "robots_url"
	InputRefEntrypoint    InputRef = "entrypoint"
)

func WebInputLabels() InputLabels {
	return InputLabels{
		InputRefBehavior:      "--behavior-profile",
		InputRefFallback:      "--fallback-status",
		InputRefFallbackPaths: "--fallback-paths",
		InputRefMaxDepth:      "--max-depth",
		InputRefMaxFiles:      "--max-files",
		InputRefMaxURLs:       "--max-urls",
		InputRefURL:           "-u/--url",
		InputRefRobotsURL:     "--robots-url",
		InputRefEntrypoint:    "--entrypoint",
	}
}
