package msgcatalog

func CommonEnglishSource() Source {
	return Source{
		Name:            "core/common",
		AllowedPrefixes: []string{"common_"},
		Items: map[Key]Message{
			"common_section_target":              {Summary: "Target"},
			"common_section_meta":                {Summary: "Meta"},
			"common_section_stages":              {Summary: "Stages"},
			"common_section_trace":               {Summary: "Trace"},
			"common_section_findings":            {Summary: "Findings"},
			"common_section_suppressed_findings": {Summary: "Suppressed Findings"},
			"common_section_http":                {Summary: "HTTP"},
			"common_section_rules":               {Summary: "Rules"},
			"common_section_parsed":              {Summary: "Parsed"},
			"common_section_discovery":           {Summary: "Discovery"},
			"common_section_entrypoints":         {Summary: "Entrypoints"},
			"common_section_documents":           {Summary: "Documents"},
			"common_section_performance":         {Summary: "Performance"},
			"common_section_problems":            {Summary: "Problems"},
			"common_section_ignored_problems":    {Summary: "Ignored Problems"},
			"common_help_show_help":              {Summary: "Show help"},
			"common_help_show_version":           {Summary: "Show version and build metadata"},
			"common_help_verbose":                {Summary: "Increase output detail.\nRepeat up to 3 times for deeper diagnostics."},
			"common_help_timeout_prefix":         {Summary: "Overall check timeout."},
			"common_help_output_prefix":          {Summary: "Output mode."},
			"common_help_output_nagios":          {Summary: "nagios emits classic monitoring text."},
		},
	}
}
