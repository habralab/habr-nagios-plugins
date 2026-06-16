package msgcatalog

func RobotsEnglishSource() Source {
	return Source{
		Name:            "probe/robots",
		AllowedPrefixes: []string{"robots_"},
		Items: map[Key]Message{
			"robots_bad_status":                   {Summary: "unexpected robots.txt HTTP status"},
			"robots_unavailable_status":           {Summary: "robots.txt is unavailable to crawlers due to 4xx status"},
			"robots_empty":                        {Summary: "robots.txt is empty"},
			"robots_fetch_failed":                 {Summary: "robots.txt fetch failed"},
			"robots_fetch_timeout":                {Summary: "robots.txt fetch timeout"},
			"robots_non_utf8":                     {Summary: "robots.txt is not valid UTF-8"},
			"robots_invalid_line":                 {Summary: "robots.txt contains an invalid directive line"},
			"robots_invalid_path":                 {Summary: "robots.txt contains an invalid Allow/Disallow path"},
			"robots_invalid_directive_value":      {Summary: "robots.txt contains an invalid extension directive value"},
			"robots_invalid_sitemap":              {Summary: "robots.txt contains an invalid Sitemap directive"},
			"robots_duplicate_sitemap":            {Summary: "robots.txt contains a duplicate Sitemap directive"},
			"robots_extension_directive":          {Summary: "robots.txt uses a non-standard extension directive"},
			"robots_unknown_directive":            {Summary: "robots.txt contains an unknown directive"},
			"robots_no_groups":                    {Summary: "robots.txt contains no User-agent groups"},
			"robots_rule_missing":                 {Summary: "required robots.txt rule is missing"},
			"robots_rule_forbidden":               {Summary: "forbidden robots.txt rule is present"},
			"robots_content_type_unexpected":      {Summary: "unexpected robots.txt content type"},
			"robots_too_large":                    {Summary: "robots.txt exceeds the RFC parsing size limit"},
			"robots_size_near_limit":              {Summary: "robots.txt size is close to the RFC parsing limit"},
			"robots_redirect_loop":                {Summary: "robots.txt redirect loop detected"},
			"robots_redirect_limit_exceeded":      {Summary: "robots.txt redirect limit exceeded"},
			"robots_agent_ignores_rules":          {Summary: "documented crawler behavior ignores the configured robots.txt rules"},
			"robots_agent_ignores_directive":      {Summary: "documented crawler behavior ignores a configured robots.txt directive"},
			"robots_agent_directive_undocumented": {Summary: "documented crawler support for a configured extension directive is unknown"},
		},
	}
}
