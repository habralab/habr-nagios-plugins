package main

import (
	"os"

	sitemapapp "github.com/habralab/habr-nagios-plugins/internal/app/sitemap"
)

func main() {
	os.Exit(sitemapapp.Run(os.Args[0], os.Args[1:]))
}
