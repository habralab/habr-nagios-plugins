package catalog

import (
	"fmt"

	"github.com/habralab/habr-nagios-plugins/internal/core/probemeta"
	"github.com/habralab/habr-nagios-plugins/internal/probe/sitemap"
)

type Probe struct {
	Meta probemeta.Metadata
}

var All = []Probe{
	{Meta: sitemap.Meta},
}

func Find(slug string) (Probe, error) {
	for _, probe := range All {
		if probe.Meta.Slug == slug {
			return probe, nil
		}
	}
	return Probe{}, fmt.Errorf("unknown probe slug %q", slug)
}
