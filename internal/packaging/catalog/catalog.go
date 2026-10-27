package catalog

import (
	"fmt"

	"github.com/habralab/habr-nagios-plugins/internal/core/probemeta"
	"github.com/habralab/habr-nagios-plugins/internal/probe/dnschain"
	"github.com/habralab/habr-nagios-plugins/internal/probe/dnsrr"
	"github.com/habralab/habr-nagios-plugins/internal/probe/robots"
	"github.com/habralab/habr-nagios-plugins/internal/probe/sitemap"
	tlsprobe "github.com/habralab/habr-nagios-plugins/internal/probe/tls"
)

type Probe struct {
	Meta probemeta.Metadata
}

var All = []Probe{
	{Meta: dnschain.Meta},
	{Meta: dnsrr.Meta},
	{Meta: robots.Meta},
	{Meta: sitemap.Meta},
	{Meta: tlsprobe.Meta},
}

func Find(slug string) (Probe, error) {
	for _, probe := range All {
		if probe.Meta.Slug == slug {
			return probe, nil
		}
	}
	return Probe{}, fmt.Errorf("unknown probe slug %q", slug)
}
