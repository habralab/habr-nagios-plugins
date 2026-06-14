package dnschain

import "github.com/habralab/habr-nagios-plugins/internal/core/probemeta"

var Meta = probemeta.Metadata{
	Slug:    "dnschain",
	Title:   "DNS Chain Probe",
	Summary: "Authoritative DNS delegation and DNSSEC chain integrity validation",
}
