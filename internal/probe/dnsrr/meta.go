package dnsrr

import "github.com/habralab/habr-nagios-plugins/internal/core/probemeta"

var Meta = probemeta.Metadata{
	Slug:    "dnsrr",
	Title:   "DNS RR Probe",
	Summary: "Authoritative DNS RR presence validation for specific owner names and RR types",
}
