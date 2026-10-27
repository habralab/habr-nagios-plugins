package tlsprobe

import "github.com/habralab/habr-nagios-plugins/internal/core/probemeta"

var Meta = probemeta.Metadata{
	Slug:    "tls",
	Title:   "TLS Probe",
	Summary: "TLS transport, PKI, and DNS-backed trust validation for HTTPS and STARTTLS services",
}
