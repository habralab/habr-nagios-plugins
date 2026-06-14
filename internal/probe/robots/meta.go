package robots

import "github.com/habralab/habr-nagios-plugins/internal/core/probemeta"

var Meta = probemeta.Metadata{
	Slug:    "robots",
	Title:   "Robots Probe",
	Summary: "robots.txt availability, syntax, and policy validation for Nagios-style monitoring",
}
