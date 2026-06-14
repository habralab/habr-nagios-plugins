package dnschain

import (
	"strings"
	"testing"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
)

func TestDetailAggregatesSuccessChecksAtLowerVerbosity(t *testing.T) {
	result := &Result{
		Config: Config{Verbosity: 1},
		Report: checkreport.Report{
			Probe:         Meta.Slug,
			PrimaryTarget: "example.com.",
			Status:        checkreport.StatusOK,
			Summary:       "ok",
			Stages: []checkreport.Stage{
				{
					ID:     "dnssec.chain",
					Title:  "DNSSEC Chain",
					Status: checkreport.StatusOK,
					Checks: []checkreport.Check{
						{
							ID:              "nsec3.name_error_probe",
							State:           checkreport.CheckPass,
							Subject:         "192.0.2.1:53",
							Message:         "signed NSEC3 closest-encloser proof established that the queried name does not exist and no wildcard answer applies",
							AggregationKey:  "nsec3.name_error_probe.pass",
							AggregationMode: checkreport.AggregationSuccessOnly,
						},
						{
							ID:              "nsec3.name_error_probe",
							State:           checkreport.CheckPass,
							Subject:         "192.0.2.2:53",
							Message:         "signed NSEC3 closest-encloser proof established that the queried name does not exist and no wildcard answer applies",
							AggregationKey:  "nsec3.name_error_probe.pass",
							AggregationMode: checkreport.AggregationSuccessOnly,
						},
					},
				},
			},
		},
	}

	detail := result.Detail()
	if !strings.Contains(detail, "subject=2 endpoint(s)") {
		t.Fatalf("Detail() missing aggregated subject; detail=%s", detail)
	}
	if !strings.Contains(detail, "meta aggregated=2") {
		t.Fatalf("Detail() missing aggregated meta; detail=%s", detail)
	}
	if strings.Contains(detail, "192.0.2.2:53") {
		t.Fatalf("Detail() unexpectedly showed individual subject at low verbosity; detail=%s", detail)
	}
}

func TestDetailKeepsAtomicSuccessChecksAtHighestVerbosity(t *testing.T) {
	result := &Result{
		Config: Config{Verbosity: 3},
		Report: checkreport.Report{
			Probe:         Meta.Slug,
			PrimaryTarget: "example.com.",
			Status:        checkreport.StatusOK,
			Summary:       "ok",
			Stages: []checkreport.Stage{
				{
					ID:     "dnssec.chain",
					Title:  "DNSSEC Chain",
					Status: checkreport.StatusOK,
					Checks: []checkreport.Check{
						{
							ID:              "nsec3.name_error_probe",
							State:           checkreport.CheckPass,
							Subject:         "192.0.2.1:53",
							Message:         "signed NSEC3 closest-encloser proof established that the queried name does not exist and no wildcard answer applies",
							AggregationKey:  "nsec3.name_error_probe.pass",
							AggregationMode: checkreport.AggregationSuccessOnly,
						},
						{
							ID:              "nsec3.name_error_probe",
							State:           checkreport.CheckPass,
							Subject:         "192.0.2.2:53",
							Message:         "signed NSEC3 closest-encloser proof established that the queried name does not exist and no wildcard answer applies",
							AggregationKey:  "nsec3.name_error_probe.pass",
							AggregationMode: checkreport.AggregationSuccessOnly,
						},
					},
				},
			},
		},
	}

	detail := result.Detail()
	if !strings.Contains(detail, "subject=192.0.2.1:53") || !strings.Contains(detail, "subject=192.0.2.2:53") {
		t.Fatalf("Detail() did not preserve atomic checks at high verbosity; detail=%s", detail)
	}
	if strings.Contains(detail, "subject=2 endpoint(s)") {
		t.Fatalf("Detail() unexpectedly aggregated at high verbosity; detail=%s", detail)
	}
}

func TestDetailHidesLowLevelChecksAndTraceAtVerbosityOne(t *testing.T) {
	result := &Result{
		Config: Config{Verbosity: 1},
		Report: checkreport.Report{
			Probe:         Meta.Slug,
			PrimaryTarget: "example.com.",
			Status:        checkreport.StatusOK,
			Summary:       "ok",
			Stages: []checkreport.Stage{
				{
					ID:     "child.authority",
					Title:  "Child Authority",
					Status: checkreport.StatusOK,
					Checks: []checkreport.Check{
						{
							ID:           "ns.endpoint",
							State:        checkreport.CheckPass,
							Subject:      "192.0.2.1:53",
							Message:      "ns1.example. authoritative SOA response received",
							MinVerbosity: 2,
						},
						{
							ID:      "ns.authoritative",
							State:   checkreport.CheckPass,
							Subject: "ns1.example.",
							Message: "authoritative SOA response received on 2 endpoint(s)",
						},
					},
				},
			},
			Traces: []checkreport.TraceEvent{
				{
					Kind:    "query",
					StageID: "child.authority",
					State:   checkreport.CheckPass,
					Target:  "example.com.",
					Message: "SOA from 192.0.2.1:53 over udp in 10ms",
				},
			},
		},
	}

	detail := result.Detail()
	if strings.Contains(detail, "ns.endpoint") {
		t.Fatalf("Detail() unexpectedly showed low-level check at verbosity 1; detail=%s", detail)
	}
	if strings.Contains(detail, "Trace:") {
		t.Fatalf("Detail() unexpectedly showed trace at verbosity 1; detail=%s", detail)
	}
	if !strings.Contains(detail, "ns.authoritative") {
		t.Fatalf("Detail() lost higher-level summary check; detail=%s", detail)
	}
}
