package checkreport

import (
	"strings"
	"testing"
)

func TestRenderDetailRespectsMinVerbosity(t *testing.T) {
	out := RenderDetail("SUMMARY", 1,
		DetailSection{Render: func(b *strings.Builder) { b.WriteString("always\n") }},
		DetailSection{MinVerbosity: 2, Render: func(b *strings.Builder) { b.WriteString("hidden\n") }},
	)
	if !strings.Contains(out, "SUMMARY\nalways\n") {
		t.Fatalf("RenderDetail() output = %q, want summary and visible section", out)
	}
	if strings.Contains(out, "hidden") {
		t.Fatalf("RenderDetail() output = %q, want hidden section omitted", out)
	}
}

func TestWriteFindingsSectionFormatsSuppressed(t *testing.T) {
	var b strings.Builder
	WriteFindingsSection(&b, "suppressed_findings", []Finding{{
		Code:     "slug",
		Severity: StatusWarning,
		Message:  "suppressed",
		Target:   "example.test",
	}}, true)
	out := b.String()
	for _, snippet := range []string{
		"Suppressed Findings:\n",
		"IGNORED slug original=WARNING: suppressed [example.test]",
	} {
		if !strings.Contains(out, snippet) {
			t.Fatalf("WriteFindingsSection() output missing %q in:\n%s", snippet, out)
		}
	}
}

func TestWriteFieldsSection(t *testing.T) {
	var b strings.Builder
	WriteFieldsSection(&b, "target", []SectionField{
		{Key: "source", Value: "hostname"},
		{Key: "effective_base", Value: "https://example.test"},
	})
	out := b.String()
	for _, snippet := range []string{
		"Target:\n",
		"source=hostname",
		"effective_base=https://example.test",
	} {
		if !strings.Contains(out, snippet) {
			t.Fatalf("WriteFieldsSection() output missing %q in:\n%s", snippet, out)
		}
	}
}

func TestWriteStageAndTraceMessageSections(t *testing.T) {
	report := &Report{
		Stages: []Stage{{
			ID: "discovery",
			Checks: []Check{
				{ID: "discovery.summary", Message: "summary message"},
				{ID: "discovery.trace", Message: "trace message"},
				{ID: "entrypoint", Subject: "https://example.test/sitemap.xml"},
			},
		}},
		Traces: []TraceEvent{
			{Kind: "http", Message: "GET /robots.txt"},
			{Kind: "dns", Message: "lookup example.test"},
		},
	}

	var b strings.Builder
	WriteStageMessagesSection(&b, report, "discovery", "discovery", 1, "discovery.summary", "discovery.trace")
	WriteCheckSubjectsSection(&b, report, "entrypoints", "discovery", 1, "entrypoint")
	WriteTraceMessageSection(&b, "http", report.Traces, 2, "http")
	out := b.String()
	for _, snippet := range []string{
		"Discovery:\n",
		"summary message",
		"trace message",
		"Entrypoints:\n",
		"https://example.test/sitemap.xml",
		"HTTP:\n",
		"GET /robots.txt",
	} {
		if !strings.Contains(out, snippet) {
			t.Fatalf("section adapter output missing %q in:\n%s", snippet, out)
		}
	}
	if strings.Contains(out, "lookup example.test") {
		t.Fatalf("section adapter output = %q, want non-http trace filtered out", out)
	}
}

func TestWriteReportSections(t *testing.T) {
	report := &Report{
		Probe:         "tls",
		PrimaryTarget: "www.example.com:443",
		Status:        StatusWarning,
		Partial:       true,
		Targets:       []Target{{Role: "service", Value: "www.example.com:443"}},
		Meta:          []KV{{Key: "transport", Value: "tcp"}},
		Stages: []Stage{{
			ID:     "handshake",
			Status: StatusWarning,
			Target: "www.example.com:443",
			Checks: []Check{{
				ID:      "version",
				State:   CheckWarning,
				Subject: "TLS 1.2",
				Message: "deprecated version accepted",
				Meta:    []KV{{Key: "foo", Value: "bar"}},
				Evidence: []Evidence{{
					Kind:    "probe",
					Summary: "probe evidence",
					Attributes: []KV{
						{Key: "suite", Value: "AES"},
					},
					Items: []EvidenceItem{{
						ID:      "endpoint_profile",
						Subject: "192.0.2.10:443",
						Summary: "structured endpoint semantic profile",
						Attributes: []KV{
							{Key: "transport.alpn", Value: "h2"},
						},
					}},
				}},
			}},
			Notes: []string{"stage note"},
		}},
		Traces: []TraceEvent{{
			Kind:    "net",
			StageID: "handshake",
			State:   CheckNote,
			Target:  "www.example.com:443",
			Message: "trace line",
			Attributes: []KV{
				{Key: "peer", Value: "1.2.3.4"},
			},
		}},
	}

	var b strings.Builder
	WriteReportOverviewSection(&b, report)
	WriteReportMetaSection(&b, report)
	WriteReportStagesSection(&b, report, 1)
	WriteReportTraceSection(&b, report, 2)
	out := b.String()
	for _, snippet := range []string{
		"Target:\n",
		"probe=tls target=www.example.com:443 status=warning partial=true",
		"Meta:\n",
		"transport=tcp",
		"Stages:\n",
		"check=version state=warning subject=TLS 1.2 message=deprecated version accepted",
		"evidence kind=probe summary=probe evidence",
		"item id=endpoint_profile subject=192.0.2.10:443 summary=structured endpoint semantic profile",
		"transport.alpn=h2",
		"note=stage note",
		"Trace:\n",
		"kind=net stage=handshake state=note target=www.example.com:443 message=trace line",
		"peer=1.2.3.4",
	} {
		if !strings.Contains(out, snippet) {
			t.Fatalf("report section output missing %q in:\n%s", snippet, out)
		}
	}
}
