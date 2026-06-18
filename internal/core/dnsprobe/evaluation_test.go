package dnsprobe

import (
	"testing"

	"github.com/habralab/habr-nagios-plugins/internal/core/dnsresolver"
	"github.com/miekg/dns"
)

func TestEvaluateRRsetResponses(t *testing.T) {
	records := []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: []string{"v=ok"}}}
	eval, endpoints, _, ok, _, _ := EvaluateRRsetResponses("TXT", "example.com.", PresenceAny, []EndpointRRsetObservation{
		{Endpoint: "192.0.2.1:53", Authoritative: true, Records: records},
	}, dnsresolver.ConsistencyAssessment{}, nil)
	if !ok {
		t.Fatal("expected RRset evaluation to succeed")
	}
	if eval.PresentCount != 1 || len(endpoints) != 1 {
		t.Fatalf("unexpected evaluation: %+v endpoints=%d", eval, len(endpoints))
	}
}

func TestRegexMatcher(t *testing.T) {
	matcher, err := NewRegexRRValueMatcher(`v=spf1`)
	if err != nil {
		t.Fatalf("NewRegexRRValueMatcher() error = %v", err)
	}
	if !matcher.MatchesString(`example.com. 300 IN TXT "v=spf1 -all"`) {
		t.Fatal("expected regex matcher to match TXT record string")
	}
}

func TestEvaluateRRsetResponsesWithMatcher(t *testing.T) {
	records := []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: []string{"v=spf1 -all"}}}
	matcher := NewContainsRRValueMatcher("spf1")
	eval, _, summary, ok, _, _ := EvaluateRRsetResponses("TXT", "example.com.", PresenceAny, []EndpointRRsetObservation{
		{Endpoint: "192.0.2.1:53", Authoritative: true, Records: records},
	}, dnsresolver.ConsistencyAssessment{}, &matcher)
	if !ok {
		t.Fatal("expected matcher-backed RRset evaluation to succeed")
	}
	if eval.MatchedCount != 1 {
		t.Fatalf("MatchedCount = %d, want 1", eval.MatchedCount)
	}
	if got, want := summary, `TXT RR containing "spf1" was observed on at least one authoritative endpoint within example.com.`; got != want {
		t.Fatalf("summary = %q, want %q", got, want)
	}
}

func TestEvaluateRRsetResponsesWithMatcherFailureSummary(t *testing.T) {
	records := []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: []string{"v=spf1 -all"}}}
	matcher := NewContainsRRValueMatcher("include:_spf.example.net")
	_, _, summary, ok, _, critMsg := EvaluateRRsetResponses("TXT", "example.com.", PresenceAny, []EndpointRRsetObservation{
		{Endpoint: "192.0.2.1:53", Authoritative: true, Records: records},
	}, dnsresolver.ConsistencyAssessment{}, &matcher)
	if ok {
		t.Fatal("expected matcher-backed RRset evaluation to fail")
	}
	if got, want := summary, `TXT RR containing "include:_spf.example.net" was not observed on any authoritative endpoint within example.com.`; got != want {
		t.Fatalf("summary = %q, want %q", got, want)
	}
	if got, want := critMsg, `TXT RR containing "include:_spf.example.net" was not present on any authoritative endpoint within example.com.`; got != want {
		t.Fatalf("critMsg = %q, want %q", got, want)
	}
}
