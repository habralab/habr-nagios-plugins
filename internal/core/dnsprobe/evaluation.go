package dnsprobe

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/core/dnsresolver"
	"github.com/miekg/dns"
)

type MatchMode string

const (
	MatchAny      MatchMode = "any"
	MatchExact    MatchMode = "exact"
	MatchContains MatchMode = "contains"
	MatchRegex    MatchMode = "regex"
)

type RRValueMatcher struct {
	Mode  MatchMode
	Value string
	expr  *regexp.Regexp
}

func NewExactRRValueMatcher(value string) RRValueMatcher {
	return RRValueMatcher{Mode: MatchExact, Value: strings.TrimSpace(value)}
}

func NewContainsRRValueMatcher(value string) RRValueMatcher {
	return RRValueMatcher{Mode: MatchContains, Value: strings.TrimSpace(value)}
}

func NewRegexRRValueMatcher(value string) (RRValueMatcher, error) {
	expr, err := regexp.Compile(strings.TrimSpace(value))
	if err != nil {
		return RRValueMatcher{}, err
	}
	return RRValueMatcher{Mode: MatchRegex, Value: strings.TrimSpace(value), expr: expr}, nil
}

type EndpointRRsetObservation struct {
	Endpoint      string
	Authoritative bool
	Error         string
	Records       []dns.RR
}

type RRsetEvaluation struct {
	AuthoritativeCount int
	PresentCount       int
	MatchedCount       int
	FailedCount        int
	Records            []dns.RR
	Consistent         bool
	ComparableCount    int
	HasMatcher         bool
}

type EndpointRRsetEvaluation struct {
	Endpoint string
	State    checkreport.CheckState
	Message  string
	Matched  bool
}

func EvaluateRRsetResponses(rrtype, scope string, mode PresenceMode, observations []EndpointRRsetObservation, consistency dnsresolver.ConsistencyAssessment, matcher *RRValueMatcher) (RRsetEvaluation, []EndpointRRsetEvaluation, string, bool, string, string) {
	var out RRsetEvaluation
	out.Consistent = true
	out.ComparableCount = consistency.ComparableCount
	if consistency.Mode != dnsresolver.ConsistencyIgnore && consistency.ComparableCount > 1 && !consistency.Consistent {
		out.Consistent = false
	}
	out.HasMatcher = matcher != nil

	var endpointChecks []EndpointRRsetEvaluation
	for _, observation := range observations {
		switch {
		case observation.Error != "":
			out.FailedCount++
			endpointChecks = append(endpointChecks, EndpointRRsetEvaluation{
				Endpoint: observation.Endpoint,
				State:    checkreport.CheckWarning,
				Message:  fmt.Sprintf("%s via %s failed: %s", rrtype, observation.Endpoint, observation.Error),
			})
		case observation.Authoritative:
			out.AuthoritativeCount++
			if len(observation.Records) > 0 {
				out.PresentCount++
				out.Records = append(out.Records, observation.Records...)
				matched := matcher == nil || matcher.MatchesAny(observation.Records)
				if matched {
					out.MatchedCount++
				}
				endpointChecks = append(endpointChecks, EndpointRRsetEvaluation{
					Endpoint: observation.Endpoint,
					State:    checkreport.CheckPass,
					Matched:  matched,
					Message:  presentMessage(rrtype, matcher, matched),
				})
			} else {
				endpointChecks = append(endpointChecks, EndpointRRsetEvaluation{
					Endpoint: observation.Endpoint,
					State:    checkreport.CheckNote,
					Message:  fmt.Sprintf("%s RRset is absent on this authoritative endpoint", rrtype),
				})
			}
		}
	}

	presentForMode := out.PresentCount
	if matcher != nil {
		presentForMode = out.MatchedCount
	}
	summary, ok, critCode, critMsg := EvaluatePresenceMode(mode, rrtype, scope, out.AuthoritativeCount, presentForMode, out.FailedCount, matcher)
	return out, endpointChecks, summary, ok, critCode, critMsg
}

func (m RRValueMatcher) MatchesAny(records []dns.RR) bool {
	if m.Mode == MatchAny {
		return len(records) > 0
	}
	for _, rr := range records {
		if m.MatchesString(rr.String()) {
			return true
		}
	}
	return false
}

func (m RRValueMatcher) MatchesString(value string) bool {
	switch m.Mode {
	case MatchExact:
		return strings.TrimSpace(value) == m.Value
	case MatchContains:
		return strings.Contains(value, m.Value)
	case MatchRegex:
		return m.expr != nil && m.expr.MatchString(value)
	default:
		return true
	}
}

func RRSummary(records []dns.RR) string {
	if len(records) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(records))
	for _, rr := range records {
		parts = append(parts, rr.String())
	}
	sort.Strings(parts)
	return strings.Join(parts, " | ")
}

func CheckStateFromStatus(status checkreport.Status) checkreport.CheckState {
	switch status {
	case checkreport.StatusCritical:
		return checkreport.CheckCritical
	case checkreport.StatusWarning:
		return checkreport.CheckWarning
	case checkreport.StatusUnknown:
		return checkreport.CheckUnknown
	default:
		return checkreport.CheckPass
	}
}

func StatusFromCheckState(state checkreport.CheckState) checkreport.Status {
	switch state {
	case checkreport.CheckCritical:
		return checkreport.StatusCritical
	case checkreport.CheckWarning:
		return checkreport.StatusWarning
	case checkreport.CheckUnknown:
		return checkreport.StatusUnknown
	default:
		return checkreport.StatusOK
	}
}

func presentMessage(rrtype string, matcher *RRValueMatcher, matched bool) string {
	if matcher == nil {
		return fmt.Sprintf("%s RRset is present on this authoritative endpoint", rrtype)
	}
	if matched {
		return fmt.Sprintf("%s RRset is present on this authoritative endpoint and matched %s", rrtype, matcherRuleDescription(*matcher))
	}
	return fmt.Sprintf("%s RRset is present on this authoritative endpoint but did not match %s", rrtype, matcherRuleDescription(*matcher))
}

func matcherSubject(rrtype string, matcher *RRValueMatcher) string {
	if matcher == nil {
		return fmt.Sprintf("%s RRset", rrtype)
	}
	switch matcher.Mode {
	case MatchExact:
		return fmt.Sprintf("%s RR matching exactly %q", rrtype, matcher.Value)
	case MatchContains:
		return fmt.Sprintf("%s RR containing %q", rrtype, matcher.Value)
	case MatchRegex:
		return fmt.Sprintf("%s RR matching regex %q", rrtype, matcher.Value)
	default:
		return fmt.Sprintf("%s RR matching %q", rrtype, matcher.Value)
	}
}

func matcherRuleDescription(matcher RRValueMatcher) string {
	switch matcher.Mode {
	case MatchExact:
		return fmt.Sprintf("the exact-match rule %q", matcher.Value)
	case MatchContains:
		return fmt.Sprintf("the contains rule %q", matcher.Value)
	case MatchRegex:
		return fmt.Sprintf("the regex rule %q", matcher.Value)
	default:
		return "the expected value rule"
	}
}
