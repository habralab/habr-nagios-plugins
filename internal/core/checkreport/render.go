package checkreport

import (
	"fmt"
	"strings"
)

func ChecksForVerbosity(checks []Check, verbosity int) []Check {
	if verbosity >= 3 {
		return checks
	}

	out := make([]Check, 0, len(checks))
	for i := 0; i < len(checks); i++ {
		check := checks[i]
		if check.MinVerbosity > verbosity {
			continue
		}
		if !shouldAggregateCheck(check, verbosity) {
			out = append(out, check)
			continue
		}

		count := 1
		subjects := []string{check.Subject}
		for j := i + 1; j < len(checks); j++ {
			next := checks[j]
			if next.MinVerbosity > verbosity {
				continue
			}
			if !sameAggregationGroup(check, next) {
				break
			}
			count++
			subjects = append(subjects, next.Subject)
			i = j
		}

		if count == 1 {
			out = append(out, check)
			continue
		}

		aggregated := check
		aggregated.Subject = fmt.Sprintf("%d endpoint(s)", count)
		aggregated.Meta = append(append([]KV{}, check.Meta...),
			KV{Key: "aggregated", Value: fmt.Sprintf("%d", count)},
		)
		if verbosity >= 2 {
			aggregated.Meta = append(aggregated.Meta, KV{
				Key:   "subjects",
				Value: strings.Join(nonEmptyStrings(subjects), ","),
			})
		}
		out = append(out, aggregated)
	}
	return out
}

func TracesForVerbosity(traces []TraceEvent, verbosity int) []TraceEvent {
	if len(traces) == 0 {
		return nil
	}
	out := make([]TraceEvent, 0, len(traces))
	for _, trace := range traces {
		if trace.MinVerbosity > verbosity {
			continue
		}
		out = append(out, trace)
	}
	return out
}

func shouldAggregateCheck(check Check, verbosity int) bool {
	if verbosity <= 0 || check.AggregationMode == AggregationNone {
		return false
	}
	switch check.AggregationMode {
	case AggregationSuccessOnly:
		return check.State == CheckPass
	default:
		return false
	}
}

func sameAggregationGroup(a, b Check) bool {
	return a.AggregationMode != AggregationNone &&
		a.AggregationMode == b.AggregationMode &&
		a.AggregationKey != "" &&
		a.AggregationKey == b.AggregationKey &&
		a.ID == b.ID &&
		a.State == b.State &&
		a.Message == b.Message
}

func nonEmptyStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	return out
}
