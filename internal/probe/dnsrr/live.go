package dnsrr

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/core/dnsprobe"
	"github.com/habralab/habr-nagios-plugins/internal/core/dnsresolver"
	"github.com/habralab/habr-nagios-plugins/internal/core/probecli"
	"github.com/miekg/dns"
)

type liveAnalyzer struct{}

func (liveAnalyzer) Analyze(ctx context.Context, cfg Config, target Target) (report checkreport.Report, err error) {
	started := time.Now().UTC()
	report = checkreport.Report{
		Probe:         Meta.Slug,
		Target:        target.Owner,
		PrimaryTarget: target.Owner,
		Targets: []checkreport.Target{
			{Role: "input", Value: target.Input},
			{Role: "owner", Value: dns.Fqdn(target.Owner)},
			{Role: "rrtype", Value: target.RRTypeRaw},
			{Role: "mode", Value: string(target.Mode)},
		},
		Status:    checkreport.StatusOK,
		Summary:   fmt.Sprintf("%s RRset is present as requested", target.RRTypeRaw),
		StartedAt: started,
		Meta:      []checkreport.KV{{Key: "output_mode", Value: string(cfg.OutputMode)}, {Key: "dnssec_mode", Value: string(cfg.DNSSECMode)}},
	}

	resolver := dnsresolver.NewResolver(cfg.QueryTimeout)
	resolver.SetTransportFamilyPolicy(cfg.TransportFamilyPolicy)
	resolver.ConfigureSharedCacheBackendDSN(cfg.CacheBackend)
	defer func() {
		probecli.AppendResolverCacheUsageStage(&report, target.Owner, resolver.CacheStats(), resolver.CacheTrace())
	}()
	zone, servers, discoveryStage, discoveryFindings, err := discoverAuthority(ctx, resolver, cfg, target)
	report.Stages = append(report.Stages, discoveryStage)
	report.Findings = append(report.Findings, discoveryFindings...)
	if err != nil {
		report.Status = checkreport.StatusUnknown
		report.Summary = err.Error()
		finalizeReport(&report, cfg, started)
		return report, nil
	}

	queryServers := servers
	scopeSubject := zone
	if target.Mode == dnsprobe.PresenceMaster {
		masterZone, masterServers, masterStage, masterFindings, masterErr := discoverMasterEndpoints(ctx, resolver, zone, servers)
		report.Stages = append(report.Stages, masterStage)
		report.Findings = append(report.Findings, masterFindings...)
		if masterErr != nil {
			report.Status = checkreport.StatusUnknown
			report.Summary = masterErr.Error()
			finalizeReport(&report, cfg, started)
			return report, nil
		}
		queryServers = masterServers
		scopeSubject = masterZone
	}

	resolveOpts := dnsresolver.ResolveOptions{
		Fanout:      dnsresolver.FanoutAllAuthoritative,
		Consistency: dnsresolver.ConsistencyObserve,
	}
	resolved, err := resolver.ResolveAuthoritative(ctx, target.Owner, target.RRType, queryServers, resolveOpts)
	if err != nil {
		report.Status = checkreport.StatusUnknown
		report.Summary = fmt.Sprintf("authoritative %s lookup failed: %v", target.RRTypeRaw, err)
		report.Findings = append(report.Findings, makeFinding("dnsrr_no_authoritative_answers", checkreport.StatusUnknown, dns.Fqdn(target.Owner), report.Summary))
		finalizeReport(&report, cfg, started)
		return report, nil
	}

	lookupStage, lookupFindings, summary := evaluatePresence(target, scopeSubject, resolved)
	report.Stages = append(report.Stages, lookupStage)
	report.Findings = append(report.Findings, lookupFindings...)
	report.Summary = summary

	var dnssecMetric *checkreport.Metric
	if cfg.DNSSECMode != dnsprobe.DNSSECIgnore {
		lookup, err := resolver.Lookup(ctx, target.Owner, target.RRType)
		dnssecStage, dnssecFindings, metric := evaluateDNSSEC(target, cfg.DNSSECMode, lookup, err)
		report.Stages = append(report.Stages, dnssecStage)
		report.Findings = append(report.Findings, dnssecFindings...)
		dnssecMetric = &metric
	} else {
		metric := dnssecMetricForMode(cfg.DNSSECMode, dnsresolver.SecurityIndeterminate)
		dnssecMetric = &metric
	}

	finalizeReport(&report, cfg, started)
	if dnssecMetric != nil {
		report.Metrics = append(report.Metrics, *dnssecMetric)
	}
	return report, nil
}

func discoverAuthority(ctx context.Context, resolver *dnsresolver.Resolver, cfg Config, target Target) (string, []dnsresolver.AuthoritativeServer, checkreport.Stage, []checkreport.Finding, error) {
	stage := checkreport.Stage{
		ID:     "zone.discovery",
		Title:  "Zone Discovery",
		Status: checkreport.StatusOK,
		Target: dns.Fqdn(target.Owner),
	}
	var findings []checkreport.Finding
	discovery, err := dnsprobe.DiscoverAuthority(ctx, resolver, dnsprobe.AuthorityDiscoveryInput{
		Owner:        target.Owner,
		ExplicitZone: cfg.Zone,
	})
	if err != nil {
		msg := fmt.Sprintf("authoritative discovery failed: %v", err)
		stage.Status = checkreport.StatusUnknown
		stage.Checks = append(stage.Checks, checkreport.Check{ID: "zone.discovery", State: checkreport.CheckUnknown, Subject: dns.Fqdn(target.Owner), Message: msg})
		findings = append(findings, makeFinding("dnsrr_discovery_failed", checkreport.StatusUnknown, dns.Fqdn(target.Owner), msg))
		return "", nil, stage, findings, err
	}
	servers := dnsresolver.AuthoritativeServersFromAddrs(discovery.ChildServers)
	stage.Checks = append(stage.Checks,
		checkreport.Check{
			ID:      "zone.cut",
			State:   checkreport.CheckPass,
			Subject: discovery.Zone,
			Message: fmt.Sprintf("resolved authoritative zone %s for owner %s", discovery.Zone, dns.Fqdn(target.Owner)),
		},
		checkreport.Check{
			ID:      "zone.authority",
			State:   checkreport.CheckPass,
			Subject: discovery.Zone,
			Message: fmt.Sprintf("prepared %d authoritative endpoint(s) across %d NS name(s)", len(servers), len(discovery.DelegationNS)),
		},
	)
	return discovery.Zone, servers, stage, findings, nil
}

func discoverMasterEndpoints(ctx context.Context, resolver *dnsresolver.Resolver, zone string, servers []dnsresolver.AuthoritativeServer) (string, []dnsresolver.AuthoritativeServer, checkreport.Stage, []checkreport.Finding, error) {
	stage := checkreport.Stage{
		ID:     "master.discovery",
		Title:  "Formal Master Discovery",
		Status: checkreport.StatusOK,
		Target: zone,
	}
	var findings []checkreport.Finding
	discovery, err := dnsprobe.DiscoverFormalMaster(ctx, resolver, zone, servers)
	if err != nil {
		msg := err.Error()
		code := "dnsrr_master_unresolved"
		subject := zone
		if strings.Contains(msg, "could not be determined") {
			code = "dnsrr_master_missing_soa"
		} else if strings.HasPrefix(msg, "formal master ") {
			subject = strings.TrimSuffix(strings.TrimPrefix(strings.SplitN(msg, " ", 3)[0], ""), "")
		}
		finding := makeFinding(code, checkreport.StatusUnknown, subject, msg)
		findings = append(findings, finding)
		stage.Status = checkreport.StatusUnknown
		stage.Checks = append(stage.Checks, checkreport.Check{ID: "master.resolve", State: checkreport.CheckUnknown, Subject: zone, Message: msg})
		return "", nil, stage, findings, errors.New(msg)
	}
	stage.Checks = append(stage.Checks,
		checkreport.Check{ID: "master.name", State: checkreport.CheckPass, Subject: discovery.Name, Message: fmt.Sprintf("formal master from SOA is %s", discovery.Name)},
		checkreport.Check{ID: "master.resolve", State: checkreport.CheckPass, Subject: discovery.Name, Message: fmt.Sprintf("resolved %d endpoint(s) for the formal master", len(discovery.Endpoints))},
	)
	return discovery.Name, discovery.Endpoints, stage, findings, nil
}

func evaluatePresence(target Target, scope string, resolved dnsresolver.ResolveResult) (checkreport.Stage, []checkreport.Finding, string) {
	stage := checkreport.Stage{
		ID:     "rrset.presence",
		Title:  "RR Presence Evaluation",
		Status: checkreport.StatusOK,
		Target: dns.Fqdn(target.Owner),
	}
	var findings []checkreport.Finding
	observations := make([]dnsprobe.EndpointRRsetObservation, 0, len(resolved.Responses))
	for _, response := range resolved.Responses {
		observations = append(observations, dnsprobe.EndpointRRsetObservation{
			Endpoint:      response.Endpoint,
			Authoritative: response.Authoritative,
			Error:         response.Error,
			Records:       response.Records,
		})
	}
	eval, endpointChecks, summary, ok, critCode, critMsg := dnsprobe.EvaluateRRsetResponses(target.RRTypeRaw, scope, target.Mode, observations, resolved.Consistency, target.Matcher)
	for _, check := range endpointChecks {
		stage.Checks = append(stage.Checks, checkreport.Check{
			ID:      "rrset.endpoint",
			State:   check.State,
			Subject: check.Endpoint,
			Message: check.Message,
		})
		if check.State == checkreport.CheckWarning {
			findings = append(findings, makeFinding("dnsrr_endpoint_failed", checkreport.StatusWarning, dns.Fqdn(target.Owner), check.Message))
		}
	}
	if eval.AuthoritativeCount == 0 {
		finding := makeFinding("dnsrr_no_authoritative_answers", checkreport.StatusUnknown, dns.Fqdn(target.Owner), "no authoritative endpoint returned a usable answer")
		findings = append(findings, finding)
		stage.Status = checkreport.StatusUnknown
		stage.Checks = append(stage.Checks, checkreport.Check{
			ID:      "rrset.authoritative",
			State:   checkreport.CheckUnknown,
			Subject: dns.Fqdn(target.Owner),
			Message: finding.Message,
		})
		return stage, findings, finding.Message
	}
	if !eval.Consistent && eval.ComparableCount > 1 {
		findings = append(findings, makeFinding("dnsrr_rrset_inconsistent", checkreport.StatusWarning, dns.Fqdn(target.Owner),
			fmt.Sprintf("%s RRset differed across authoritative endpoints", target.RRTypeRaw)))
	}
	if !ok {
		severity := checkreport.StatusCritical
		if critCode == "dnsrr_inconclusive" {
			severity = checkreport.StatusUnknown
		}
		findings = append(findings, makeFinding(critCode, severity, dns.Fqdn(target.Owner), critMsg))
		stage.Status = severity
	} else if eval.FailedCount > 0 || len(findings) > 0 {
		stage.Status = checkreport.StatusWarning
	}
	stage.Checks = append(stage.Checks, checkreport.Check{
		ID:      "rrset.mode",
		State:   dnsprobe.CheckStateFromStatus(stage.Status),
		Subject: dns.Fqdn(target.Owner),
		Message: summary,
		Evidence: []checkreport.Evidence{{
			Kind:    "dns",
			Summary: "authoritative RRset evaluation",
			Attributes: []checkreport.KV{
				{Key: "zone_or_master_scope", Value: scope},
				{Key: "rrtype", Value: target.RRTypeRaw},
				{Key: "authoritative_responses", Value: fmt.Sprintf("%d", eval.AuthoritativeCount)},
				{Key: "present_responses", Value: fmt.Sprintf("%d", eval.PresentCount)},
				{Key: "matched_responses", Value: fmt.Sprintf("%d", eval.MatchedCount)},
				{Key: "failed_endpoints", Value: fmt.Sprintf("%d", eval.FailedCount)},
				{Key: "records", Value: dnsprobe.RRSummary(eval.Records)},
			},
		}},
	})
	return stage, findings, summary
}

func evaluateDNSSEC(target Target, mode dnsprobe.DNSSECMode, lookup dnsresolver.LookupResult, err error) (checkreport.Stage, []checkreport.Finding, checkreport.Metric) {
	stage := checkreport.Stage{
		ID:     "dnssec.assessment",
		Title:  "DNSSEC Assessment",
		Status: checkreport.StatusOK,
		Target: dns.Fqdn(target.Owner),
	}
	metric := dnssecMetricForMode(mode, lookup.Security)
	var findings []checkreport.Finding
	if err != nil {
		msg := fmt.Sprintf("DNSSEC lookup for %s %s failed: %v", dns.Fqdn(target.Owner), target.RRTypeRaw, err)
		finding := makeFinding("dnsrr_dnssec_inconclusive", checkreport.StatusUnknown, dns.Fqdn(target.Owner), msg)
		findings = append(findings, finding)
		stage.Status = checkreport.StatusUnknown
		stage.Checks = append(stage.Checks, checkreport.Check{ID: "dnssec.lookup", State: checkreport.CheckUnknown, Subject: dns.Fqdn(target.Owner), Message: msg})
		return stage, findings, dnssecMetricForMode(mode, dnsresolver.SecurityIndeterminate)
	}
	state := checkreport.CheckPass
	message := ""
	switch lookup.Security {
	case dnsresolver.SecuritySecure:
		message = fmt.Sprintf("%s lookup was protected by a secure DNSSEC chain", target.RRTypeRaw)
	case dnsresolver.SecurityInsecure:
		message = fmt.Sprintf("%s lookup completed without a secure DS-backed DNSSEC chain", target.RRTypeRaw)
		if mode == dnsprobe.DNSSECRequire {
			state = checkreport.CheckCritical
			findings = append(findings, makeFinding("dnsrr_dnssec_not_secure", checkreport.StatusCritical, dns.Fqdn(target.Owner), message))
		} else {
			state = checkreport.CheckWarning
			findings = append(findings, makeFinding("dnsrr_dnssec_not_secure", checkreport.StatusWarning, dns.Fqdn(target.Owner), message))
		}
	case dnsresolver.SecurityBogus:
		message = fmt.Sprintf("%s lookup failed DNSSEC validation: %s", target.RRTypeRaw, emptyStringAsDash(lookup.ValidationMessage))
		state = checkreport.CheckCritical
		findings = append(findings, makeFinding("dnsrr_dnssec_validation_failed", checkreport.StatusCritical, dns.Fqdn(target.Owner), message))
	default:
		message = fmt.Sprintf("%s lookup DNSSEC state was inconclusive: %s", target.RRTypeRaw, emptyStringAsDash(lookup.ValidationMessage))
		if mode == dnsprobe.DNSSECRequire {
			state = checkreport.CheckCritical
			findings = append(findings, makeFinding("dnsrr_dnssec_inconclusive", checkreport.StatusCritical, dns.Fqdn(target.Owner), message))
		} else {
			state = checkreport.CheckUnknown
			findings = append(findings, makeFinding("dnsrr_dnssec_inconclusive", checkreport.StatusUnknown, dns.Fqdn(target.Owner), message))
		}
	}
	stage.Status = dnsprobe.StatusFromCheckState(state)
	stage.Checks = append(stage.Checks, checkreport.Check{
		ID:      "dnssec.state",
		State:   state,
		Subject: dns.Fqdn(target.Owner),
		Message: message,
	})
	return stage, findings, metric
}

func dnssecMetricForMode(mode dnsprobe.DNSSECMode, state dnsresolver.SecurityState) checkreport.Metric {
	value := dnssecMetricValue(mode, state)
	display := fmt.Sprintf("%.0f", value)
	return checkreport.Metric{
		Name:   "dnssec_status",
		Type:   "state",
		Unit:   "status",
		Value:  display,
		Number: &value,
	}
}

func dnssecMetricValue(mode dnsprobe.DNSSECMode, state dnsresolver.SecurityState) float64 {
	if mode == dnsprobe.DNSSECIgnore {
		return -1
	}
	switch state {
	case dnsresolver.SecuritySecure:
		return 3
	case dnsresolver.SecurityInsecure:
		return 2
	case dnsresolver.SecurityBogus:
		return 1
	default:
		return 0
	}
}

func finalizeReport(report *checkreport.Report, cfg Config, started time.Time) {
	report.Findings, report.SuppressedFindings = checkreport.PartitionSuppressedFindings(report.Findings, cfg.IgnoreErrorSet)
	report.Status = aggregateStatus(report.Findings)
	if report.Status == checkreport.StatusOK && len(report.SuppressedFindings) > 0 {
		report.Summary = "all DNS RR findings were suppressed"
	}
	report.Metrics = append(report.Metrics,
		countMetric("findings", len(report.Findings)),
		countMetric("ignored", len(report.SuppressedFindings)),
	)
	report.DurationMS = time.Since(started).Milliseconds()
	if report.Status == "" {
		report.Status = checkreport.StatusOK
	}
	if report.Summary == "" {
		report.Summary = "authoritative DNS RR evaluation completed"
	}
}

func aggregateStatus(findings []checkreport.Finding) checkreport.Status {
	status := checkreport.StatusOK
	for _, finding := range findings {
		switch finding.Severity {
		case checkreport.StatusCritical:
			return checkreport.StatusCritical
		case checkreport.StatusUnknown:
			if status != checkreport.StatusCritical {
				status = checkreport.StatusUnknown
			}
		case checkreport.StatusWarning:
			if status == checkreport.StatusOK {
				status = checkreport.StatusWarning
			}
		}
	}
	return status
}

func countMetric(name string, n int) checkreport.Metric {
	value := float64(n)
	return checkreport.Metric{Name: name, Type: "count", Unit: "items", Value: fmt.Sprintf("%d", n), Number: &value}
}

func emptyStringAsDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
