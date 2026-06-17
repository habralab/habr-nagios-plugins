package dnschain

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/core/dnsresolver"
	"github.com/miekg/dns"
)

type ownerProbeResult struct {
	Findings []checkreport.Finding
	Traces   []checkreport.TraceEvent
}

type ownerEndpointResult struct {
	Endpoint     nsAddr
	CNAMETargets []string
	ARecords     []string
	AAAARecords  []string
	AddressOwner string
	Fingerprint  string
}

func probeOwnerName(ctx context.Context, resolver *dnsresolver.Resolver, owner, zone string, servers []nsAddr) (checkreport.Stage, ownerProbeResult) {
	stage := checkreport.Stage{
		ID:     "owner.rrset",
		Title:  "Owner RRset",
		Status: checkreport.StatusOK,
		Target: owner,
	}
	result := ownerProbeResult{}
	var baseline string
	var sawData bool
	var sawCNAME bool
	var sawAddress bool
	var sawForeignZoneCNAME bool
	authority := dnsresolver.AuthoritativeServersFromAddrs(internalServerAddrs(servers))
	aResults, err := resolver.ResolveAuthoritative(ctx, owner, dns.TypeA, authority, dnsresolver.ResolveOptions{
		Fanout: dnsresolver.FanoutAllAuthoritative,
	})
	if err != nil {
		stage.Status = checkreport.StatusUnknown
		stage.Checks = append(stage.Checks, checkreport.Check{
			ID:      "owner.a",
			State:   checkreport.CheckUnknown,
			Subject: owner,
			Message: fmt.Sprintf("authoritative A fanout failed: %v", err),
		})
		result.Findings = append(result.Findings, unknownFinding("dnschain_owner_probe_failed", owner, fmt.Sprintf("authoritative A fanout failed: %v", err)))
		return stage, result
	}
	aaaaResults, err := resolver.ResolveAuthoritative(ctx, owner, dns.TypeAAAA, authority, dnsresolver.ResolveOptions{
		Fanout: dnsresolver.FanoutAllAuthoritative,
	})
	if err != nil {
		stage.Status = checkreport.StatusUnknown
		stage.Checks = append(stage.Checks, checkreport.Check{
			ID:      "owner.aaaa",
			State:   checkreport.CheckUnknown,
			Subject: owner,
			Message: fmt.Sprintf("authoritative AAAA fanout failed: %v", err),
		})
		result.Findings = append(result.Findings, unknownFinding("dnschain_owner_probe_failed", owner, fmt.Sprintf("authoritative AAAA fanout failed: %v", err)))
		return stage, result
	}
	aByEndpoint := responsesByEndpoint(aResults)
	aaaaByEndpoint := responsesByEndpoint(aaaaResults)

	for _, endpoint := range uniqueNSAddrs(servers) {
		var aMsg []dns.RR
		var aaaaMsg []dns.RR

		aRes, aSeen := aByEndpoint[endpoint.Addr]
		if aSeen && aRes.Error != "" {
			result.Findings = append(result.Findings, warningFinding("dnschain_nameserver_endpoint_unreachable", owner, fmt.Sprintf("owner A query failed via %s: %s", endpoint.Addr, aRes.Error)))
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "owner.a",
				State:   checkreport.CheckWarning,
				Subject: endpoint.Addr,
				Message: fmt.Sprintf("A query failed: %s", aRes.Error),
			})
		} else if aSeen && !aRes.Authoritative {
			result.Findings = append(result.Findings, warningFinding("dnschain_nameserver_endpoint_rrset_failed", owner, fmt.Sprintf("owner A response via %s was not authoritative", endpoint.Addr)))
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "owner.a",
				State:   checkreport.CheckWarning,
				Subject: endpoint.Addr,
				Message: "A response was not authoritative",
			})
		} else {
			aMsg = aRes.Records
		}

		aaaaRes, aaaaSeen := aaaaByEndpoint[endpoint.Addr]
		if aaaaSeen && aaaaRes.Error != "" {
			result.Findings = append(result.Findings, warningFinding("dnschain_nameserver_endpoint_unreachable", owner, fmt.Sprintf("owner AAAA query failed via %s: %s", endpoint.Addr, aaaaRes.Error)))
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "owner.aaaa",
				State:   checkreport.CheckWarning,
				Subject: endpoint.Addr,
				Message: fmt.Sprintf("AAAA query failed: %s", aaaaRes.Error),
			})
		} else if aaaaSeen && !aaaaRes.Authoritative {
			result.Findings = append(result.Findings, warningFinding("dnschain_nameserver_endpoint_rrset_failed", owner, fmt.Sprintf("owner AAAA response via %s was not authoritative", endpoint.Addr)))
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "owner.aaaa",
				State:   checkreport.CheckWarning,
				Subject: endpoint.Addr,
				Message: "AAAA response was not authoritative",
			})
		} else {
			aaaaMsg = aaaaRes.Records
		}

		if aMsg == nil && aaaaMsg == nil {
			continue
		}

		ownerState := ownerEndpointState(owner, aMsg, aaaaMsg)
		ownerState.Endpoint = endpoint
		if len(ownerState.CNAMETargets) > 0 && !ownerState.HasTerminalAddress() {
			ownerState = followSameZoneCNAMETerminal(ctx, resolver, endpoint, zone, ownerState, &stage, &result)
			if len(ownerState.CNAMETargets) > 0 && !ownerState.HasTerminalAddress() && !allTargetsWithinZone(ownerState.CNAMETargets, zone) {
				sawForeignZoneCNAME = true
			}
		}
		if ownerState.Fingerprint != "" {
			sawData = true
		}
		if len(ownerState.CNAMETargets) > 0 {
			sawCNAME = true
		}
		if ownerState.HasTerminalAddress() {
			sawAddress = true
		}
		if ownerState.Fingerprint != "" {
			if baseline == "" {
				baseline = ownerState.Fingerprint
			} else if baseline != ownerState.Fingerprint {
				result.Findings = append(result.Findings, warningFinding("dnschain_owner_rrset_inconsistent", owner, fmt.Sprintf("authoritative endpoint %s served a different owner RRset for %s", endpoint.Addr, owner)))
			}
		}
		stage.Checks = append(stage.Checks, checkreport.Check{
			ID:           "owner.endpoint",
			State:        checkreport.CheckPass,
			Subject:      endpoint.Addr,
			Message:      ownerEndpointMessage(ownerState),
			MinVerbosity: 2,
		})
	}

	if !sawData {
		stage.Status = checkreport.StatusCritical
		stage.Checks = append(stage.Checks, checkreport.Check{
			ID:      "owner.presence",
			State:   checkreport.CheckCritical,
			Subject: owner,
			Message: "no authoritative endpoint returned CNAME, A, or AAAA data for the requested owner name",
		})
		result.Findings = append(result.Findings, criticalFinding("dnschain_owner_rr_missing", owner, "the requested owner name has no CNAME, A, or AAAA RRset on the authoritative servers"))
		return stage, result
	}

	consistencyState := checkStateFromFinding(result.Findings, "dnschain_owner_rrset_inconsistent")
	stage.Checks = append(stage.Checks, checkreport.Check{
		ID:      "owner.consistency",
		State:   consistencyState,
		Subject: owner,
		Message: consistencyMessage("owner RRset", consistencyState),
	})

	switch {
	case sawAddress:
		stage.Checks = append(stage.Checks, checkreport.Check{
			ID:      "owner.presence",
			State:   checkreport.CheckPass,
			Subject: owner,
			Message: "the requested owner name published at least one terminal address RRset",
		})
	case sawCNAME:
		stage.Checks = append(stage.Checks, checkreport.Check{
			ID:      "owner.presence",
			State:   checkreport.CheckPass,
			Subject: owner,
			Message: "the requested owner name published a CNAME RRset; same-zone terminal targets were followed, but foreign-zone target validation is not implemented yet",
		})
		if sawForeignZoneCNAME {
			stage.Notes = append(stage.Notes, "Foreign-zone CNAME targets are recognized as owner-level presence, but recursive cross-zone target validation is not implemented yet")
		}
	}

	ownerStateStatus := aggregateStatus(result.Findings)
	if ownerStateStatus != checkreport.StatusOK {
		stage.Status = ownerStateStatus
	}
	return stage, result
}

func ownerEndpointState(owner string, rrsets ...[]dns.RR) ownerEndpointResult {
	state := ownerEndpointResult{}
	cnameSet := map[string]bool{}
	aSet := map[string]bool{}
	aaaaSet := map[string]bool{}
	fqdnOwner := dns.Fqdn(owner)

	for _, rrset := range rrsets {
		if rrset == nil {
			continue
		}
		for _, rr := range rrset {
			switch v := rr.(type) {
			case *dns.CNAME:
				if dns.Fqdn(v.Header().Name) == fqdnOwner {
					cnameSet[dns.Fqdn(v.Target)] = true
				}
			case *dns.A:
				if dns.Fqdn(v.Header().Name) == fqdnOwner {
					aSet[v.A.String()] = true
				}
			case *dns.AAAA:
				if dns.Fqdn(v.Header().Name) == fqdnOwner {
					aaaaSet[v.AAAA.String()] = true
				}
			}
		}
	}

	state.CNAMETargets = sortedSetKeys(cnameSet)
	state.ARecords = sortedSetKeys(aSet)
	state.AAAARecords = sortedSetKeys(aaaaSet)
	if len(state.ARecords) > 0 || len(state.AAAARecords) > 0 {
		state.AddressOwner = fqdnOwner
	}
	if len(state.CNAMETargets) == 0 && len(state.ARecords) == 0 && len(state.AAAARecords) == 0 {
		return state
	}
	state.Fingerprint = fmt.Sprintf("cname=%s|addr_owner=%s|a=%s|aaaa=%s",
		strings.Join(state.CNAMETargets, ","),
		state.AddressOwner,
		strings.Join(state.ARecords, ","),
		strings.Join(state.AAAARecords, ","),
	)
	return state
}

func ownerEndpointMessage(state ownerEndpointResult) string {
	parts := make([]string, 0, 4)
	if len(state.CNAMETargets) > 0 {
		parts = append(parts, fmt.Sprintf("CNAME=%s", strings.Join(state.CNAMETargets, ",")))
	}
	if state.AddressOwner != "" && state.HasTerminalAddress() {
		parts = append(parts, fmt.Sprintf("terminal=%s", state.AddressOwner))
	}
	if len(state.ARecords) > 0 {
		parts = append(parts, fmt.Sprintf("A=%s", strings.Join(state.ARecords, ",")))
	}
	if len(state.AAAARecords) > 0 {
		parts = append(parts, fmt.Sprintf("AAAA=%s", strings.Join(state.AAAARecords, ",")))
	}
	if len(parts) == 0 {
		return "no owner RRset data returned"
	}
	return strings.Join(parts, " ")
}

func sortedSetKeys(values map[string]bool) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func (state ownerEndpointResult) HasTerminalAddress() bool {
	return len(state.ARecords) > 0 || len(state.AAAARecords) > 0
}

func followSameZoneCNAMETerminal(ctx context.Context, resolver *dnsresolver.Resolver, endpoint nsAddr, zone string, state ownerEndpointResult, stage *checkreport.Stage, result *ownerProbeResult) ownerEndpointResult {
	visited := map[string]bool{}
	if state.AddressOwner != "" {
		visited[dns.Fqdn(state.AddressOwner)] = true
	}

	const maxDepth = 8
	for depth := 0; depth < maxDepth; depth++ {
		target, ok := nextSameZoneCNAMETarget(state.CNAMETargets, zone, visited)
		if !ok {
			return state
		}
		visited[target] = true

		var aMsg []dns.RR
		var aaaaMsg []dns.RR

		aResolved, err := resolver.ResolveAuthoritative(ctx, target, dns.TypeA, []dnsresolver.AuthoritativeServer{{Name: endpoint.Name, Endpoint: endpoint.Addr}}, dnsresolver.ResolveOptions{
			Fanout: dnsresolver.FanoutAllAuthoritative,
		})
		if err != nil {
			result.Findings = append(result.Findings, warningFinding("dnschain_nameserver_endpoint_unreachable", target, fmt.Sprintf("terminal A query failed via %s: %v", endpoint.Addr, err)))
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "owner.terminal_a",
				State:   checkreport.CheckWarning,
				Subject: endpoint.Addr,
				Message: fmt.Sprintf("terminal A query for %s failed: %v", target, err),
			})
		} else if len(aResolved.Responses) == 0 && len(aResolved.Endpoints) > 0 {
			result.Findings = append(result.Findings, warningFinding("dnschain_nameserver_endpoint_rrset_failed", target, fmt.Sprintf("terminal A query via %s produced no authoritative response material", endpoint.Addr)))
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "owner.terminal_a",
				State:   checkreport.CheckWarning,
				Subject: endpoint.Addr,
				Message: fmt.Sprintf("terminal A query for %s produced no authoritative response material", target),
			})
		} else if aResolved.Responses[0].Error != "" {
			result.Findings = append(result.Findings, warningFinding("dnschain_nameserver_endpoint_unreachable", target, fmt.Sprintf("terminal A query failed via %s: %s", endpoint.Addr, aResolved.Responses[0].Error)))
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "owner.terminal_a",
				State:   checkreport.CheckWarning,
				Subject: endpoint.Addr,
				Message: fmt.Sprintf("terminal A query for %s failed: %s", target, aResolved.Responses[0].Error),
			})
		} else if !aResolved.Responses[0].Authoritative {
			result.Findings = append(result.Findings, warningFinding("dnschain_nameserver_endpoint_rrset_failed", target, fmt.Sprintf("terminal A response via %s was not authoritative", endpoint.Addr)))
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "owner.terminal_a",
				State:   checkreport.CheckWarning,
				Subject: endpoint.Addr,
				Message: fmt.Sprintf("terminal A response for %s was not authoritative", target),
			})
		} else {
			aMsg = aResolved.Responses[0].Records
		}

		aaaaResolved, err := resolver.ResolveAuthoritative(ctx, target, dns.TypeAAAA, []dnsresolver.AuthoritativeServer{{Name: endpoint.Name, Endpoint: endpoint.Addr}}, dnsresolver.ResolveOptions{
			Fanout: dnsresolver.FanoutAllAuthoritative,
		})
		if err != nil {
			result.Findings = append(result.Findings, warningFinding("dnschain_nameserver_endpoint_unreachable", target, fmt.Sprintf("terminal AAAA query failed via %s: %v", endpoint.Addr, err)))
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "owner.terminal_aaaa",
				State:   checkreport.CheckWarning,
				Subject: endpoint.Addr,
				Message: fmt.Sprintf("terminal AAAA query for %s failed: %v", target, err),
			})
		} else if len(aaaaResolved.Responses) == 0 && len(aaaaResolved.Endpoints) > 0 {
			result.Findings = append(result.Findings, warningFinding("dnschain_nameserver_endpoint_rrset_failed", target, fmt.Sprintf("terminal AAAA query via %s produced no authoritative response material", endpoint.Addr)))
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "owner.terminal_aaaa",
				State:   checkreport.CheckWarning,
				Subject: endpoint.Addr,
				Message: fmt.Sprintf("terminal AAAA query for %s produced no authoritative response material", target),
			})
		} else if aaaaResolved.Responses[0].Error != "" {
			result.Findings = append(result.Findings, warningFinding("dnschain_nameserver_endpoint_unreachable", target, fmt.Sprintf("terminal AAAA query failed via %s: %s", endpoint.Addr, aaaaResolved.Responses[0].Error)))
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "owner.terminal_aaaa",
				State:   checkreport.CheckWarning,
				Subject: endpoint.Addr,
				Message: fmt.Sprintf("terminal AAAA query for %s failed: %s", target, aaaaResolved.Responses[0].Error),
			})
		} else if !aaaaResolved.Responses[0].Authoritative {
			result.Findings = append(result.Findings, warningFinding("dnschain_nameserver_endpoint_rrset_failed", target, fmt.Sprintf("terminal AAAA response via %s was not authoritative", endpoint.Addr)))
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "owner.terminal_aaaa",
				State:   checkreport.CheckWarning,
				Subject: endpoint.Addr,
				Message: fmt.Sprintf("terminal AAAA response for %s was not authoritative", target),
			})
		} else {
			aaaaMsg = aaaaResolved.Responses[0].Records
		}

		if aMsg == nil && aaaaMsg == nil {
			return state
		}

		targetState := ownerEndpointState(target, aMsg, aaaaMsg)
		state = mergeOwnerEndpointState(state, targetState)
		if state.HasTerminalAddress() {
			return state
		}
	}
	return state
}

func nextSameZoneCNAMETarget(targets []string, zone string, visited map[string]bool) (string, bool) {
	for _, target := range targets {
		fqdnTarget := dns.Fqdn(target)
		if visited[fqdnTarget] {
			continue
		}
		if dns.IsSubDomain(dns.Fqdn(zone), fqdnTarget) {
			return fqdnTarget, true
		}
	}
	return "", false
}

func mergeOwnerEndpointState(base, next ownerEndpointResult) ownerEndpointResult {
	cnameSet := map[string]bool{}
	for _, value := range base.CNAMETargets {
		cnameSet[dns.Fqdn(value)] = true
	}
	for _, value := range next.CNAMETargets {
		cnameSet[dns.Fqdn(value)] = true
	}
	aSet := map[string]bool{}
	for _, value := range base.ARecords {
		aSet[value] = true
	}
	for _, value := range next.ARecords {
		aSet[value] = true
	}
	aaaaSet := map[string]bool{}
	for _, value := range base.AAAARecords {
		aaaaSet[value] = true
	}
	for _, value := range next.AAAARecords {
		aaaaSet[value] = true
	}

	base.CNAMETargets = sortedSetKeys(cnameSet)
	base.ARecords = sortedSetKeys(aSet)
	base.AAAARecords = sortedSetKeys(aaaaSet)
	if next.AddressOwner != "" {
		base.AddressOwner = next.AddressOwner
	}
	if len(base.CNAMETargets) == 0 && len(base.ARecords) == 0 && len(base.AAAARecords) == 0 {
		base.Fingerprint = ""
		return base
	}
	base.Fingerprint = fmt.Sprintf("cname=%s|addr_owner=%s|a=%s|aaaa=%s",
		strings.Join(base.CNAMETargets, ","),
		base.AddressOwner,
		strings.Join(base.ARecords, ","),
		strings.Join(base.AAAARecords, ","),
	)
	return base
}

func allTargetsWithinZone(targets []string, zone string) bool {
	if len(targets) == 0 {
		return false
	}
	for _, target := range targets {
		if !dns.IsSubDomain(dns.Fqdn(zone), dns.Fqdn(target)) {
			return false
		}
	}
	return true
}
