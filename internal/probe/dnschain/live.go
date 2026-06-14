package dnschain

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/miekg/dns"
)

type liveAnalyzer struct{}

func init() {
	DefaultAnalyzerFactory = func() Analyzer {
		return liveAnalyzer{}
	}
}

func (liveAnalyzer) Analyze(ctx context.Context, cfg Config, target string) (checkreport.Report, error) {
	ctx = withDNSQueryTimeout(ctx, cfg.QueryTimeout)
	started := time.Now()
	report := checkreport.Report{
		Probe:         Meta.Slug,
		Target:        target,
		PrimaryTarget: target,
		Targets: []checkreport.Target{
			{Role: "input", Value: target},
		},
		Status:       checkreport.StatusOK,
		Summary:      "authoritative DNS delegation and DNSSEC linkage look healthy",
		Partial:      true,
		CoverageNote: "DNSSEC coverage currently validates the root trust anchor, secure delegation hops, parent DS RRset signatures, child DNSKEY RRset signatures, parent-side authenticated denial for missing DS through exact NSEC/NSEC3 proofs and NSEC3 closest-encloser opt-out proofs, and sampled final-zone NSEC3 name-error and no-data proofs together with apex NSEC3PARAM policy and consistency; authoritative transport probing attempts both IPv4 and IPv6 endpoints when available, child-side SOA/NS/DNSKEY checks are evaluated per advertised endpoint, and hostname mode additionally verifies owner-level CNAME/A/AAAA presence and consistency on the final zone authoritative servers while following same-zone CNAME chains to terminal A/AAAA data, but without recursively validating foreign-zone CNAME targets yet",
		StartedAt:    started.UTC(),
		Meta: []checkreport.KV{
			{Key: "output_mode", Value: string(cfg.OutputMode)},
			{Key: "root_trust_anchors", Value: fmt.Sprintf("%d", len(rootTrustAnchors))},
		},
	}

	rootStage, rootProbe := probeRootTrustAnchors(ctx)
	report.Traces = append(report.Traces, rootProbe.Traces...)
	report.Stages = append(report.Stages, rootStage)
	report.Findings = append(report.Findings, rootProbe.Findings...)

	discovery, err := discoverAuthority(ctx, cfg, target)
	if err != nil {
		return buildUnknownReport(report, started, target, "dnschain_discovery_failed", fmt.Sprintf("zone discovery failed: %v", err), cfg.IgnoreErrorSet), nil
	}

	report.Targets = append(report.Targets,
		checkreport.Target{Role: "zone", Value: discovery.Zone},
		checkreport.Target{Role: "parent_zone", Value: discovery.ParentZone},
	)
	if strings.TrimSpace(cfg.Hostname) != "" {
		report.Targets = append(report.Targets, checkreport.Target{Role: "owner", Value: dns.Fqdn(strings.TrimSpace(cfg.Hostname))})
	}
	report.Traces = append(report.Traces, discovery.Traces...)
	report.Stages = append(report.Stages, discovery.Stage)

	childStage, childProbe := probeChildZone(ctx, discovery.Zone, discovery.ChildServers, discovery.DelegationNS)
	report.Traces = append(report.Traces, childProbe.Traces...)
	report.Stages = append(report.Stages, childStage)
	report.Findings = append(report.Findings, childProbe.Findings...)

	dnssecStage, dnssecProbe := probeDNSSECChain(ctx, discovery.Hops, rootProbe, childProbe)
	report.Traces = append(report.Traces, dnssecProbe.Traces...)
	report.Stages = append(report.Stages, dnssecStage)
	report.Findings = append(report.Findings, dnssecProbe.Findings...)

	if strings.TrimSpace(cfg.Hostname) != "" {
		ownerStage, ownerProbe := probeOwnerName(ctx, dns.Fqdn(strings.TrimSpace(cfg.Hostname)), discovery.Zone, discovery.ChildServers)
		report.Traces = append(report.Traces, ownerProbe.Traces...)
		report.Stages = append(report.Stages, ownerStage)
		report.Findings = append(report.Findings, ownerProbe.Findings...)
	}

	report.Findings, report.SuppressedFindings = checkreport.PartitionSuppressedFindings(report.Findings, cfg.IgnoreErrorSet)

	report.Status = aggregateStatus(report.Findings)
	report.Summary = aggregateSummary(report, report.EffectiveTarget())
	report.Metrics = []checkreport.Metric{
		countMetric("delegated_ns", len(discovery.DelegationNS)),
		countMetric("child_endpoints", len(discovery.ChildServers)),
		countMetric("reachable_servers", childProbe.ReachableServers),
		countMetric("reachable_endpoints", childProbe.ReachableEndpoints),
		countMetric("findings", len(report.Findings)),
		countMetric("ignored", len(report.SuppressedFindings)),
	}
	report.DurationMS = time.Since(started).Milliseconds()
	return report, nil
}

type discoveryResult struct {
	Zone          string
	ParentZone    string
	DelegationNS  []string
	ParentServers []nsAddr
	ChildServers  []nsAddr
	Hops          []delegationHop
	Stage         checkreport.Stage
	Traces        []checkreport.TraceEvent
}

func discoverAuthority(ctx context.Context, cfg Config, target string) (*discoveryResult, error) {
	fqdn := dns.Fqdn(target)
	zone := fqdn
	if strings.TrimSpace(cfg.Zone) == "" {
		iter, err := resolveIterative(ctx, fqdn, dns.TypeNS)
		if err != nil {
			return nil, err
		}
		if len(iter.Hops) == 0 {
			return nil, fmt.Errorf("no delegation hops discovered for %s", fqdn)
		}
		zone = iter.Hops[len(iter.Hops)-1].ToZone
	}

	hops, err := buildZoneChain(ctx, zone)
	if err != nil {
		return nil, err
	}
	if len(hops) == 0 {
		return nil, fmt.Errorf("no zone chain discovered for %s", zone)
	}

	last := hops[len(hops)-1]
	stage := checkreport.Stage{
		ID:     "zone.discovery",
		Title:  "Zone Discovery",
		Status: checkreport.StatusOK,
		Target: zone,
		Checks: []checkreport.Check{
			{
				ID:      "zone.cut",
				State:   checkreport.CheckPass,
				Subject: zone,
				Message: fmt.Sprintf("discovered zone cut %s via parent %s", last.ToZone, last.FromZone),
				Meta: []checkreport.KV{
					{Key: "explicit_zone", Value: fmt.Sprintf("%t", strings.TrimSpace(cfg.Zone) != "")},
				},
			},
		},
	}
	var traces []checkreport.TraceEvent
	for _, hop := range hops {
		traces = append(traces, checkreport.TraceEvent{
			Kind:    "delegation",
			StageID: "zone.discovery",
			State:   checkreport.CheckPass,
			Target:  hop.ToZone,
			Message: fmt.Sprintf("%s referred %s to %d child server addresses", hop.FromZone, hop.ToZone, len(hop.ChildServers)),
			Attributes: []checkreport.KV{
				{Key: "parent_server", Value: hop.ParentServer.Addr},
				{Key: "child_ns", Value: strings.Join(hop.ChildNS, ",")},
			},
		})
	}
	return &discoveryResult{
		Zone:          last.ToZone,
		ParentZone:    last.FromZone,
		DelegationNS:  append([]string(nil), last.ChildNS...),
		ParentServers: append([]nsAddr(nil), last.ParentServers...),
		ChildServers:  append([]nsAddr(nil), last.ChildServers...),
		Hops:          append([]delegationHop(nil), hops...),
		Stage:         stage,
		Traces:        traces,
	}, nil
}

type childProbeResult struct {
	ReachableServers   int
	ReachableEndpoints int
	Findings           []checkreport.Finding
	Traces             []checkreport.TraceEvent
	NS                 []string
	DNSKEYSets         []dnskeyEndpointResult
	DNSKEYFingerprints map[string]string
	NSEC3PARAMSets     map[string][]*dns.NSEC3PARAM
}

type dnskeyEndpointResult struct {
	Endpoint    nsAddr
	Keys        []*dns.DNSKEY
	Sigs        []*dns.RRSIG
	Fingerprint string
}

type nameserverEndpoints struct {
	Name      string
	Endpoints []nsAddr
}

func groupNSAddrsByName(values []nsAddr) []nameserverEndpoints {
	byName := map[string][]nsAddr{}
	var order []string
	for _, value := range values {
		name := dns.Fqdn(value.Name)
		if _, ok := byName[name]; !ok {
			order = append(order, name)
		}
		byName[name] = append(byName[name], value)
	}
	out := make([]nameserverEndpoints, 0, len(order))
	for _, name := range order {
		out = append(out, nameserverEndpoints{
			Name:      name,
			Endpoints: uniqueNSAddrs(byName[name]),
		})
	}
	return out
}

func probeChildZone(ctx context.Context, zone string, servers []nsAddr, delegatedNS []string) (checkreport.Stage, childProbeResult) {
	stage := checkreport.Stage{
		ID:     "child.authority",
		Title:  "Child Authority",
		Status: checkreport.StatusOK,
		Target: zone,
	}
	result := childProbeResult{}
	var nsBaseline []string
	var soaFingerprint string
	var dnskeyFingerprint string
	var nsec3ParamFingerprint string
	var nsec3ParamBaseline []*dns.NSEC3PARAM
	groups := groupNSAddrsByName(servers)

	for _, group := range groups {
		var groupReachable bool
		for _, endpoint := range group.Endpoints {
			soaRes, err := exchangeDNS(ctx, endpoint.Addr, zone, dns.TypeSOA, true)
			if err != nil {
				result.Findings = append(result.Findings, warningFinding("dnschain_nameserver_endpoint_unreachable", zone, fmt.Sprintf("%s SOA query failed via %s: %v", group.Name, endpoint.Addr, err)))
				stage.Checks = append(stage.Checks, checkreport.Check{
					ID:      "ns.endpoint",
					State:   checkreport.CheckWarning,
					Subject: endpoint.Addr,
					Message: fmt.Sprintf("%s SOA query failed: %v", group.Name, err),
				})
				continue
			}
			if !soaRes.Msg.Authoritative {
				result.Findings = append(result.Findings, criticalFinding("dnschain_lame_nameserver", zone, fmt.Sprintf("%s answered without AA for SOA via %s", group.Name, endpoint.Addr)))
				stage.Checks = append(stage.Checks, checkreport.Check{
					ID:      "ns.endpoint",
					State:   checkreport.CheckCritical,
					Subject: endpoint.Addr,
					Message: fmt.Sprintf("%s SOA response was not authoritative", group.Name),
				})
				continue
			}
			groupReachable = true
			result.ReachableEndpoints++
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:           "ns.endpoint",
				State:        checkreport.CheckPass,
				Subject:      endpoint.Addr,
				Message:      fmt.Sprintf("%s authoritative SOA response received", group.Name),
				MinVerbosity: 2,
			})
			result.Traces = append(result.Traces, checkreport.TraceEvent{
				Kind:    "query",
				StageID: "child.authority",
				State:   checkreport.CheckPass,
				Target:  zone,
				Message: fmt.Sprintf("SOA from %s over %s in %s", endpoint.Addr, soaRes.Network, soaRes.RTT),
			})
			if fp := soaAnswerFingerprint(soaRes.Msg, zone); fp != "" {
				if soaFingerprint == "" {
					soaFingerprint = fp
				} else if soaFingerprint != fp {
					result.Findings = append(result.Findings, warningFinding("dnschain_child_soa_inconsistent", zone, fmt.Sprintf("%s endpoint %s served a different SOA RRset", group.Name, endpoint.Addr)))
				}
			}

			nsRes, err := exchangeDNS(ctx, endpoint.Addr, zone, dns.TypeNS, true)
			if err != nil {
				result.Findings = append(result.Findings, warningFinding("dnschain_nameserver_endpoint_unreachable", zone, fmt.Sprintf("%s NS query failed via %s: %v", group.Name, endpoint.Addr, err)))
				stage.Checks = append(stage.Checks, checkreport.Check{
					ID:      "ns.endpoint_ns",
					State:   checkreport.CheckWarning,
					Subject: endpoint.Addr,
					Message: fmt.Sprintf("%s NS query failed: %v", group.Name, err),
				})
			} else if !nsRes.Msg.Authoritative {
				result.Findings = append(result.Findings, criticalFinding("dnschain_lame_nameserver", zone, fmt.Sprintf("%s answered without AA for NS via %s", group.Name, endpoint.Addr)))
				stage.Checks = append(stage.Checks, checkreport.Check{
					ID:      "ns.endpoint_ns",
					State:   checkreport.CheckCritical,
					Subject: endpoint.Addr,
					Message: fmt.Sprintf("%s NS response was not authoritative", group.Name),
				})
			} else {
				names := rrsetNames(nsRes.Msg, zone, dns.TypeNS)
				if len(names) > 0 {
					if nsBaseline == nil {
						nsBaseline = names
					} else if !equalStringSet(nsBaseline, names) {
						result.Findings = append(result.Findings, warningFinding("dnschain_child_ns_inconsistent", zone, fmt.Sprintf("%s endpoint %s served a different NS RRset", group.Name, endpoint.Addr)))
					}
				}
			}

			dnskeyRes, err := exchangeDNS(ctx, endpoint.Addr, zone, dns.TypeDNSKEY, true)
			if err != nil {
				result.Findings = append(result.Findings, warningFinding("dnschain_nameserver_endpoint_unreachable", zone, fmt.Sprintf("%s DNSKEY query failed via %s: %v", group.Name, endpoint.Addr, err)))
				stage.Checks = append(stage.Checks, checkreport.Check{
					ID:      "ns.endpoint_dnskey",
					State:   checkreport.CheckWarning,
					Subject: endpoint.Addr,
					Message: fmt.Sprintf("%s DNSKEY query failed: %v", group.Name, err),
				})
				continue
			}
			if !dnskeyRes.Msg.Authoritative {
				result.Findings = append(result.Findings, criticalFinding("dnschain_lame_nameserver", zone, fmt.Sprintf("%s answered without AA for DNSKEY via %s", group.Name, endpoint.Addr)))
				stage.Checks = append(stage.Checks, checkreport.Check{
					ID:      "ns.endpoint_dnskey",
					State:   checkreport.CheckCritical,
					Subject: endpoint.Addr,
					Message: fmt.Sprintf("%s DNSKEY response was not authoritative", group.Name),
				})
				continue
			}

			keys, sigs := splitDNSKEYAnswer(dnskeyRes.Msg.Answer, zone)
			if result.DNSKEYFingerprints == nil {
				result.DNSKEYFingerprints = map[string]string{}
			}
			fp := dnskeySetFingerprint(keys)
			if fp != "" {
				result.DNSKEYFingerprints[endpoint.Addr] = fp
				if dnskeyFingerprint == "" {
					dnskeyFingerprint = fp
				} else if dnskeyFingerprint != fp {
					result.Findings = append(result.Findings, warningFinding("dnschain_dnskey_rrset_inconsistent", zone, fmt.Sprintf("%s endpoint %s served a different DNSKEY RRset", group.Name, endpoint.Addr)))
				}
			}
			result.DNSKEYSets = append(result.DNSKEYSets, dnskeyEndpointResult{
				Endpoint:    endpoint,
				Keys:        keys,
				Sigs:        sigs,
				Fingerprint: fp,
			})

			nsec3ParamRes, err := exchangeDNS(ctx, endpoint.Addr, zone, dns.TypeNSEC3PARAM, true)
			if err != nil {
				result.Findings = append(result.Findings, warningFinding("dnschain_nameserver_endpoint_unreachable", zone, fmt.Sprintf("%s NSEC3PARAM query failed via %s: %v", group.Name, endpoint.Addr, err)))
				stage.Checks = append(stage.Checks, checkreport.Check{
					ID:      "ns.endpoint_nsec3param",
					State:   checkreport.CheckWarning,
					Subject: endpoint.Addr,
					Message: fmt.Sprintf("%s NSEC3PARAM query failed: %v", group.Name, err),
				})
				continue
			}
			if !nsec3ParamRes.Msg.Authoritative {
				result.Findings = append(result.Findings, criticalFinding("dnschain_lame_nameserver", zone, fmt.Sprintf("%s answered without AA for NSEC3PARAM via %s", group.Name, endpoint.Addr)))
				stage.Checks = append(stage.Checks, checkreport.Check{
					ID:      "ns.endpoint_nsec3param",
					State:   checkreport.CheckCritical,
					Subject: endpoint.Addr,
					Message: fmt.Sprintf("%s NSEC3PARAM response was not authoritative", group.Name),
				})
				continue
			}

			params := splitNSEC3PARAMAnswer(nsec3ParamRes.Msg.Answer, zone)
			if len(params) == 0 {
				continue
			}
			if result.NSEC3PARAMSets == nil {
				result.NSEC3PARAMSets = map[string][]*dns.NSEC3PARAM{}
			}
			result.NSEC3PARAMSets[endpoint.Addr] = params
			fpNSEC3 := nsec3ParamSetFingerprint(params)
			if nsec3ParamFingerprint == "" {
				nsec3ParamFingerprint = fpNSEC3
				nsec3ParamBaseline = params
			} else if nsec3ParamFingerprint != fpNSEC3 {
				result.Findings = append(result.Findings, warningFinding("dnschain_nsec3param_inconsistent", zone, fmt.Sprintf("%s endpoint %s served a different NSEC3PARAM RRset", group.Name, endpoint.Addr)))
			}
		}
		if !groupReachable {
			result.Findings = append(result.Findings, warningFinding("dnschain_nameserver_unreachable", zone, fmt.Sprintf("%s SOA query failed on all endpoints", group.Name)))
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "ns.reachability",
				State:   checkreport.CheckWarning,
				Subject: group.Name,
				Message: "SOA query failed on all endpoints",
			})
			continue
		}
		result.ReachableServers++
		stage.Checks = append(stage.Checks, checkreport.Check{
			ID:      "ns.authoritative",
			State:   checkreport.CheckPass,
			Subject: group.Name,
			Message: fmt.Sprintf("authoritative SOA response received on %d endpoint(s)", countReachableGroupEndpoints(group.Name, stage.Checks)),
		})
	}

	if result.ReachableServers == 0 {
		result.Findings = append(result.Findings, criticalFinding("dnschain_no_authoritative_servers", zone, "no delegated authoritative server returned an authoritative SOA response"))
		stage.Status = checkreport.StatusCritical
	} else if result.ReachableServers < len(groups) {
		result.Findings = append(result.Findings, warningFinding("dnschain_partial_authoritative_reachability", zone, fmt.Sprintf("%d of %d delegated name servers answered authoritatively", result.ReachableServers, len(groups))))
		stage.Status = checkreport.StatusWarning
	}

	if len(nsBaseline) > 0 {
		result.NS = nsBaseline
		if !equalStringSet(nsBaseline, delegatedNS) {
			result.Findings = append(result.Findings, warningFinding("dnschain_delegation_ns_mismatch", zone, "delegation NS set differs from child authoritative NS RRset"))
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "ns.delegation_match",
				State:   checkreport.CheckWarning,
				Subject: zone,
				Message: "delegation NS set differs from child authoritative NS RRset",
			})
			if stage.Status == checkreport.StatusOK {
				stage.Status = checkreport.StatusWarning
			}
		} else {
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "ns.delegation_match",
				State:   checkreport.CheckPass,
				Subject: zone,
				Message: "delegation NS set matches child authoritative NS RRset",
			})
		}
	}
	if soaFingerprint != "" {
		state := checkStateFromFinding(result.Findings, "dnschain_child_soa_inconsistent")
		stage.Checks = append(stage.Checks, checkreport.Check{
			ID:      "soa.consistency",
			State:   state,
			Subject: zone,
			Message: consistencyMessage("SOA RRset", state),
		})
	}
	if dnskeyFingerprint != "" {
		state := checkStateFromFinding(result.Findings, "dnschain_dnskey_rrset_inconsistent")
		stage.Checks = append(stage.Checks, checkreport.Check{
			ID:      "dnskey.consistency",
			State:   state,
			Subject: zone,
			Message: consistencyMessage("DNSKEY RRset", state),
		})
	}
	if nsec3ParamFingerprint != "" {
		state := checkStateFromFinding(result.Findings, "dnschain_nsec3param_inconsistent")
		stage.Checks = append(stage.Checks, checkreport.Check{
			ID:      "nsec3param.consistency",
			State:   state,
			Subject: zone,
			Message: consistencyMessage("NSEC3PARAM RRset", state),
		})
		assessment := assessNSEC3ParamPolicy(nsec3ParamBaseline)
		if assessment.State != "" {
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:       "nsec3param.policy",
				State:    assessment.State,
				Subject:  zone,
				Message:  assessment.Message,
				Evidence: assessment.Evidence,
			})
			if assessment.State == checkreport.CheckWarning {
				result.Findings = append(result.Findings, warningFinding("dnschain_nsec3param_not_recommended", zone, assessment.Message))
			}
		}
	}
	childState := aggregateStatus(result.Findings)
	if childState != checkreport.StatusOK {
		stage.Status = childState
	}
	return stage, result
}

type dnssecProbeResult struct {
	Findings []checkreport.Finding
	Traces   []checkreport.TraceEvent
}

type parentDSEndpointResult struct {
	Endpoint nsAddr
	Msg      *dns.Msg
	Records  []*dns.DS
	Sigs     []*dns.RRSIG
}

type dsSEPAssessment struct {
	Matched bool
	Signed  bool
}

type dsSEPAlgorithmAssessment struct {
	TotalAlgorithms  int
	SignedAlgorithms int
}

type dsCoverageSummary struct {
	MatchedDSCount  int
	TotalDSCount    int
	UnmatchedDS     []string
	UnsignedMatched []string
}

type rootAnchorProbeResult struct {
	Findings      []checkreport.Finding
	Traces        []checkreport.TraceEvent
	ValidatedKeys []*dns.DNSKEY
}

func probeRootTrustAnchors(ctx context.Context) (checkreport.Stage, rootAnchorProbeResult) {
	stage := checkreport.Stage{
		ID:     "dnssec.root_anchor",
		Title:  "Root Trust Anchor",
		Status: checkreport.StatusOK,
		Target: ".",
	}
	result := rootAnchorProbeResult{}

	res, err := queryAny(ctx, rootHintsAny, ".", dns.TypeDNSKEY, true)
	if err != nil {
		stage.Status = checkreport.StatusUnknown
		stage.Checks = append(stage.Checks, checkreport.Check{
			ID:      "root.dnskey_fetch",
			State:   checkreport.CheckUnknown,
			Subject: ".",
			Message: fmt.Sprintf("root DNSKEY lookup failed: %v", err),
		})
		result.Findings = append(result.Findings, unknownFinding("dnschain_root_dnskey_fetch_failed", ".", fmt.Sprintf("root DNSKEY lookup failed: %v", err)))
		return stage, result
	}

	keys, sigs := splitDNSKEYAnswer(res.Msg.Answer, ".")
	if len(keys) == 0 {
		stage.Status = checkreport.StatusCritical
		stage.Checks = append(stage.Checks, checkreport.Check{
			ID:      "root.dnskey_presence",
			State:   checkreport.CheckCritical,
			Subject: res.Server.Addr,
			Message: "root DNSKEY RRset was not returned",
		})
		result.Findings = append(result.Findings, criticalFinding("dnschain_root_dnskey_missing", ".", "root DNSKEY RRset was not returned"))
		return stage, result
	}

	matched, missing, anchoredKeys := matchRootTrustAnchorKeys(keys)
	if matched == 0 {
		stage.Status = checkreport.StatusCritical
		stage.Checks = append(stage.Checks, checkreport.Check{
			ID:      "root.anchor_match",
			State:   checkreport.CheckCritical,
			Subject: res.Server.Addr,
			Message: "none of the embedded root trust anchors matched the published root DNSKEY RRset",
		})
		result.Findings = append(result.Findings, criticalFinding("dnschain_root_anchor_mismatch", ".", "none of the embedded root trust anchors matched the published root DNSKEY RRset"))
		return stage, result
	}
	stage.Checks = append(stage.Checks, checkreport.Check{
		ID:      "root.anchor_match",
		State:   checkreport.CheckPass,
		Subject: res.Server.Addr,
		Message: fmt.Sprintf("%d root trust anchor(s) matched the published root DNSKEY RRset", matched),
		Meta: []checkreport.KV{
			{Key: "missing_anchors", Value: fmt.Sprintf("%d", missing)},
		},
	})
	if missing > 0 {
		result.Findings = append(result.Findings, warningFinding("dnschain_root_anchor_partial_match", ".", fmt.Sprintf("%d current root trust anchor(s) were not present in the published root DNSKEY RRset", missing)))
		if stage.Status == checkreport.StatusOK {
			stage.Status = checkreport.StatusWarning
		}
	}

	if len(sigs) == 0 {
		stage.Status = checkreport.StatusCritical
		stage.Checks = append(stage.Checks, checkreport.Check{
			ID:      "root.dnskey_rrsig",
			State:   checkreport.CheckCritical,
			Subject: ".",
			Message: "root DNSKEY RRset had no RRSIG records",
		})
		result.Findings = append(result.Findings, criticalFinding("dnschain_root_dnskey_rrsig_missing", ".", "root DNSKEY RRset had no RRSIG records"))
		return stage, result
	}

	if err := verifyRRSIGSet(anchoredKeys, sigs, keys, time.Now().UTC()); err != nil {
		stage.Status = checkreport.StatusCritical
		stage.Checks = append(stage.Checks, checkreport.Check{
			ID:      "root.dnskey_rrsig",
			State:   checkreport.CheckCritical,
			Subject: ".",
			Message: fmt.Sprintf("root DNSKEY RRset signature validation failed: %v", err),
		})
		result.Findings = append(result.Findings, criticalFinding("dnschain_root_dnskey_rrsig_invalid", ".", fmt.Sprintf("root DNSKEY RRset signature validation failed: %v", err)))
		return stage, result
	}

	stage.Checks = append(stage.Checks, checkreport.Check{
		ID:      "root.dnskey_rrsig",
		State:   checkreport.CheckPass,
		Subject: ".",
		Message: "root DNSKEY RRset signatures validated with an embedded trust anchor",
	})
	result.ValidatedKeys = append(result.ValidatedKeys, keys...)
	result.Traces = append(result.Traces, checkreport.TraceEvent{
		Kind:    "dnssec",
		StageID: "dnssec.root_anchor",
		State:   checkreport.CheckPass,
		Target:  ".",
		Message: fmt.Sprintf("root DNSKEY validated via %d embedded trust anchor(s) from %s", matched, res.Server.Addr),
	})
	return stage, result
}

func probeDNSSECChain(ctx context.Context, hops []delegationHop, root rootAnchorProbeResult, child childProbeResult) (checkreport.Stage, dnssecProbeResult) {
	stage := checkreport.Stage{
		ID:     "dnssec.chain",
		Title:  "DNSSEC Chain",
		Status: checkreport.StatusOK,
		Target: ".",
	}
	result := dnssecProbeResult{}

	if len(hops) == 0 {
		stage.Status = checkreport.StatusUnknown
		stage.Checks = append(stage.Checks, checkreport.Check{
			ID:      "chain.discovery",
			State:   checkreport.CheckUnknown,
			Subject: ".",
			Message: "no delegation hops were available for DNSSEC chain validation",
		})
		result.Findings = append(result.Findings, unknownFinding("dnschain_dnssec_chain_unavailable", ".", "no delegation hops were available for DNSSEC chain validation"))
		return stage, result
	}
	if len(root.ValidatedKeys) == 0 {
		stage.Status = checkreport.StatusUnknown
		stage.Checks = append(stage.Checks, checkreport.Check{
			ID:      "root.trust_state",
			State:   checkreport.CheckUnknown,
			Subject: ".",
			Message: "root trust anchor validation did not yield a trusted root DNSKEY RRset",
		})
		result.Findings = append(result.Findings, unknownFinding("dnschain_root_trust_state_unknown", ".", "root trust anchor validation did not yield a trusted root DNSKEY RRset"))
		return stage, result
	}

	stage.Target = hops[len(hops)-1].ToZone
	trustedKeys := append([]*dns.DNSKEY(nil), root.ValidatedKeys...)

	for i, hop := range hops {
		parentDSResponses := collectParentDSEndpointResponses(ctx, hop, &stage, &result)
		if len(parentDSResponses) == 0 {
			if stage.Status == checkreport.StatusOK {
				stage.Status = checkreport.StatusUnknown
			}
			return stage, result
		}

		parentDSState, parentDSMessage, parentDSFinding := assessParentDSConsistencyResponses(hop, parentDSResponses)
		if parentDSMessage != "" {
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "parent.ds_consistency",
				State:   parentDSState,
				Subject: hop.ToZone,
				Message: parentDSMessage,
			})
		}
		if parentDSFinding != nil {
			result.Findings = append(result.Findings, *parentDSFinding)
		}
		dsRecords, _, insecure, stop := validateParentDSEndpoints(hop, parentDSResponses, trustedKeys, &stage, &result)
		if stop {
			return stage, result
		}
		if insecure {
			return stage, result
		}

		var keys []*dns.DNSKEY
		var sigs []*dns.RRSIG
		var dnskeySets []dnskeyEndpointResult
		var err error
		switch {
		case i == len(hops)-1 && len(child.DNSKEYSets) > 0:
			dnskeySets = append([]dnskeyEndpointResult(nil), child.DNSKEYSets...)
		default:
			dnskeySets, err = collectDNSKEYEndpointSets(ctx, hop.ToZone, hop.ChildServers)
			if err != nil {
				stage.Status = checkreport.StatusCritical
				stage.Checks = append(stage.Checks, checkreport.Check{
					ID:      "child.dnskey_lookup",
					State:   checkreport.CheckCritical,
					Subject: hop.ToZone,
					Message: fmt.Sprintf("DNSKEY lookup failed: %v", err),
				})
				result.Findings = append(result.Findings, criticalFinding("dnschain_dnskey_lookup_failed", hop.ToZone, fmt.Sprintf("DNSKEY lookup failed: %v", err)))
				return stage, result
			}
		}
		if len(dnskeySets) > 0 {
			keys = append(keys, dnskeySets[0].Keys...)
			sigs = append(sigs, dnskeySets[0].Sigs...)
		}
		if len(keys) == 0 {
			stage.Status = checkreport.StatusCritical
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "child.dnskey_presence",
				State:   checkreport.CheckCritical,
				Subject: hop.ToZone,
				Message: "parent publishes DS records but no child DNSKEY RRset was obtained",
			})
			result.Findings = append(result.Findings, criticalFinding("dnschain_dnskey_missing", hop.ToZone, "parent publishes DS records but no child DNSKEY RRset was obtained"))
			return stage, result
		}
		if len(sigs) == 0 {
			stage.Status = checkreport.StatusCritical
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "child.dnskey_rrsig",
				State:   checkreport.CheckCritical,
				Subject: hop.ToZone,
				Message: "child DNSKEY RRset had no RRSIG records",
			})
			result.Findings = append(result.Findings, criticalFinding("dnschain_dnskey_rrsig_missing", hop.ToZone, "child DNSKEY RRset had no RRSIG records"))
			return stage, result
		}

		matchedKeys := matchingDNSKEYs(dsRecords, keys)
		if len(matchedKeys) == 0 {
			stage.Status = checkreport.StatusCritical
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "ds.dnskey_match",
				State:   checkreport.CheckCritical,
				Subject: hop.ToZone,
				Message: "no parent DS record matches any child DNSKEY",
			})
			result.Findings = append(result.Findings, criticalFinding("dnschain_ds_dnskey_mismatch", hop.ToZone, "no parent DS record matches any child DNSKEY"))
			return stage, result
		}
		partialSEPCoverage := map[string]int{}
		for _, set := range dnskeySets {
			endpointMatchedKeys := matchingDNSKEYs(dsRecords, set.Keys)
			if len(endpointMatchedKeys) == 0 {
				stage.Status = checkreport.StatusCritical
				stage.Checks = append(stage.Checks, checkreport.Check{
					ID:      "child.dnskey_endpoint",
					State:   checkreport.CheckCritical,
					Subject: set.Endpoint.Addr,
					Message: fmt.Sprintf("authoritative endpoint %s served a DNSKEY RRset that does not match any parent DS record", set.Endpoint.Addr),
				})
				result.Findings = append(result.Findings, criticalFinding("dnschain_ds_dnskey_mismatch", hop.ToZone, fmt.Sprintf("authoritative endpoint %s served a DNSKEY RRset that does not match any parent DS record", set.Endpoint.Addr)))
				return stage, result
			}
			if len(set.Sigs) == 0 {
				stage.Status = checkreport.StatusCritical
				stage.Checks = append(stage.Checks, checkreport.Check{
					ID:      "child.dnskey_endpoint",
					State:   checkreport.CheckCritical,
					Subject: set.Endpoint.Addr,
					Message: "authoritative endpoint returned a DNSKEY RRset without RRSIG coverage",
				})
				result.Findings = append(result.Findings, criticalFinding("dnschain_dnskey_rrsig_missing", hop.ToZone, fmt.Sprintf("authoritative endpoint %s returned a DNSKEY RRset without RRSIG coverage", set.Endpoint.Addr)))
				return stage, result
			}
			sepByDS := assessSecureEntryPoints(dsRecords, set.Keys, set.Sigs, time.Now().UTC())
			signedSEPCount := 0
			for _, assessment := range sepByDS {
				if assessment.Signed {
					signedSEPCount++
				}
			}
			if signedSEPCount == 0 {
				stage.Status = checkreport.StatusCritical
				stage.Checks = append(stage.Checks, checkreport.Check{
					ID:      "child.sep_endpoint",
					State:   checkreport.CheckCritical,
					Subject: set.Endpoint.Addr,
					Message: "no secure entry point was established from the parent DS RRset on this authoritative endpoint",
				})
				result.Findings = append(result.Findings, criticalFinding("dnschain_no_secure_entry_point", hop.ToZone, fmt.Sprintf("authoritative endpoint %s did not establish any secure entry point from the parent DS RRset", set.Endpoint.Addr)))
				return stage, result
			}
			algCoverage := assessSecureEntryPointAlgorithms(dsRecords, set.Keys, set.Sigs, time.Now().UTC())
			if algCoverage.SignedAlgorithms < algCoverage.TotalAlgorithms {
				stage.Checks = append(stage.Checks, checkreport.Check{
					ID:      "child.sep_endpoint",
					State:   checkreport.CheckWarning,
					Subject: set.Endpoint.Addr,
					Message: fmt.Sprintf("secure entry points covered only %d of %d parent DS algorithm(s) on this authoritative endpoint", algCoverage.SignedAlgorithms, algCoverage.TotalAlgorithms),
				})
				partialSEPCoverage[fmt.Sprintf("%d/%d", algCoverage.SignedAlgorithms, algCoverage.TotalAlgorithms)]++
			}
			if err := verifyRRSetWithDNSKEYs(endpointMatchedKeys, set.Sigs, dnskeysToRRs(set.Keys), time.Now().UTC()); err != nil {
				stage.Status = checkreport.StatusCritical
				stage.Checks = append(stage.Checks, checkreport.Check{
					ID:      "child.dnskey_endpoint",
					State:   checkreport.CheckCritical,
					Subject: set.Endpoint.Addr,
					Message: fmt.Sprintf("authoritative endpoint served an invalid DNSKEY RRset signature set: %v", err),
				})
				result.Findings = append(result.Findings, criticalFinding("dnschain_dnskey_rrsig_invalid", hop.ToZone, fmt.Sprintf("authoritative endpoint %s served an invalid DNSKEY RRset signature set: %v", set.Endpoint.Addr, err)))
				return stage, result
			}
		}
		for ratio, endpoints := range partialSEPCoverage {
			result.Findings = append(result.Findings, warningFinding("dnschain_ds_partial_sep_coverage", hop.ToZone, fmt.Sprintf("%d authoritative endpoint(s) established secure entry points for only %s parent DS algorithm(s)", endpoints, ratio)))
		}
		if err := verifyRRSetWithDNSKEYs(matchedKeys, sigs, dnskeysToRRs(keys), time.Now().UTC()); err != nil {
			stage.Status = checkreport.StatusCritical
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "child.dnskey_rrsig",
				State:   checkreport.CheckCritical,
				Subject: hop.ToZone,
				Message: fmt.Sprintf("child DNSKEY RRset signature validation failed: %v", err),
			})
			result.Findings = append(result.Findings, criticalFinding("dnschain_dnskey_rrsig_invalid", hop.ToZone, fmt.Sprintf("child DNSKEY RRset signature validation failed: %v", err)))
			return stage, result
		}

		now := time.Now().UTC()
		dsCoverage := summarizeDSCoverage(dsRecords, keys, sigs, now)
		var dsCoverageEvidence []checkreport.Evidence
		if len(dsCoverage.UnmatchedDS) > 0 || len(dsCoverage.UnsignedMatched) > 0 {
			evidence := checkreport.Evidence{
				Kind:    "dnssec.ds_coverage",
				Summary: fmt.Sprintf("%d of %d parent DS record(s) matched active child DNSKEY material", dsCoverage.MatchedDSCount, dsCoverage.TotalDSCount),
				Attributes: []checkreport.KV{
					{Key: "matched_ds", Value: fmt.Sprintf("%d", dsCoverage.MatchedDSCount)},
					{Key: "total_ds", Value: fmt.Sprintf("%d", dsCoverage.TotalDSCount)},
				},
			}
			if len(dsCoverage.UnmatchedDS) > 0 {
				evidence.Attributes = append(evidence.Attributes, checkreport.KV{
					Key:   "unmatched_ds",
					Value: strings.Join(dsCoverage.UnmatchedDS, ", "),
				})
			}
			if len(dsCoverage.UnsignedMatched) > 0 {
				evidence.Attributes = append(evidence.Attributes, checkreport.KV{
					Key:   "matched_but_not_sep_ds",
					Value: strings.Join(dsCoverage.UnsignedMatched, ", "),
				})
			}
			dsCoverageEvidence = []checkreport.Evidence{evidence}
		}
		cryptoPolicy := assessCryptoPolicy(dsRecords, keys, sigs, now)
		dsCoverageEvidence = append(dsCoverageEvidence, cryptoPolicy.Evidence...)
		if len(cryptoPolicy.ActiveNotRecommendedAlgorithmNames) > 0 {
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "crypto.algorithm_not_recommended_active",
				State:   checkreport.CheckWarning,
				Subject: hop.ToZone,
				Message: fmt.Sprintf("active secure entry points rely on not-recommended DNSKEY algorithm(s): %s", strings.Join(cryptoPolicy.ActiveNotRecommendedAlgorithmNames, ", ")),
			})
			result.Findings = append(result.Findings, warningFinding("dnschain_algorithm_not_recommended_in_use", hop.ToZone, fmt.Sprintf("active secure entry points rely on not-recommended DNSKEY algorithm(s): %s", strings.Join(cryptoPolicy.ActiveNotRecommendedAlgorithmNames, ", "))))
		}
		if len(cryptoPolicy.ActiveMustNotAlgorithmNames) > 0 {
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "crypto.algorithm_must_not_active",
				State:   checkreport.CheckWarning,
				Subject: hop.ToZone,
				Message: fmt.Sprintf("active secure entry points rely on MUST-NOT DNSKEY algorithm(s): %s", strings.Join(cryptoPolicy.ActiveMustNotAlgorithmNames, ", ")),
			})
			result.Findings = append(result.Findings, warningFinding("dnschain_algorithm_must_not_in_use", hop.ToZone, fmt.Sprintf("active secure entry points rely on MUST-NOT DNSKEY algorithm(s): %s", strings.Join(cryptoPolicy.ActiveMustNotAlgorithmNames, ", "))))
		}
		if len(cryptoPolicy.ActiveNotRecommendedDigestNames) > 0 {
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "crypto.digest_not_recommended_active",
				State:   checkreport.CheckWarning,
				Subject: hop.ToZone,
				Message: fmt.Sprintf("active secure entry points rely on not-recommended DS digest(s): %s", strings.Join(cryptoPolicy.ActiveNotRecommendedDigestNames, ", ")),
			})
			result.Findings = append(result.Findings, warningFinding("dnschain_digest_not_recommended_in_use", hop.ToZone, fmt.Sprintf("active secure entry points rely on not-recommended DS digest(s): %s", strings.Join(cryptoPolicy.ActiveNotRecommendedDigestNames, ", "))))
		}
		if len(cryptoPolicy.ActiveMustNotDigestNames) > 0 {
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "crypto.digest_must_not_active",
				State:   checkreport.CheckWarning,
				Subject: hop.ToZone,
				Message: fmt.Sprintf("active secure entry points rely on MUST-NOT DS digest(s): %s", strings.Join(cryptoPolicy.ActiveMustNotDigestNames, ", ")),
			})
			result.Findings = append(result.Findings, warningFinding("dnschain_digest_must_not_in_use", hop.ToZone, fmt.Sprintf("active secure entry points rely on MUST-NOT DS digest(s): %s", strings.Join(cryptoPolicy.ActiveMustNotDigestNames, ", "))))
		}
		if len(cryptoPolicy.PublishedNotRecommendedAlgorithms) > 0 {
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "crypto.algorithm_not_recommended_published",
				State:   checkreport.CheckWarning,
				Subject: hop.ToZone,
				Message: fmt.Sprintf("published DNSKEY algorithm set includes not-recommended algorithm(s): %s", strings.Join(cryptoPolicy.PublishedNotRecommendedAlgorithms, ", ")),
			})
			result.Findings = append(result.Findings, warningFinding("dnschain_algorithm_not_recommended_published", hop.ToZone, fmt.Sprintf("published DNSKEY algorithm set includes not-recommended algorithm(s): %s", strings.Join(cryptoPolicy.PublishedNotRecommendedAlgorithms, ", "))))
		}
		if len(cryptoPolicy.PublishedMustNotAlgorithms) > 0 {
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "crypto.algorithm_must_not_published",
				State:   checkreport.CheckWarning,
				Subject: hop.ToZone,
				Message: fmt.Sprintf("published DNSKEY algorithm set includes MUST-NOT algorithm(s): %s", strings.Join(cryptoPolicy.PublishedMustNotAlgorithms, ", ")),
			})
			result.Findings = append(result.Findings, warningFinding("dnschain_algorithm_must_not_published", hop.ToZone, fmt.Sprintf("published DNSKEY algorithm set includes MUST-NOT algorithm(s): %s", strings.Join(cryptoPolicy.PublishedMustNotAlgorithms, ", "))))
		}
		if len(cryptoPolicy.PublishedNotRecommendedDigests) > 0 {
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "crypto.digest_not_recommended_published",
				State:   checkreport.CheckWarning,
				Subject: hop.ToZone,
				Message: fmt.Sprintf("published DS digest set includes not-recommended digest(s): %s", strings.Join(cryptoPolicy.PublishedNotRecommendedDigests, ", ")),
			})
			result.Findings = append(result.Findings, warningFinding("dnschain_digest_not_recommended_published", hop.ToZone, fmt.Sprintf("published DS digest set includes not-recommended digest(s): %s", strings.Join(cryptoPolicy.PublishedNotRecommendedDigests, ", "))))
		}
		if len(cryptoPolicy.PublishedMustNotDigests) > 0 {
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "crypto.digest_must_not_published",
				State:   checkreport.CheckWarning,
				Subject: hop.ToZone,
				Message: fmt.Sprintf("published DS digest set includes MUST-NOT digest(s): %s", strings.Join(cryptoPolicy.PublishedMustNotDigests, ", ")),
			})
			result.Findings = append(result.Findings, warningFinding("dnschain_digest_must_not_published", hop.ToZone, fmt.Sprintf("published DS digest set includes MUST-NOT digest(s): %s", strings.Join(cryptoPolicy.PublishedMustNotDigests, ", "))))
		}
		if len(cryptoPolicy.PublishedUnsupportedAlgorithms) > 0 {
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "crypto.algorithm_unsupported_published",
				State:   checkreport.CheckWarning,
				Subject: hop.ToZone,
				Message: fmt.Sprintf("published DNSKEY algorithm set includes algorithm(s) the checker cannot validate: %s", strings.Join(cryptoPolicy.PublishedUnsupportedAlgorithms, ", ")),
			})
			result.Findings = append(result.Findings, warningFinding("dnschain_algorithm_unsupported_published", hop.ToZone, fmt.Sprintf("published DNSKEY algorithm set includes algorithm(s) the checker cannot validate: %s", strings.Join(cryptoPolicy.PublishedUnsupportedAlgorithms, ", "))))
		}
		if len(cryptoPolicy.PublishedUnsupportedDigestNames) > 0 {
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "crypto.digest_unsupported_published",
				State:   checkreport.CheckWarning,
				Subject: hop.ToZone,
				Message: fmt.Sprintf("published DS digest set includes digest(s) the checker cannot reproduce: %s", strings.Join(cryptoPolicy.PublishedUnsupportedDigestNames, ", ")),
			})
			result.Findings = append(result.Findings, warningFinding("dnschain_digest_unsupported_published", hop.ToZone, fmt.Sprintf("published DS digest set includes digest(s) the checker cannot reproduce: %s", strings.Join(cryptoPolicy.PublishedUnsupportedDigestNames, ", "))))
		}

		stage.Checks = append(stage.Checks,
			checkreport.Check{
				ID:       "ds.dnskey_match",
				State:    checkreport.CheckPass,
				Subject:  hop.ToZone,
				Message:  fmt.Sprintf("%d DS-matched DNSKEY record(s) established trust", len(matchedKeys)),
				Evidence: dsCoverageEvidence,
			},
			checkreport.Check{
				ID:      "child.dnskey_rrsig",
				State:   checkreport.CheckPass,
				Subject: hop.ToZone,
				Message: "child DNSKEY RRset signatures validated using DS-matched key material",
			},
		)
		result.Traces = append(result.Traces, checkreport.TraceEvent{
			Kind:    "dnssec",
			StageID: "dnssec.chain",
			State:   checkreport.CheckPass,
			Target:  hop.ToZone,
			Message: fmt.Sprintf("validated secure hop %s -> %s", hop.FromZone, hop.ToZone),
			Attributes: []checkreport.KV{
				{Key: "parent_server", Value: hop.ParentServer.Addr},
				{Key: "child_servers", Value: fmt.Sprintf("%d", len(hop.ChildServers))},
				{Key: "matched_dnskeys", Value: fmt.Sprintf("%d", len(matchedKeys))},
			},
		})
		trustedKeys = append([]*dns.DNSKEY(nil), keys...)
		if i == len(hops)-1 && len(child.NSEC3PARAMSets) > 0 {
			probeFinalZoneNSEC3Responses(ctx, hop.ToZone, hop.ChildServers, trustedKeys, &stage, &result)
		}
	}

	return stage, result
}

func collectParentDSEndpointResponses(ctx context.Context, hop delegationHop, stage *checkreport.Stage, result *dnssecProbeResult) []parentDSEndpointResult {
	var responses []parentDSEndpointResult
	for _, server := range uniqueNSAddrs(hop.ParentServers) {
		res, err := exchangeDNS(ctx, server.Addr, hop.ToZone, dns.TypeDS, true)
		if err != nil {
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "parent.ds_endpoint",
				State:   checkreport.CheckWarning,
				Subject: server.Addr,
				Message: fmt.Sprintf("DS lookup for %s failed: %v", hop.ToZone, err),
			})
			result.Findings = append(result.Findings, warningFinding("dnschain_nameserver_endpoint_unreachable", hop.ToZone, fmt.Sprintf("parent endpoint %s did not answer the DS lookup for %s: %v", server.Addr, hop.ToZone, err)))
			continue
		}
		if !res.Msg.Authoritative {
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "parent.ds_endpoint",
				State:   checkreport.CheckWarning,
				Subject: server.Addr,
				Message: fmt.Sprintf("DS response for %s was not authoritative", hop.ToZone),
			})
			result.Findings = append(result.Findings, warningFinding("dnschain_parent_ds_endpoint_failed", hop.ToZone, fmt.Sprintf("parent endpoint %s returned a non-authoritative DS response for %s", server.Addr, hop.ToZone)))
			continue
		}
		records, sigs := splitDSAnswer(res.Msg.Answer, hop.ToZone)
		responses = append(responses, parentDSEndpointResult{
			Endpoint: server,
			Msg:      res.Msg,
			Records:  records,
			Sigs:     sigs,
		})
	}
	if len(responses) == 0 {
		stage.Status = checkreport.StatusUnknown
		stage.Checks = append(stage.Checks, checkreport.Check{
			ID:      "parent.ds_lookup",
			State:   checkreport.CheckUnknown,
			Subject: hop.ToZone,
			Message: fmt.Sprintf("no authoritative parent endpoint returned a DS response for %s", hop.ToZone),
		})
		result.Findings = append(result.Findings, unknownFinding("dnschain_parent_ds_lookup_failed", hop.ToZone, fmt.Sprintf("no authoritative parent endpoint returned a DS response for %s", hop.ToZone)))
	}
	return responses
}

func validateParentDSEndpoints(hop delegationHop, responses []parentDSEndpointResult, trustedKeys []*dns.DNSKEY, stage *checkreport.Stage, result *dnssecProbeResult) ([]*dns.DS, []*dns.RRSIG, bool, bool) {
	now := time.Now().UTC()
	hasDSRecords := false
	hasNoDSRecords := false
	for _, response := range responses {
		if len(response.Records) == 0 {
			hasNoDSRecords = true
			denial, err := validateNoDSProof(hop.ToZone, response.Msg.Ns, trustedKeys, now)
			if err != nil {
				stage.Status = checkreport.StatusCritical
				stage.Checks = append(stage.Checks, checkreport.Check{
					ID:      "parent.ds_endpoint",
					State:   checkreport.CheckCritical,
					Subject: response.Endpoint.Addr,
					Message: fmt.Sprintf("missing DS denial proof validation failed: %v", err),
				})
				result.Findings = append(result.Findings, criticalFinding("dnschain_ds_absence_proof_invalid", hop.ToZone, fmt.Sprintf("missing DS denial proof validation failed via parent endpoint %s: %v", response.Endpoint.Addr, err)))
				return nil, nil, false, true
			}
			if ttlAssessment := assessDenialProofTTL(response.Msg.Ns); ttlAssessment != nil && ttlAssessment.State == checkreport.CheckWarning {
				stage.Checks = append(stage.Checks, checkreport.Check{
					ID:       "parent.denial_ttl_endpoint",
					State:    ttlAssessment.State,
					Subject:  response.Endpoint.Addr,
					Message:  ttlAssessment.Message,
					Evidence: ttlAssessment.Evidence,
				})
				result.Findings = append(result.Findings, warningFinding("dnschain_denial_ttl_unexpected", hop.ToZone, fmt.Sprintf("%s via parent endpoint %s", ttlAssessment.Message, response.Endpoint.Addr)))
			}
			result.Traces = append(result.Traces, checkreport.TraceEvent{
				Kind:    "dnssec",
				StageID: "dnssec.chain",
				State:   denial.State,
				Target:  hop.ToZone,
				Message: fmt.Sprintf("%s via parent endpoint %s", denial.TraceMessage, response.Endpoint.Addr),
			})
			continue
		}
		hasDSRecords = true
		if len(response.Sigs) == 0 {
			stage.Status = checkreport.StatusCritical
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "parent.ds_endpoint",
				State:   checkreport.CheckCritical,
				Subject: response.Endpoint.Addr,
				Message: "parent published DS records without RRSIG coverage",
			})
			result.Findings = append(result.Findings, criticalFinding("dnschain_ds_rrsig_missing", hop.ToZone, fmt.Sprintf("parent endpoint %s published DS records without RRSIG coverage", response.Endpoint.Addr)))
			return nil, nil, false, true
		}
		if err := verifyRRSetWithDNSKEYs(trustedKeys, response.Sigs, dsToRRs(response.Records), now); err != nil {
			stage.Status = checkreport.StatusCritical
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "parent.ds_endpoint",
				State:   checkreport.CheckCritical,
				Subject: response.Endpoint.Addr,
				Message: fmt.Sprintf("parent DS RRset signature validation failed: %v", err),
			})
			result.Findings = append(result.Findings, criticalFinding("dnschain_ds_rrsig_invalid", hop.ToZone, fmt.Sprintf("parent DS RRset signature validation failed via parent endpoint %s: %v", response.Endpoint.Addr, err)))
			return nil, nil, false, true
		}
	}

	if hasDSRecords && hasNoDSRecords {
		stage.Checks = append(stage.Checks, checkreport.Check{
			ID:      "parent.ds_mixed_state",
			State:   checkreport.CheckWarning,
			Subject: hop.ToZone,
			Message: "parent authoritative endpoints disagreed on whether DS records exist for the delegation",
		})
		result.Findings = append(result.Findings, warningFinding("dnschain_parent_ds_mixed_state", hop.ToZone, "parent authoritative endpoints disagreed on whether DS records exist for the delegation"))
	}

	baseline := responses[0]
	for _, response := range responses {
		if len(response.Records) > 0 {
			baseline = response
			break
		}
	}
	if len(baseline.Records) == 0 {
		denial, _ := validateNoDSProof(hop.ToZone, baseline.Msg.Ns, trustedKeys, now)
		stage.Checks = append(stage.Checks, checkreport.Check{
			ID:       "parent.ds_absence_proof",
			State:    denial.State,
			Subject:  hop.ToZone,
			Message:  denial.Message,
			Evidence: denial.Evidence,
		})
		if ttlAssessment := assessDenialProofTTL(baseline.Msg.Ns); ttlAssessment != nil {
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:       "parent.denial_ttl",
				State:    ttlAssessment.State,
				Subject:  hop.ToZone,
				Message:  ttlAssessment.Message,
				Evidence: ttlAssessment.Evidence,
			})
			if ttlAssessment.State == checkreport.CheckWarning {
				result.Findings = append(result.Findings, warningFinding("dnschain_denial_ttl_unexpected", hop.ToZone, ttlAssessment.Message))
			}
		}
		return nil, nil, true, false
	}

	stage.Checks = append(stage.Checks, checkreport.Check{
		ID:      "parent.ds_rrsig",
		State:   checkreport.CheckPass,
		Subject: hop.ToZone,
		Message: fmt.Sprintf("parent DS RRset for %s validated using trusted %s DNSKEY material", hop.ToZone, hop.FromZone),
	})
	return baseline.Records, baseline.Sigs, false, false
}

func assessSecureEntryPoints(dsRecords []*dns.DS, keys []*dns.DNSKEY, sigs []*dns.RRSIG, now time.Time) map[string]dsSEPAssessment {
	out := make(map[string]dsSEPAssessment, len(dsRecords))
	for _, ds := range dsRecords {
		key := fmt.Sprintf("%d|%d|%d|%s", ds.KeyTag, ds.Algorithm, ds.DigestType, strings.ToUpper(ds.Digest))
		matchedKeys := matchingDNSKEYs([]*dns.DS{ds}, keys)
		if len(matchedKeys) == 0 {
			out[key] = dsSEPAssessment{Matched: false, Signed: false}
			continue
		}
		err := verifyRRSetWithDNSKEYs(matchedKeys, sigs, dnskeysToRRs(keys), now)
		out[key] = dsSEPAssessment{Matched: true, Signed: err == nil}
	}
	return out
}

func assessSecureEntryPointAlgorithms(dsRecords []*dns.DS, keys []*dns.DNSKEY, sigs []*dns.RRSIG, now time.Time) dsSEPAlgorithmAssessment {
	perDS := assessSecureEntryPoints(dsRecords, keys, sigs, now)
	allAlgorithms := map[uint8]bool{}
	signedAlgorithms := map[uint8]bool{}
	for _, ds := range dsRecords {
		allAlgorithms[ds.Algorithm] = true
		key := fmt.Sprintf("%d|%d|%d|%s", ds.KeyTag, ds.Algorithm, ds.DigestType, strings.ToUpper(ds.Digest))
		if assessment, ok := perDS[key]; ok && assessment.Signed {
			signedAlgorithms[ds.Algorithm] = true
		}
	}
	return dsSEPAlgorithmAssessment{
		TotalAlgorithms:  len(allAlgorithms),
		SignedAlgorithms: len(signedAlgorithms),
	}
}

func summarizeDSCoverage(dsRecords []*dns.DS, keys []*dns.DNSKEY, sigs []*dns.RRSIG, now time.Time) dsCoverageSummary {
	perDS := assessSecureEntryPoints(dsRecords, keys, sigs, now)
	summary := dsCoverageSummary{TotalDSCount: len(dsRecords)}
	for _, ds := range dsRecords {
		key := fmt.Sprintf("%d|%d|%d|%s", ds.KeyTag, ds.Algorithm, ds.DigestType, strings.ToUpper(ds.Digest))
		label := fmt.Sprintf("keytag=%d alg=%d digest=%d", ds.KeyTag, ds.Algorithm, ds.DigestType)
		assessment, ok := perDS[key]
		if !ok || !assessment.Matched {
			summary.UnmatchedDS = append(summary.UnmatchedDS, label)
			continue
		}
		summary.MatchedDSCount++
		if !assessment.Signed {
			summary.UnsignedMatched = append(summary.UnsignedMatched, label)
		}
	}
	return summary
}

func matchDNSKEY(ds *dns.DS, keys []*dns.DNSKEY) bool {
	for _, key := range keys {
		if key.Header().Name != ds.Header().Name {
			continue
		}
		if generated := key.ToDS(ds.DigestType); generated != nil && strings.EqualFold(generated.Digest, ds.Digest) && generated.Algorithm == ds.Algorithm && generated.KeyTag == ds.KeyTag {
			return true
		}
	}
	return false
}

func matchingDNSKEYs(dsRecords []*dns.DS, keys []*dns.DNSKEY) []*dns.DNSKEY {
	var matched []*dns.DNSKEY
	for _, key := range keys {
		for _, ds := range dsRecords {
			if key.Header().Name != ds.Header().Name {
				continue
			}
			if generated := key.ToDS(ds.DigestType); generated != nil && strings.EqualFold(generated.Digest, ds.Digest) && generated.Algorithm == ds.Algorithm && generated.KeyTag == ds.KeyTag {
				matched = append(matched, key)
				break
			}
		}
	}
	return matched
}

func splitDNSKEYAnswer(rrs []dns.RR, owner string) ([]*dns.DNSKEY, []*dns.RRSIG) {
	var keys []*dns.DNSKEY
	var sigs []*dns.RRSIG
	for _, rr := range rrs {
		switch v := rr.(type) {
		case *dns.DNSKEY:
			if dns.Fqdn(v.Header().Name) == dns.Fqdn(owner) {
				keys = append(keys, v)
			}
		case *dns.RRSIG:
			if dns.Fqdn(v.Header().Name) == dns.Fqdn(owner) && v.TypeCovered == dns.TypeDNSKEY {
				sigs = append(sigs, v)
			}
		}
	}
	return keys, sigs
}

func splitDSAnswer(rrs []dns.RR, owner string) ([]*dns.DS, []*dns.RRSIG) {
	var dsRecords []*dns.DS
	var sigs []*dns.RRSIG
	for _, rr := range rrs {
		switch v := rr.(type) {
		case *dns.DS:
			if dns.Fqdn(v.Header().Name) == dns.Fqdn(owner) {
				dsRecords = append(dsRecords, v)
			}
		case *dns.RRSIG:
			if dns.Fqdn(v.Header().Name) == dns.Fqdn(owner) && v.TypeCovered == dns.TypeDS {
				sigs = append(sigs, v)
			}
		}
	}
	return dsRecords, sigs
}

func soaAnswerFingerprint(msg *dns.Msg, owner string) string {
	for _, rr := range msg.Answer {
		soa, ok := rr.(*dns.SOA)
		if !ok || dns.Fqdn(soa.Header().Name) != dns.Fqdn(owner) {
			continue
		}
		return fmt.Sprintf("%s|%s|%d|%d|%d|%d|%d", dns.Fqdn(soa.Ns), dns.Fqdn(soa.Mbox), soa.Serial, soa.Refresh, soa.Retry, soa.Expire, soa.Minttl)
	}
	return ""
}

func dnskeySetFingerprint(keys []*dns.DNSKEY) string {
	if len(keys) == 0 {
		return ""
	}
	items := make([]string, 0, len(keys))
	for _, key := range keys {
		items = append(items, fmt.Sprintf("%s|%d|%d|%d|%s", dns.Fqdn(key.Header().Name), key.Flags, key.Protocol, key.Algorithm, key.PublicKey))
	}
	sort.Strings(items)
	return strings.Join(items, ";")
}

func dsSetFingerprint(records []*dns.DS) string {
	if len(records) == 0 {
		return ""
	}
	items := make([]string, 0, len(records))
	for _, ds := range records {
		items = append(items, fmt.Sprintf("%s|%d|%d|%d|%s", dns.Fqdn(ds.Header().Name), ds.KeyTag, ds.Algorithm, ds.DigestType, strings.ToUpper(ds.Digest)))
	}
	sort.Strings(items)
	return strings.Join(items, ";")
}

func checkStateFromFinding(findings []checkreport.Finding, code string) checkreport.CheckState {
	for _, finding := range findings {
		if finding.Code != code {
			continue
		}
		switch finding.Severity {
		case checkreport.StatusCritical:
			return checkreport.CheckCritical
		case checkreport.StatusUnknown:
			return checkreport.CheckUnknown
		case checkreport.StatusWarning:
			return checkreport.CheckWarning
		}
	}
	return checkreport.CheckPass
}

func consistencyMessage(subject string, state checkreport.CheckState) string {
	if state == checkreport.CheckPass {
		return subject + " was consistent across responding authoritative servers"
	}
	return subject + " differed across responding authoritative servers"
}

func assessParentDSConsistencyResponses(hop delegationHop, responses []parentDSEndpointResult) (checkreport.CheckState, string, *checkreport.Finding) {
	if len(responses) <= 1 {
		return checkreport.CheckPass, "", nil
	}
	fingerprints := map[string]bool{}
	for _, response := range responses {
		fingerprints[dsSetFingerprint(response.Records)] = true
	}
	if len(fingerprints) <= 1 {
		return checkreport.CheckPass, "parent DS responses were consistent across responding authoritative servers", nil
	}
	finding := warningFinding("dnschain_parent_ds_inconsistent", hop.ToZone, "parent authoritative servers served different DS RRsets for the same delegation")
	return checkreport.CheckWarning, "parent DS responses differed across responding authoritative servers", &finding
}

func matchRootTrustAnchorKeys(keys []*dns.DNSKEY) (matched int, missing int, anchored []*dns.DNSKEY) {
	for _, anchor := range rootTrustAnchors {
		found := false
		for _, key := range keys {
			if key.KeyTag() != anchor.KeyTag || key.Algorithm != anchor.Algorithm || key.Flags != anchor.Flags || key.PublicKey != anchor.PublicKey {
				continue
			}
			if generated := key.ToDS(anchor.DigestType); generated == nil || !strings.EqualFold(generated.Digest, anchor.Digest) {
				continue
			}
			found = true
			anchored = append(anchored, key)
			break
		}
		if found {
			matched++
		} else {
			missing++
		}
	}
	return matched, missing, anchored
}

func verifyRRSIGSet(keys []*dns.DNSKEY, sigs []*dns.RRSIG, rrset []*dns.DNSKEY, now time.Time) error {
	return verifyRRSetWithDNSKEYs(keys, sigs, dnskeysToRRs(rrset), now)
}

func verifyRRSetWithDNSKEYs(keys []*dns.DNSKEY, sigs []*dns.RRSIG, rrset []dns.RR, now time.Time) error {
	var errs []string
	for _, sig := range sigs {
		if !sig.ValidityPeriod(now) {
			errs = append(errs, fmt.Sprintf("RRSIG keytag=%d is outside validity window", sig.KeyTag))
			continue
		}
		for _, key := range keys {
			if sig.KeyTag != key.KeyTag() {
				continue
			}
			if err := sig.Verify(key, rrset); err == nil {
				return nil
			} else {
				errs = append(errs, fmt.Sprintf("keytag=%d verify error: %v", sig.KeyTag, err))
			}
		}
	}
	if len(errs) == 0 {
		return fmt.Errorf("no matching DNSKEY/RRSIG pair found")
	}
	return errors.New(strings.Join(errs, "; "))
}

func dnskeysToRRs(keys []*dns.DNSKEY) []dns.RR {
	rrs := make([]dns.RR, 0, len(keys))
	for _, rr := range keys {
		rrs = append(rrs, rr)
	}
	return rrs
}

func dsToRRs(records []*dns.DS) []dns.RR {
	rrs := make([]dns.RR, 0, len(records))
	for _, rr := range records {
		rrs = append(rrs, rr)
	}
	return rrs
}

func collectDNSKEYEndpointSets(ctx context.Context, zone string, servers []nsAddr) ([]dnskeyEndpointResult, error) {
	var sets []dnskeyEndpointResult
	var errs []string
	for _, server := range uniqueNSAddrs(servers) {
		res, err := exchangeDNS(ctx, server.Addr, zone, dns.TypeDNSKEY, true)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", server.Addr, err))
			continue
		}
		if !res.Msg.Authoritative {
			errs = append(errs, fmt.Sprintf("%s: response was not authoritative", server.Addr))
			continue
		}
		keys, sigs := splitDNSKEYAnswer(res.Msg.Answer, zone)
		sets = append(sets, dnskeyEndpointResult{
			Endpoint:    server,
			Keys:        keys,
			Sigs:        sigs,
			Fingerprint: dnskeySetFingerprint(keys),
		})
	}
	if len(sets) > 0 {
		return sets, nil
	}
	if len(errs) == 0 {
		return nil, fmt.Errorf("no authoritative DNSKEY response was obtained")
	}
	return nil, fmt.Errorf("all DNSKEY queries failed: %s", strings.Join(errs, "; "))
}

func countReachableGroupEndpoints(name string, checks []checkreport.Check) int {
	count := 0
	for _, check := range checks {
		if check.ID == "ns.endpoint" && check.State == checkreport.CheckPass && strings.Contains(check.Message, name) {
			count++
		}
	}
	return count
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

func aggregateSummary(report checkreport.Report, zone string) string {
	switch report.Status {
	case checkreport.StatusCritical:
		return fmt.Sprintf("DNS delegation or DNSSEC linkage is broken for %s", zone)
	case checkreport.StatusWarning:
		return fmt.Sprintf("DNS delegation is degraded for %s", zone)
	case checkreport.StatusUnknown:
		return fmt.Sprintf("DNS analysis is incomplete for %s", zone)
	default:
		return fmt.Sprintf("authoritative delegation looks healthy for %s", zone)
	}
}

func buildUnknownReport(base checkreport.Report, started time.Time, target, code, message string, ignoreSet map[string]bool) checkreport.Report {
	base.Status = checkreport.StatusUnknown
	base.Summary = message
	base.Findings = append(base.Findings, unknownFinding(code, target, message))
	base.Findings, base.SuppressedFindings = checkreport.PartitionSuppressedFindings(base.Findings, ignoreSet)
	base.Metrics = []checkreport.Metric{
		countMetric("findings", len(base.Findings)),
		countMetric("ignored", len(base.SuppressedFindings)),
	}
	base.DurationMS = time.Since(started).Milliseconds()
	return base
}

func warningFinding(code, target, message string) checkreport.Finding {
	return makeFinding(code, checkreport.StatusWarning, target, message)
}

func criticalFinding(code, target, message string) checkreport.Finding {
	return makeFinding(code, checkreport.StatusCritical, target, message)
}

func unknownFinding(code, target, message string) checkreport.Finding {
	return makeFinding(code, checkreport.StatusUnknown, target, message)
}

func equalStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	index := map[string]int{}
	for _, value := range a {
		index[dns.Fqdn(value)]++
	}
	for _, value := range b {
		key := dns.Fqdn(value)
		if index[key] == 0 {
			return false
		}
		index[key]--
	}
	for _, count := range index {
		if count != 0 {
			return false
		}
	}
	return true
}
