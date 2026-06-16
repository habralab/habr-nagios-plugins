package dnschain

import (
	"context"
	"fmt"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/core/dnsresolver"
	"github.com/miekg/dns"
)

func probeFinalZoneNSEC3Responses(ctx context.Context, resolver *dnsresolver.Resolver, zone string, servers []nsAddr, trustedKeys []*dns.DNSKEY, stage *checkreport.Stage, result *dnssecProbeResult) {
	sampleName := fmt.Sprintf("_dnschain-nsec3-probe-%d.%s", time.Now().UTC().UnixNano(), zone)
	now := time.Now().UTC()

	for _, server := range uniqueNSAddrs(servers) {
		resolved, err := resolver.ResolveAuthoritative(ctx, sampleName, dns.TypeA, []dnsresolver.AuthoritativeServer{{Name: server.Name, Endpoint: server.Addr}}, dnsresolver.ResolveOptions{
			Fanout: dnsresolver.FanoutAllAuthoritative,
		})
		if err != nil {
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "nsec3.name_error_probe",
				State:   checkreport.CheckWarning,
				Subject: server.Addr,
				Message: fmt.Sprintf("NSEC3 name-error probe failed: %v", err),
			})
			result.Findings = append(result.Findings, warningFinding("dnschain_nameserver_endpoint_unreachable", zone, fmt.Sprintf("sampled NSEC3 name-error probe failed via endpoint %s: %v", server.Addr, err)))
			continue
		}
		if len(resolved.Responses) == 0 {
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "nsec3.name_error_probe",
				State:   checkreport.CheckWarning,
				Subject: server.Addr,
				Message: "sampled NSEC3 name-error response contained no authoritative response material",
			})
			result.Findings = append(result.Findings, warningFinding("dnschain_nameserver_endpoint_rrset_failed", zone, fmt.Sprintf("sampled NSEC3 name-error response via endpoint %s contained no authoritative response material", server.Addr)))
			continue
		}
		res := resolved.Responses[0]
		if res.Error != "" {
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "nsec3.name_error_probe",
				State:   checkreport.CheckWarning,
				Subject: server.Addr,
				Message: fmt.Sprintf("NSEC3 name-error probe failed: %s", res.Error),
			})
			result.Findings = append(result.Findings, warningFinding("dnschain_nameserver_endpoint_unreachable", zone, fmt.Sprintf("sampled NSEC3 name-error probe failed via endpoint %s: %s", server.Addr, res.Error)))
			continue
		}
		if !res.Authoritative {
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "nsec3.name_error_probe",
				State:   checkreport.CheckWarning,
				Subject: server.Addr,
				Message: "sampled NSEC3 name-error response was not authoritative",
			})
			result.Findings = append(result.Findings, warningFinding("dnschain_nameserver_endpoint_rrset_failed", zone, fmt.Sprintf("sampled NSEC3 name-error response via endpoint %s was not authoritative", server.Addr)))
			continue
		}
		switch res.RCode {
		case dns.RcodeNameError:
			proof, err := validateNSEC3NameErrorProof(sampleName, res.Authority, trustedKeys, now)
			if err != nil {
				stage.Checks = append(stage.Checks, checkreport.Check{
					ID:      "nsec3.name_error_probe",
					State:   checkreport.CheckCritical,
					Subject: server.Addr,
					Message: fmt.Sprintf("NSEC3 name-error proof validation failed: %v", err),
				})
				result.Findings = append(result.Findings, criticalFinding("dnschain_nsec3_name_error_invalid", zone, fmt.Sprintf("NSEC3 name-error proof validation failed via %s: %v", server.Addr, err)))
				continue
			}
			if proof.State == "" {
				stage.Checks = append(stage.Checks, checkreport.Check{
					ID:      "nsec3.name_error_probe",
					State:   checkreport.CheckWarning,
					Subject: server.Addr,
					Message: "response was NXDOMAIN but the NSEC3 name-error proof pattern was not recognized",
				})
				result.Findings = append(result.Findings, warningFinding("dnschain_nsec3_name_error_unrecognized", zone, fmt.Sprintf("NSEC3 name-error proof was not recognized via %s", server.Addr)))
				continue
			}
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:              "nsec3.name_error_probe",
				State:           proof.State,
				Subject:         server.Addr,
				Message:         proof.Message,
				Evidence:        proof.Evidence,
				AggregationKey:  "nsec3.name_error_probe.pass",
				AggregationMode: checkreport.AggregationSuccessOnly,
			})
		case dns.RcodeSuccess:
			if res.RawAnswerCount == 0 {
				proof, err := validateNSEC3WildcardNoDataProof(sampleName, dns.TypeA, res.Authority, trustedKeys, now)
				if err != nil {
					stage.Checks = append(stage.Checks, checkreport.Check{
						ID:      "nsec3.wildcard_no_data_probe",
						State:   checkreport.CheckCritical,
						Subject: server.Addr,
						Message: fmt.Sprintf("NSEC3 wildcard no-data proof validation failed: %v", err),
					})
					result.Findings = append(result.Findings, criticalFinding("dnschain_nsec3_wildcard_no_data_invalid", zone, fmt.Sprintf("NSEC3 wildcard no-data proof validation failed via %s: %v", server.Addr, err)))
					continue
				}
				if proof.State != "" {
					stage.Checks = append(stage.Checks, checkreport.Check{
						ID:              "nsec3.wildcard_no_data_probe",
						State:           proof.State,
						Subject:         server.Addr,
						Message:         proof.Message,
						Evidence:        proof.Evidence,
						AggregationKey:  "nsec3.wildcard_no_data_probe.pass",
						AggregationMode: checkreport.AggregationSuccessOnly,
					})
				}
			}
		}
	}

	for _, server := range uniqueNSAddrs(servers) {
		resolved, err := resolver.ResolveAuthoritative(ctx, zone, dns.TypeOPENPGPKEY, []dnsresolver.AuthoritativeServer{{Name: server.Name, Endpoint: server.Addr}}, dnsresolver.ResolveOptions{
			Fanout: dnsresolver.FanoutAllAuthoritative,
		})
		if err != nil {
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "nsec3.no_data_probe",
				State:   checkreport.CheckWarning,
				Subject: server.Addr,
				Message: fmt.Sprintf("NSEC3 no-data probe failed: %v", err),
			})
			result.Findings = append(result.Findings, warningFinding("dnschain_nameserver_endpoint_unreachable", zone, fmt.Sprintf("sampled NSEC3 no-data probe failed via endpoint %s: %v", server.Addr, err)))
			continue
		}
		if len(resolved.Responses) == 0 {
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "nsec3.no_data_probe",
				State:   checkreport.CheckWarning,
				Subject: server.Addr,
				Message: "sampled NSEC3 no-data response contained no authoritative response material",
			})
			result.Findings = append(result.Findings, warningFinding("dnschain_nameserver_endpoint_rrset_failed", zone, fmt.Sprintf("sampled NSEC3 no-data response via endpoint %s contained no authoritative response material", server.Addr)))
			continue
		}
		res := resolved.Responses[0]
		if res.Error != "" {
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "nsec3.no_data_probe",
				State:   checkreport.CheckWarning,
				Subject: server.Addr,
				Message: fmt.Sprintf("NSEC3 no-data probe failed: %s", res.Error),
			})
			result.Findings = append(result.Findings, warningFinding("dnschain_nameserver_endpoint_unreachable", zone, fmt.Sprintf("sampled NSEC3 no-data probe failed via endpoint %s: %s", server.Addr, res.Error)))
			continue
		}
		if !res.Authoritative {
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "nsec3.no_data_probe",
				State:   checkreport.CheckWarning,
				Subject: server.Addr,
				Message: "sampled NSEC3 no-data response was not authoritative",
			})
			result.Findings = append(result.Findings, warningFinding("dnschain_nameserver_endpoint_rrset_failed", zone, fmt.Sprintf("sampled NSEC3 no-data response via endpoint %s was not authoritative", server.Addr)))
			continue
		}
		if res.RCode != dns.RcodeSuccess || res.RawAnswerCount != 0 {
			continue
		}
		proof, err := validateNSEC3NoDataProof(zone, dns.TypeOPENPGPKEY, res.Authority, trustedKeys, now)
		if err != nil {
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "nsec3.no_data_probe",
				State:   checkreport.CheckCritical,
				Subject: server.Addr,
				Message: fmt.Sprintf("NSEC3 no-data proof validation failed: %v", err),
			})
			result.Findings = append(result.Findings, criticalFinding("dnschain_nsec3_no_data_invalid", zone, fmt.Sprintf("NSEC3 no-data proof validation failed via %s: %v", server.Addr, err)))
			continue
		}
		if proof.State == "" {
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "nsec3.no_data_probe",
				State:   checkreport.CheckWarning,
				Subject: server.Addr,
				Message: "response was no-data but the NSEC3 no-data proof pattern was not recognized",
			})
			result.Findings = append(result.Findings, warningFinding("dnschain_nsec3_no_data_unrecognized", zone, fmt.Sprintf("NSEC3 no-data proof was not recognized via %s", server.Addr)))
			continue
		}
		stage.Checks = append(stage.Checks, checkreport.Check{
			ID:              "nsec3.no_data_probe",
			State:           proof.State,
			Subject:         server.Addr,
			Message:         proof.Message,
			Evidence:        proof.Evidence,
			AggregationKey:  "nsec3.no_data_probe.pass",
			AggregationMode: checkreport.AggregationSuccessOnly,
		})
	}
}
