package dnschain

import (
	"context"
	"fmt"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/miekg/dns"
)

func probeFinalZoneNSEC3Responses(ctx context.Context, zone string, servers []nsAddr, trustedKeys []*dns.DNSKEY, stage *checkreport.Stage, result *dnssecProbeResult) {
	sampleName := fmt.Sprintf("_dnschain-nsec3-probe-%d.%s", time.Now().UTC().UnixNano(), zone)
	now := time.Now().UTC()

	for _, server := range uniqueNSAddrs(servers) {
		res, err := exchangeDNS(ctx, server.Addr, sampleName, dns.TypeA, true)
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
		if !res.Msg.Authoritative {
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "nsec3.name_error_probe",
				State:   checkreport.CheckWarning,
				Subject: server.Addr,
				Message: "sampled NSEC3 name-error response was not authoritative",
			})
			result.Findings = append(result.Findings, warningFinding("dnschain_nameserver_endpoint_rrset_failed", zone, fmt.Sprintf("sampled NSEC3 name-error response via endpoint %s was not authoritative", server.Addr)))
			continue
		}
		switch res.Msg.Rcode {
		case dns.RcodeNameError:
			proof, err := validateNSEC3NameErrorProof(sampleName, res.Msg.Ns, trustedKeys, now)
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
			if len(res.Msg.Answer) == 0 {
				proof, err := validateNSEC3WildcardNoDataProof(sampleName, dns.TypeA, res.Msg.Ns, trustedKeys, now)
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
		res, err := exchangeDNS(ctx, server.Addr, zone, dns.TypeOPENPGPKEY, true)
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
		if !res.Msg.Authoritative {
			stage.Checks = append(stage.Checks, checkreport.Check{
				ID:      "nsec3.no_data_probe",
				State:   checkreport.CheckWarning,
				Subject: server.Addr,
				Message: "sampled NSEC3 no-data response was not authoritative",
			})
			result.Findings = append(result.Findings, warningFinding("dnschain_nameserver_endpoint_rrset_failed", zone, fmt.Sprintf("sampled NSEC3 no-data response via endpoint %s was not authoritative", server.Addr)))
			continue
		}
		if res.Msg.Rcode != dns.RcodeSuccess || len(res.Msg.Answer) != 0 {
			continue
		}
		proof, err := validateNSEC3NoDataProof(zone, dns.TypeOPENPGPKEY, res.Msg.Ns, trustedKeys, now)
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
