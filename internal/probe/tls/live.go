package tlsprobe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
	"github.com/habralab/habr-nagios-plugins/internal/core/dnsresolver"
	"github.com/habralab/habr-nagios-plugins/internal/core/httpx"
	"github.com/habralab/habr-nagios-plugins/internal/core/ipfamily"
	"github.com/habralab/habr-nagios-plugins/internal/core/pkix"
	"github.com/habralab/habr-nagios-plugins/internal/core/probecli"
	"github.com/habralab/habr-nagios-plugins/internal/core/tlsx"
	"github.com/miekg/dns"
	"golang.org/x/crypto/ocsp"
)

type liveAnalyzer struct{}

type dnsResolver interface {
	Lookup(context.Context, string, uint16) (dnsresolver.LookupResult, error)
	LookupEffectiveCAA(context.Context, string) (dnsresolver.EffectiveCAAResult, error)
}

type dnsBatchResolver interface {
	LookupBatch(context.Context, []dnsresolver.Question) []dnsresolver.LookupBatchItem
}

type ocspAssessment struct {
	Check   checkreport.Check
	Finding *checkreport.Finding
	Metric  checkreport.Metric
	Status  string
	Source  string
	Parsed  *ocsp.Response
}

var detectTransportFamilyCapabilities = ipfamily.DetectCapabilities

var defaultDNSResolverFactory = func(timeout time.Duration, cacheBackend string, familyPolicy ipfamily.Policy) dnsResolver {
	resolver := dnsresolver.NewResolver(timeout)
	resolver.ConfigureSharedCacheBackendDSN(cacheBackend)
	resolver.SetTransportFamilyPolicy(familyPolicy)
	return resolver
}

type handshakeResult struct {
	State      tls.ConnectionState
	Duration   time.Duration
	RemoteAddr string
	Endpoint   string
}

type endpointSemanticProfile struct {
	Endpoint  string
	Transport endpointTransportProfile
	PKI       endpointPKIProfile
	OCSP      endpointOCSPProfile
	CT        endpointCTProfile
	DANE      endpointDANEProfile
	SNI       endpointSNIProfile
}

type endpointTransportProfile struct {
	ALPN        string
	Version     string
	CipherSuite string
}

type endpointPKIProfile struct {
	LeafFingerprint  string
	ChainFingerprint string
	LeafSummary      string
	TrustState       chainTrustState
	PathCount        int
}

type endpointOCSPProfile struct {
	Status string
	Source string
}

type endpointCTProfile struct {
	Status       string
	Required     bool
	PolicyReason string
	Sources      []string
}

type endpointDANEProfile struct {
	Status       string
	Security     dnsresolver.SecurityState
	MatchedCount int
	RecordCount  int
}

type endpointSNIProfile struct {
	Status        string
	SNILeaf       string
	NoSNILeaf     string
	SNIALPN       string
	NoSNIALPN     string
	SNIVersion    string
	NoSNIVersion  string
	FailureReason string
}

type endpointAttemptResult struct {
	Endpoint   string
	Success    bool
	Skipped    bool
	Error      string
	RemoteAddr string
}

type deprecatedProbeResult struct {
	Version  uint16
	Duration time.Duration
	Success  bool
	Err      error
	Errors   []string
}

type serviceAddressResults struct {
	Endpoints []string
	Records   []dns.RR
}

type chainTrustState string

const (
	chainTrustUnknown   chainTrustState = "unknown"
	chainTrustTrusted   chainTrustState = "trusted"
	chainTrustUntrusted chainTrustState = "untrusted"
	chainTrustInvalid   chainTrustState = "invalid"
)

type chainAssessment struct {
	PathCount   int
	TrustState  chainTrustState
	Description string
	Graph       checkreport.Evidence
}

type ctPolicy struct {
	Required bool
	Reason   string
}

type ctAssessment struct {
	Checks  []checkreport.Check
	Finding *checkreport.Finding
}

type ocspDetails struct {
	Summary ocspAssessment
	Checks  []checkreport.Check
}

type dnsAssessment struct {
	Checks  []checkreport.Check
	Finding *checkreport.Finding
	Metric  float64
}

type weakCipherAssessment struct {
	Checks  []checkreport.Check
	Finding *checkreport.Finding
}

type deprecatedProbeAssessment struct {
	Checks []checkreport.Check
}

func (liveAnalyzer) Analyze(ctx context.Context, cfg Config, target string) (report checkreport.Report, err error) {
	if cfg.Transport != tlsx.TransportTCP {
		return placeholderWithMessage(ctx, cfg, target, fmt.Sprintf("transport %q is not implemented yet", cfg.Transport))
	}

	started := time.Now()
	serviceTarget := fmt.Sprintf("%s:%d", target, cfg.Port)
	report = baseReport(cfg, target, serviceTarget, started)
	targetStage := checkreport.StageByID(&report, "target.selection")

	transportStage := checkreport.Stage{ID: "transport.setup", Title: "Transport Setup", Status: checkreport.StatusOK, Target: serviceTarget}
	modernStage := checkreport.Stage{ID: "tls.modern_handshake", Title: "Modern TLS Handshake", Status: checkreport.StatusOK, Target: serviceTarget}
	sniStage := checkreport.Stage{ID: "sni.profile", Title: "SNI Profile", Status: checkreport.StatusOK, Target: serviceTarget}
	pkiStage := checkreport.Stage{ID: "pki.validation", Title: "PKI Validation", Status: checkreport.StatusOK, Target: serviceTarget}
	dnsStage := checkreport.Stage{ID: "dns.policy", Title: "DNS Policy", Status: checkreport.StatusOK, Target: target}
	cipherStage := checkreport.Stage{ID: "cipher.audit", Title: "Cipher Audit", Status: checkreport.StatusOK, Target: serviceTarget}
	protocolStage := checkreport.Stage{ID: "protocol.audit", Title: "Deprecated Protocol Audit", Status: checkreport.StatusOK, Target: serviceTarget}
	addressStage := checkreport.Stage{ID: "coverage.addresses", Title: "Address Coverage", Status: checkreport.StatusOK, Target: serviceTarget}
	endpointSemanticsStage := checkreport.Stage{ID: "coverage.endpoint_semantics", Title: "Endpoint Semantics", Status: checkreport.StatusOK, Target: serviceTarget}
	coverageStage := checkreport.Stage{ID: "coverage.remaining", Title: "Remaining Coverage", Status: checkreport.StatusUnknown, Target: serviceTarget}

	dnsResolver := defaultDNSResolverFactory(cfg.DNSTimeout, cfg.CacheBackend, cfg.TransportFamilyPolicy)
	if statsProvider, ok := dnsResolver.(interface{ CacheStats() dnsresolver.CacheStats }); ok {
		traceProvider, _ := dnsResolver.(interface {
			CacheTrace() []dnsresolver.CacheTrace
		})
		defer func() {
			var traces []dnsresolver.CacheTrace
			if traceProvider != nil {
				traces = traceProvider.CacheTrace()
			}
			probecli.AppendResolverCacheUsageStage(&report, target, statsProvider.CacheStats(), traces)
		}()
	}
	addresses, err := resolveServiceAddresses(ctx, cfg, target, dnsResolver)
	if err != nil {
		check, finding := classifyHandshakeError(err, serviceTarget)
		if targetStage != nil {
			targetStage.Checks = append(targetStage.Checks, checkreport.Check{
				ID:      "target.addresses",
				State:   checkreport.CheckCritical,
				Subject: target,
				Message: fmt.Sprintf("service address resolution failed: %v", err),
			})
			targetStage.Status = deriveStageStatus(targetStage.Checks, targetStage.Status)
		}
		modernStage.Checks = append(modernStage.Checks, check)
		modernStage.Status = statusFromCheckState(check.State)
		report.Stages = append(report.Stages, modernStage)
		report.Findings = append(report.Findings, finding)
		report.Stages = append(report.Stages, coveragePlaceholderStage(cfg, target, serviceTarget))
		finalizeReport(&report, cfg, started, serviceTarget, 0, 0, false, 0)
		return report, nil
	}
	if targetStage != nil {
		targetStage.Checks = append(targetStage.Checks, checkreport.Check{
			ID:      "target.addresses",
			State:   checkreport.CheckPass,
			Subject: target,
			Message: fmt.Sprintf("resolved %d service endpoint(s) through authoritative DNS lookups", len(addresses.Endpoints)),
			Evidence: []checkreport.Evidence{{
				Kind:    "dns",
				Summary: "service endpoints resolved for TLS probing",
				Attributes: []checkreport.KV{
					{Key: "records", Value: rrSummary(addresses.Records)},
				},
			}},
		})
	}
	for _, endpoint := range addresses.Endpoints {
		report.Targets = append(report.Targets, checkreport.Target{Role: "service_endpoint_discovered", Value: endpoint})
	}

	handshake, successfulHandshakes, attempts, transportChecks, err := performModernHandshake(ctx, cfg, target, serviceTarget, addresses.Endpoints)
	transportStage.Checks = append(transportStage.Checks, transportChecks...)
	if err != nil {
		check, finding := classifyHandshakeError(err, serviceTarget)
		modernStage.Checks = append(modernStage.Checks, check)
		transportStage.Status = deriveStageStatus(transportStage.Checks, transportStage.Status)
		modernStage.Status = statusFromCheckState(check.State)
		addressStage = buildAddressCoverageStage(serviceTarget, attempts, "")
		addressStage.Status = deriveStageStatus(addressStage.Checks, addressStage.Status)
		report.Stages = append(report.Stages, transportStage, modernStage, addressStage)
		report.Findings = append(report.Findings, finding)
		report.Stages = append(report.Stages, coveragePlaceholderStage(cfg, target, serviceTarget))
		finalizeReport(&report, cfg, started, serviceTarget, 0, 0, false, 0)
		return report, nil
	}
	report.Targets = append(report.Targets, checkreport.Target{Role: "service_endpoint_selected", Value: handshake.Endpoint})
	for _, attempt := range attempts {
		if attempt.Success {
			report.Targets = append(report.Targets, checkreport.Target{Role: "service_endpoint_successful", Value: attempt.Endpoint})
		}
	}
	addressStage = buildAddressCoverageStage(serviceTarget, attempts, handshake.Endpoint)
	if partialFinding := buildAddressCoverageFinding(serviceTarget, attempts); partialFinding != nil {
		report.Findings = append(report.Findings, *partialFinding)
	}

	report.Traces = append(report.Traces, checkreport.TraceEvent{
		Kind:         "handshake",
		StageID:      modernStage.ID,
		State:        checkreport.CheckPass,
		Target:       serviceTarget,
		Message:      fmt.Sprintf("modern handshake succeeded in %s", handshake.Duration.Round(time.Millisecond)),
		MinVerbosity: 2,
		Attributes: []checkreport.KV{
			{Key: "version", Value: tlsVersionName(handshake.State.Version)},
			{Key: "cipher_suite", Value: cipherSuiteName(handshake.State.CipherSuite)},
			{Key: "remote_addr", Value: handshake.RemoteAddr},
		},
	})

	modernStage.Checks = append(modernStage.Checks,
		checkreport.Check{
			ID:           "handshake.policy",
			State:        checkreport.CheckPass,
			Subject:      serviceTarget,
			Message:      "modern handshake policy requires TLS 1.2 or newer",
			MinVerbosity: 1,
		},
		checkreport.Check{
			ID:      "handshake.connect",
			State:   checkreport.CheckPass,
			Subject: serviceTarget,
			Message: fmt.Sprintf("modern TLS handshake succeeded in %s", handshake.Duration.Round(time.Millisecond)),
			Evidence: []checkreport.Evidence{
				{
					Kind:    "tls",
					Summary: "modern handshake parameters",
					Attributes: []checkreport.KV{
						{Key: "version", Value: tlsVersionName(handshake.State.Version)},
						{Key: "cipher_suite", Value: cipherSuiteName(handshake.State.CipherSuite)},
						{Key: "resumed", Value: strconv.FormatBool(handshake.State.DidResume)},
					},
				},
			},
		},
		checkreport.Check{
			ID:           "handshake.endpoint",
			State:        checkreport.CheckPass,
			Subject:      handshake.Endpoint,
			Message:      fmt.Sprintf("selected endpoint %s for the successful TLS handshake", handshake.Endpoint),
			MinVerbosity: 1,
		},
		checkreport.Check{
			ID:           "handshake.parameters",
			State:        checkreport.CheckPass,
			Subject:      serviceTarget,
			Message:      fmt.Sprintf("negotiated %s using %s", tlsVersionName(handshake.State.Version), cipherSuiteName(handshake.State.CipherSuite)),
			MinVerbosity: 1,
			Evidence: []checkreport.Evidence{
				{
					Kind:    "tls",
					Summary: "successful handshake details",
					Attributes: []checkreport.KV{
						{Key: "endpoint", Value: handshake.Endpoint},
						{Key: "remote_addr", Value: handshake.RemoteAddr},
						{Key: "version", Value: tlsVersionName(handshake.State.Version)},
						{Key: "cipher_suite", Value: cipherSuiteName(handshake.State.CipherSuite)},
						{Key: "resumed", Value: strconv.FormatBool(handshake.State.DidResume)},
					},
				},
			},
		},
		checkreport.Check{
			ID:      "handshake.version",
			State:   checkreport.CheckPass,
			Subject: tlsVersionName(handshake.State.Version),
			Message: fmt.Sprintf("negotiated %s", tlsVersionName(handshake.State.Version)),
		},
	)

	alpnCheck, alpnFinding := evaluateALPN(cfg, handshake.State)
	modernStage.Checks = append(modernStage.Checks, alpnCheck)
	if alpnFinding != nil {
		report.Findings = append(report.Findings, *alpnFinding)
	}

	sniChecks, sniFinding := evaluateNoSNIProfile(ctx, cfg, target, serviceTarget, handshake, addresses.Endpoints)
	sniStage.Checks = append(sniStage.Checks, sniChecks...)
	if sniFinding != nil {
		report.Findings = append(report.Findings, *sniFinding)
	}

	negotiatedCipherCheck, negotiatedCipherFinding := evaluateNegotiatedCipher(serviceTarget, handshake.State)
	cipherStage.Checks = append(cipherStage.Checks, negotiatedCipherCheck)
	if negotiatedCipherFinding != nil {
		report.Findings = append(report.Findings, *negotiatedCipherFinding)
	}

	weakCipherResult := evaluateWeakCipherSupport(ctx, cfg, target, serviceTarget, addresses.Endpoints)
	cipherStage.Checks = append(cipherStage.Checks, weakCipherResult.Checks...)
	if weakCipherResult.Finding != nil {
		report.Findings = append(report.Findings, *weakCipherResult.Finding)
	}

	ocspResult := evaluateOCSPDetailed(ctx, cfg, serviceTarget, target, dnsResolver, handshake.State)
	modernStage.Checks = append(modernStage.Checks, ocspResult.Checks...)
	if ocspResult.Summary.Finding != nil {
		report.Findings = append(report.Findings, *ocspResult.Summary.Finding)
	}

	roots, rootSource, rootErr := loadTrustRoots(cfg)
	if rootErr != nil {
		pkiStage.Checks = append(pkiStage.Checks, checkreport.Check{
			ID:      "pki.roots",
			State:   checkreport.CheckUnknown,
			Subject: serviceTarget,
			Message: fmt.Sprintf("failed to load trust roots: %v", rootErr),
		})
		report.Findings = append(report.Findings, makeFinding("tls_chain_invalid", checkreport.StatusUnknown, serviceTarget, fmt.Sprintf("failed to load trust roots: %v", rootErr)))
	} else {
		pkiStage.Checks = append(pkiStage.Checks, checkreport.Check{
			ID:      "pki.roots",
			State:   checkreport.CheckPass,
			Subject: serviceTarget,
			Message: fmt.Sprintf("loaded trust roots from %s", rootSource),
		})
	}

	endpointSemanticsStage, endpointSemanticFindings := buildEndpointSemanticsStage(ctx, cfg, target, serviceTarget, dnsResolver, roots, rootSource, rootErr, handshake, successfulHandshakes)
	report.Findings = append(report.Findings, endpointSemanticFindings...)
	report.Meta = append(report.Meta,
		checkreport.KV{Key: "selected_endpoint", Value: handshake.Endpoint},
		checkreport.KV{Key: "successful_endpoint_count", Value: strconv.Itoa(len(successfulHandshakes))},
	)

	var chainResult chainAssessment
	pathCount, daysToExpire, haveDaysToExpire := 0, 0, false
	if len(handshake.State.PeerCertificates) == 0 {
		pkiStage.Checks = append(pkiStage.Checks, checkreport.Check{
			ID:      "pki.leaf",
			State:   checkreport.CheckCritical,
			Subject: serviceTarget,
			Message: "server did not present a certificate chain",
		})
		report.Findings = append(report.Findings, makeFinding("tls_chain_incomplete", checkreport.StatusCritical, serviceTarget, "server did not present any certificates"))
		chainResult = chainAssessment{TrustState: chainTrustInvalid, Description: "server did not present a certificate chain"}
	} else {
		leaf := handshake.State.PeerCertificates[0]
		daysToExpire = int(time.Until(leaf.NotAfter).Hours() / 24)
		haveDaysToExpire = true
		pkiChecks, pkiFindings, chainInfo := evaluateLeafAndChain(cfg, target, serviceTarget, roots, handshake.State.PeerCertificates)
		pkiStage.Checks = append(pkiStage.Checks, pkiChecks...)
		report.Findings = append(report.Findings, pkiFindings...)
		chainResult = chainInfo
		pathCount = chainInfo.PathCount
	}

	ctResult := evaluateSCT(serviceTarget, handshake.State, determineCTPolicy(cfg, rootSource, rootErr, chainResult), ocspResult.Summary)
	modernStage.Checks = append(modernStage.Checks, ctResult.Checks...)
	if ctResult.Finding != nil {
		report.Findings = append(report.Findings, *ctResult.Finding)
	}

	daneMetric := evaluateDNSLayer(ctx, cfg, target, serviceTarget, successfulHandshakes, dnsResolver, &dnsStage, &report)

	deprecated10, deprecated11 := probeDeprecatedProtocols(ctx, cfg, target, serviceTarget, addresses.Endpoints)
	protocolStage.Checks = append(protocolStage.Checks, formatDeprecatedProbeDetailed(serviceTarget, deprecated10).Checks...)
	protocolStage.Checks = append(protocolStage.Checks, formatDeprecatedProbeDetailed(serviceTarget, deprecated11).Checks...)
	if deprecated10.Success {
		report.Findings = append(report.Findings, makeFinding("tls_protocol_deprecated_supported", checkreport.StatusCritical, serviceTarget, "server accepted a TLS 1.0 handshake"))
	}
	if deprecated11.Success {
		report.Findings = append(report.Findings, makeFinding("tls_protocol_deprecated_supported", checkreport.StatusCritical, serviceTarget, "server accepted a TLS 1.1 handshake"))
	}

	coverageStage = coveragePlaceholderStage(cfg, target, serviceTarget)
	transportStage.Status = deriveStageStatus(transportStage.Checks, transportStage.Status)
	modernStage.Status = deriveStageStatus(modernStage.Checks, modernStage.Status)
	sniStage.Status = deriveStageStatus(sniStage.Checks, sniStage.Status)
	pkiStage.Status = deriveStageStatus(pkiStage.Checks, pkiStage.Status)
	dnsStage.Status = deriveStageStatus(dnsStage.Checks, dnsStage.Status)
	cipherStage.Status = deriveStageStatus(cipherStage.Checks, cipherStage.Status)
	protocolStage.Status = deriveStageStatus(protocolStage.Checks, protocolStage.Status)
	addressStage.Status = deriveStageStatus(addressStage.Checks, addressStage.Status)
	endpointSemanticsStage.Status = deriveStageStatus(endpointSemanticsStage.Checks, endpointSemanticsStage.Status)
	coverageStage.Status = deriveStageStatus(coverageStage.Checks, coverageStage.Status)

	report.Stages = append(report.Stages, transportStage, modernStage, sniStage, pkiStage, dnsStage, cipherStage, protocolStage, addressStage, endpointSemanticsStage, coverageStage)
	finalizeReport(&report, cfg, started, serviceTarget, handshake.Duration.Milliseconds(), daysToExpire, haveDaysToExpire, pathCount)
	report.Metrics = append(report.Metrics, ocspResult.Summary.Metric)
	report.Metrics = append(report.Metrics, daneMetric)
	return report, nil
}

func placeholderWithMessage(_ context.Context, cfg Config, target, message string) (checkreport.Report, error) {
	report, err := placeholderAnalyzer{}.Analyze(context.Background(), cfg, target)
	if err != nil {
		return report, err
	}
	report.Summary = message
	if len(report.Findings) > 0 {
		report.Findings[0].Message = message
	}
	if stage := checkreport.StageByID(&report, "engine.status"); stage != nil && len(stage.Checks) > 0 {
		stage.Checks[0].Message = message
	}
	return report, nil
}

func baseReport(cfg Config, target, serviceTarget string, started time.Time) checkreport.Report {
	report := checkreport.Report{
		Probe:         Meta.Slug,
		Target:        serviceTarget,
		PrimaryTarget: serviceTarget,
		Targets: []checkreport.Target{
			{Role: "hostname", Value: target},
			{Role: "service", Value: serviceTarget},
			{Role: "transport", Value: string(cfg.Transport)},
		},
		Partial:      true,
		CoverageNote: "current TLS phase covers direct TCP TLS and SMTP/IMAP STARTTLS handshakes, certificate identity and expiry, structured trust-path validation with PKI graph evidence, authoritative CAA lookup, DANE/TLSA matching with DNSSEC chain validation, stapled and optional active OCSP validation, SCT presence checks, negotiated cipher inspection, weak TLS 1.2 cipher probing, and deprecated TLS 1.0/1.1 probes; QUIC, broader cipher preference policy, and richer path-level PKI semantics remain for later phases",
		StartedAt:    started.UTC(),
		Meta: []checkreport.KV{
			{Key: "output_mode", Value: string(cfg.OutputMode)},
			{Key: "policy_untrusted_root", Value: string(cfg.PolicyUntrustedRoot)},
			{Key: "policy_dual_stack", Value: string(cfg.PolicyDualStack)},
			{Key: "ocsp_mode", Value: string(cfg.OCSPMode)},
			{Key: "warn_expiry_days", Value: strconv.Itoa(cfg.WarnExpiryDays)},
		},
		Stages: []checkreport.Stage{
			{
				ID:     "target.selection",
				Title:  "Target Selection",
				Status: checkreport.StatusOK,
				Target: serviceTarget,
				Checks: []checkreport.Check{
					{
						ID:      "target.hostname",
						State:   checkreport.CheckPass,
						Subject: target,
						Message: fmt.Sprintf("target hostname %q with service port %d selected", target, cfg.Port),
						Meta: []checkreport.KV{
							{Key: "transport", Value: string(cfg.Transport)},
						},
					},
				},
			},
		},
	}
	return report
}

func performModernHandshake(ctx context.Context, cfg Config, target, serviceTarget string, endpoints []string) (handshakeResult, []handshakeResult, []endpointAttemptResult, []checkreport.Check, error) {
	handshakeCtx, cancel := context.WithTimeout(ctx, cfg.HandshakeTimeout)
	defer cancel()

	started := time.Now()
	checks := []checkreport.Check{{
		ID:           "transport.endpoint_candidates",
		State:        checkreport.CheckPass,
		Subject:      serviceTarget,
		Message:      fmt.Sprintf("prepared %d resolved endpoint(s) for transport probing", len(endpoints)),
		MinVerbosity: 1,
	}}
	attempts := make([]endpointAttemptResult, 0, len(endpoints))
	successes := make([]handshakeResult, 0, len(endpoints))
	var errs []string
	var skipped []string
	var selected handshakeResult
	var selectedChecks []checkreport.Check
	successCount := 0
	for _, endpoint := range endpoints {
		result, transportChecks, err := performHandshakeToEndpoint(handshakeCtx, cfg, target, endpoint, requestedALPN(cfg))
		if err != nil {
			if cfg.TransportFamilyPolicy.RequiresDetection() && ipfamily.LooksLikeLocalFamilyUnavailable(err) {
				skipped = append(skipped, fmt.Sprintf("%s: %v", endpoint, err))
				attempts = append(attempts, endpointAttemptResult{
					Endpoint: endpoint,
					Skipped:  true,
					Error:    err.Error(),
				})
				continue
			}
			errText := fmt.Sprintf("%s: %v", endpoint, err)
			errs = append(errs, errText)
			attempts = append(attempts, endpointAttemptResult{
				Endpoint: endpoint,
				Success:  false,
				Error:    err.Error(),
			})
			continue
		}
		attempts = append(attempts, endpointAttemptResult{
			Endpoint:   result.Endpoint,
			Success:    true,
			RemoteAddr: result.RemoteAddr,
		})
		successes = append(successes, result)
		successCount++
		if successCount == 1 {
			selected = result
			selected.Duration = time.Since(started)
			selectedChecks = append(selectedChecks, transportChecks...)
		}
	}
	if successCount == 0 {
		checks = append(checks, checkreport.Check{
			ID:           "transport.endpoint_attempts",
			State:        transportAttemptState(false, errs),
			Subject:      serviceTarget,
			Message:      transportAttemptMessage(false, errs),
			MinVerbosity: 1,
			Evidence:     transportAttemptEvidence(errs, skipped),
		})
		if len(errs) == 0 {
			return handshakeResult{}, successes, attempts, checks, fmt.Errorf("no TLS endpoints available for %s", serviceTarget)
		}
		return handshakeResult{}, successes, attempts, checks, errors.New(strings.Join(errs, "; "))
	}
	checks = append(checks, selectedChecks...)
	checks = append(checks,
		checkreport.Check{
			ID:           "transport.endpoint_attempts",
			State:        transportAttemptState(true, errs),
			Subject:      serviceTarget,
			Message:      transportAttemptMessage(true, errs),
			MinVerbosity: 1,
			Evidence:     transportAttemptEvidence(errs, skipped),
		},
		checkreport.Check{
			ID:           "transport.endpoint_selected",
			State:        checkreport.CheckPass,
			Subject:      selected.Endpoint,
			Message:      fmt.Sprintf("selected endpoint %s for the successful transport session", selected.Endpoint),
			MinVerbosity: 1,
		},
	)
	return selected, successes, attempts, checks, nil
}

func buildAddressCoverageStage(serviceTarget string, attempts []endpointAttemptResult, selectedEndpoint string) checkreport.Stage {
	successCount := 0
	failureCount := 0
	details := make([]string, 0, len(attempts))
	attributes := make([]checkreport.KV, 0, len(attempts)+3)
	for _, attempt := range attempts {
		if attempt.Success {
			successCount++
			details = append(details, fmt.Sprintf("%s=ok", attempt.Endpoint))
			attributes = append(attributes, checkreport.KV{Key: attempt.Endpoint, Value: "ok"})
			continue
		}
		if attempt.Skipped {
			details = append(details, fmt.Sprintf("%s=skipped(%s)", attempt.Endpoint, attempt.Error))
			attributes = append(attributes, checkreport.KV{Key: attempt.Endpoint, Value: "skipped: " + attempt.Error})
			continue
		}
		failureCount++
		details = append(details, fmt.Sprintf("%s=%s", attempt.Endpoint, attempt.Error))
		attributes = append(attributes, checkreport.KV{Key: attempt.Endpoint, Value: attempt.Error})
	}
	attributes = append(attributes,
		checkreport.KV{Key: "successful_endpoints", Value: strconv.Itoa(successCount)},
		checkreport.KV{Key: "failed_endpoints", Value: strconv.Itoa(failureCount)},
	)

	stage := checkreport.Stage{
		ID:     "coverage.addresses",
		Title:  "Address Coverage",
		Status: checkreport.StatusOK,
		Target: serviceTarget,
		Checks: []checkreport.Check{{
			ID:           "coverage.addresses",
			State:        addressCoverageState(successCount, failureCount),
			Subject:      serviceTarget,
			Message:      addressCoverageMessage(successCount, failureCount),
			MinVerbosity: 1,
			Evidence: []checkreport.Evidence{{
				Kind:    "transport",
				Summary: "per-endpoint TLS transport outcomes",
				Attributes: append([]checkreport.KV{
					{Key: "selected_endpoint", Value: emptyStringAsDash(selectedEndpoint)},
					{Key: "attempts", Value: strings.Join(details, " | ")},
				}, attributes...),
			}},
		}},
	}
	if successCount > 1 {
		stage.Checks = append(stage.Checks, checkreport.Check{
			ID:           "coverage.address_semantics",
			State:        checkreport.CheckNote,
			Subject:      selectedEndpoint,
			Message:      fmt.Sprintf("deep TLS semantics are currently evaluated against the selected successful endpoint %s while %d endpoint(s) completed the handshake", selectedEndpoint, successCount),
			MinVerbosity: 1,
		})
	}
	return stage
}

func buildAddressCoverageFinding(serviceTarget string, attempts []endpointAttemptResult) *checkreport.Finding {
	successCount := 0
	var failed []string
	for _, attempt := range attempts {
		if attempt.Success {
			successCount++
			continue
		}
		if attempt.Skipped {
			continue
		}
		failed = append(failed, fmt.Sprintf("%s: %s", attempt.Endpoint, attempt.Error))
	}
	if successCount == 0 || len(failed) == 0 {
		return nil
	}
	finding := makeFinding(
		"tls_endpoint_failed",
		checkreport.StatusWarning,
		serviceTarget,
		fmt.Sprintf("%d resolved endpoint(s) failed TLS transport checks while %d succeeded: %s", len(failed), successCount, strings.Join(failed, " | ")),
	)
	return &finding
}

func buildEndpointSemanticsStage(ctx context.Context, cfg Config, target, serviceTarget string, resolver dnsResolver, roots *x509.CertPool, rootSource string, rootErr error, selected handshakeResult, successful []handshakeResult) (checkreport.Stage, []checkreport.Finding) {
	stage := checkreport.Stage{
		ID:     "coverage.endpoint_semantics",
		Title:  "Endpoint Semantics",
		Status: checkreport.StatusOK,
		Target: serviceTarget,
	}
	if len(successful) == 0 {
		stage.Checks = append(stage.Checks, checkreport.Check{
			ID:      "endpoint_semantics.coverage",
			State:   checkreport.CheckNote,
			Subject: serviceTarget,
			Message: "no successful endpoint handshakes were available for semantic comparison",
		})
		return stage, nil
	}
	stage.Checks = append(stage.Checks,
		checkreport.Check{
			ID:           "endpoint_semantics.scope",
			State:        checkreport.CheckPass,
			Subject:      serviceTarget,
			Message:      fmt.Sprintf("selected endpoint %s anchors the primary detailed path while %d successful endpoint(s) participate in cross-endpoint semantic comparison", selected.Endpoint, len(successful)),
			MinVerbosity: 1,
			Evidence: []checkreport.Evidence{{
				Kind:    "tls",
				Summary: "endpoint semantic comparison scope",
				Attributes: []checkreport.KV{
					{Key: "selected_endpoint", Value: selected.Endpoint},
					{Key: "successful_endpoints", Value: strings.Join(successfulEndpointList(successful), ",")},
					{Key: "successful_endpoint_count", Value: strconv.Itoa(len(successful))},
				},
			}},
		},
		buildSelectedEndpointProfileCheck(serviceTarget, selected),
	)
	if len(successful) == 1 {
		profiles := collectEndpointSemanticProfiles(ctx, cfg, target, resolver, roots, rootSource, rootErr, successful)
		stage.Checks = append(stage.Checks, buildEndpointProfilesCheck(serviceTarget, profiles))
		stage.Checks = append(stage.Checks, checkreport.Check{
			ID:           "endpoint_semantics.coverage",
			State:        checkreport.CheckNote,
			Subject:      successful[0].Endpoint,
			Message:      "only one successful endpoint was available, so no cross-endpoint semantic comparison was required",
			MinVerbosity: 1,
		})
		return stage, nil
	}

	profiles := collectEndpointSemanticProfiles(ctx, cfg, target, resolver, roots, rootSource, rootErr, successful)
	var findings []checkreport.Finding
	stage.Checks = append(stage.Checks,
		buildEndpointProfilesCheck(serviceTarget, profiles),
		buildEndpointProfileCheck(
			"endpoint_semantics.transport",
			serviceTarget,
			"Negotiated transport profile matched across all successful endpoints",
			"successful endpoints negotiated different transport profiles",
			"tls_endpoint_transport_differs",
			buildTransportProfileKey,
			describeTransportProfile,
			profiles,
			&findings,
		),
		buildEndpointProfileCheck(
			"endpoint_semantics.pki",
			serviceTarget,
			"PKI profiles matched across all successful endpoints",
			"successful endpoints presented different PKI profiles",
			"tls_endpoint_pki_differs",
			buildPKIProfileKey,
			describePKIProfile,
			profiles,
			&findings,
		),
		buildEndpointProfileCheck(
			"endpoint_semantics.ocsp",
			serviceTarget,
			"OCSP state matched across all successful endpoints",
			"successful endpoints exposed different OCSP states",
			"tls_endpoint_ocsp_differs",
			buildOCSPProfileKey,
			describeOCSPProfile,
			profiles,
			&findings,
		),
		buildEndpointProfileCheck(
			"endpoint_semantics.ct",
			serviceTarget,
			"Certificate transparency outcome matched across all successful endpoints",
			"successful endpoints exposed different certificate transparency outcomes",
			"tls_endpoint_ct_differs",
			buildCTProfileKey,
			describeCTProfile,
			profiles,
			&findings,
		),
		buildEndpointProfileCheck(
			"endpoint_semantics.dane",
			serviceTarget,
			"DANE/TLSA matching outcome matched across all successful endpoints",
			"successful endpoints did not agree under DANE/TLSA matching",
			"tls_endpoint_dane_differs",
			buildDANEProfileKey,
			describeDANEProfile,
			profiles,
			&findings,
		),
		buildEndpointProfileNoteCheck(
			"endpoint_semantics.sni",
			serviceTarget,
			"SNI versus no-SNI behavior matched across all successful endpoints",
			"successful endpoints exposed different SNI versus no-SNI behavior",
			buildSNIProfileKey,
			describeSNIProfile,
			profiles,
		),
	)
	return stage, findings
}

func buildEndpointProfilesCheck(serviceTarget string, profiles []endpointSemanticProfile) checkreport.Check {
	return checkreport.Check{
		ID:           "endpoint_semantics.profiles",
		State:        checkreport.CheckPass,
		Subject:      serviceTarget,
		Message:      fmt.Sprintf("collected structured semantic profiles for %d successful endpoint(s)", len(profiles)),
		MinVerbosity: 1,
		Evidence: []checkreport.Evidence{{
			Kind:    "tls",
			Summary: "per-endpoint semantic profiles",
			Items:   buildEndpointProfileEvidenceItems(profiles),
		}},
	}
}

func buildSelectedEndpointProfileCheck(serviceTarget string, selected handshakeResult) checkreport.Check {
	return checkreport.Check{
		ID:           "endpoint_semantics.selected_profile",
		State:        checkreport.CheckPass,
		Subject:      selected.Endpoint,
		Message:      fmt.Sprintf("selected endpoint %s negotiated %s with %s and ALPN %s", selected.Endpoint, tlsVersionName(selected.State.Version), cipherSuiteName(selected.State.CipherSuite), emptyStringAsDash(selected.State.NegotiatedProtocol)),
		MinVerbosity: 1,
		Evidence: []checkreport.Evidence{{
			Kind:    "tls",
			Summary: "selected endpoint semantic profile",
			Attributes: []checkreport.KV{
				{Key: "endpoint", Value: selected.Endpoint},
				{Key: "alpn", Value: emptyStringAsDash(selected.State.NegotiatedProtocol)},
				{Key: "version", Value: tlsVersionName(selected.State.Version)},
				{Key: "cipher_suite", Value: cipherSuiteName(selected.State.CipherSuite)},
				{Key: "leaf", Value: handshakeLeafSummary(selected.State)},
				{Key: "remote_addr", Value: selected.RemoteAddr},
			},
		}},
	}
}

func successfulEndpointList(successful []handshakeResult) []string {
	out := make([]string, 0, len(successful))
	for _, hs := range successful {
		out = append(out, hs.Endpoint)
	}
	return out
}

func collectEndpointSemanticProfiles(ctx context.Context, cfg Config, target string, resolver dnsResolver, roots *x509.CertPool, rootSource string, rootErr error, successful []handshakeResult) []endpointSemanticProfile {
	profiles := make([]endpointSemanticProfile, 0, len(successful))
	tlsaResult, tlsaErr, _ := lookupTLSAResult(ctx, resolver, cfg.Port, target)
	for _, hs := range successful {
		ocspAssessment := evaluateOCSP(ctx, cfg, hs.Endpoint, target, resolver, hs.State)
		chain := collectEndpointChainAssessment(cfg, target, roots, hs.State)
		profile := endpointSemanticProfile{
			Endpoint:  hs.Endpoint,
			Transport: collectEndpointTransportProfile(hs.State),
			PKI:       collectEndpointPKIProfile(cfg, target, roots, hs.State, chain),
			OCSP:      collectEndpointOCSPProfile(ocspAssessment),
			CT:        collectEndpointCTProfile(cfg, hs.Endpoint, rootSource, rootErr, chain, hs.State, ocspAssessment),
			DANE:      collectEndpointDANEProfile(tlsaResult, tlsaErr, hs.State),
			SNI:       collectEndpointSNIProfile(ctx, cfg, target, hs),
		}
		profiles = append(profiles, profile)
	}
	return profiles
}

func buildEndpointProfileCheck(
	id, subject, passMessage, warnMessage, findingCode string,
	keyFn func(endpointSemanticProfile) string,
	describeFn func(endpointSemanticProfile) string,
	profiles []endpointSemanticProfile,
	findings *[]checkreport.Finding,
) checkreport.Check {
	details := make([]string, 0, len(profiles))
	seen := map[string]struct{}{}
	for _, profile := range profiles {
		key := keyFn(profile)
		seen[key] = struct{}{}
		details = append(details, fmt.Sprintf("%s=%s", profile.Endpoint, describeFn(profile)))
	}
	check := checkreport.Check{
		ID:           id,
		State:        checkreport.CheckPass,
		Subject:      subject,
		Message:      passMessage,
		MinVerbosity: 1,
		Evidence: []checkreport.Evidence{{
			Kind:    "tls",
			Summary: "per-endpoint semantic profiles",
			Attributes: []checkreport.KV{
				{Key: "profiles", Value: strings.Join(details, " | ")},
			},
		}},
	}
	if len(seen) <= 1 {
		return check
	}
	finding := makeFinding(findingCode, checkreport.StatusWarning, subject, fmt.Sprintf("%s: %s", warnMessage, strings.Join(details, " | ")))
	*findings = append(*findings, finding)
	check.State = checkreport.CheckWarning
	check.Message = finding.Message
	return check
}

func buildEndpointProfileNoteCheck(
	id, subject, passMessage, noteMessage string,
	keyFn func(endpointSemanticProfile) string,
	describeFn func(endpointSemanticProfile) string,
	profiles []endpointSemanticProfile,
) checkreport.Check {
	details := make([]string, 0, len(profiles))
	seen := map[string]struct{}{}
	for _, profile := range profiles {
		key := keyFn(profile)
		seen[key] = struct{}{}
		details = append(details, fmt.Sprintf("%s=%s", profile.Endpoint, describeFn(profile)))
	}
	check := checkreport.Check{
		ID:           id,
		State:        checkreport.CheckPass,
		Subject:      subject,
		Message:      passMessage,
		MinVerbosity: 1,
		Evidence: []checkreport.Evidence{{
			Kind:    "tls",
			Summary: "per-endpoint semantic profiles",
			Attributes: []checkreport.KV{
				{Key: "profiles", Value: strings.Join(details, " | ")},
			},
		}},
	}
	if len(seen) <= 1 {
		return check
	}
	check.State = checkreport.CheckNote
	check.Message = fmt.Sprintf("%s: %s", noteMessage, strings.Join(details, " | "))
	return check
}

func collectEndpointChainAssessment(cfg Config, target string, roots *x509.CertPool, state tls.ConnectionState) chainAssessment {
	if roots == nil || len(state.PeerCertificates) == 0 {
		return chainAssessment{}
	}
	_, _, assessment := evaluateLeafAndChain(cfg, target, "", roots, state.PeerCertificates)
	return assessment
}

func collectEndpointPKIProfile(cfg Config, target string, roots *x509.CertPool, state tls.ConnectionState, chain chainAssessment) endpointPKIProfile {
	profile := endpointPKIProfile{
		LeafSummary: handshakeLeafSummary(state),
	}
	if len(state.PeerCertificates) == 0 {
		return profile
	}
	profile.LeafFingerprint = sha256Hex(state.PeerCertificates[0].Raw)
	profile.ChainFingerprint = chainFingerprint(state.PeerCertificates)
	_ = cfg
	_ = target
	_ = roots
	profile.TrustState = chain.TrustState
	profile.PathCount = chain.PathCount
	return profile
}

func collectEndpointTransportProfile(state tls.ConnectionState) endpointTransportProfile {
	return endpointTransportProfile{
		ALPN:        emptyStringAsDash(state.NegotiatedProtocol),
		Version:     tlsVersionName(state.Version),
		CipherSuite: cipherSuiteName(state.CipherSuite),
	}
}

func collectEndpointOCSPProfile(assessment ocspAssessment) endpointOCSPProfile {
	return endpointOCSPProfile{
		Status: assessment.Status,
		Source: assessment.Source,
	}
}

func collectEndpointCTProfile(cfg Config, target, rootSource string, rootErr error, chain chainAssessment, state tls.ConnectionState, ocspAssessment ocspAssessment) endpointCTProfile {
	policy := determineCTPolicy(cfg, rootSource, rootErr, chain)
	presence := ctSourcePresence(state, ocspAssessment)
	sources := presence.list()
	profile := endpointCTProfile{
		Required:     policy.Required,
		PolicyReason: policy.Reason,
		Sources:      append([]string(nil), sources...),
	}
	switch {
	case len(sources) > 0:
		profile.Status = "present"
	case policy.Required:
		profile.Status = "required_missing"
	default:
		profile.Status = "not_required_absent"
	}
	_ = target
	return profile
}

func collectEndpointDANEProfile(result dnsresolver.LookupResult, err error, state tls.ConnectionState) endpointDANEProfile {
	if err != nil {
		return endpointDANEProfile{Status: "lookup_failed"}
	}
	profile := endpointDANEProfile{Security: result.Security}
	switch result.Security {
	case dnsresolver.SecuritySecure:
		if len(result.Records) == 0 {
			profile.Status = "secure_nodata"
			return profile
		}
		assessment := assessTLSARecords(result.Records, state.PeerCertificates)
		profile.RecordCount = assessment.RecordCount
		profile.MatchedCount = assessment.MatchedCount
		if assessment.MatchedCount > 0 {
			profile.Status = "secure_match"
		} else {
			profile.Status = "secure_mismatch"
		}
	case dnsresolver.SecurityInsecure:
		if len(result.Records) == 0 {
			profile.Status = "insecure_nodata"
		} else {
			profile.Status = "insecure_records"
			profile.RecordCount = len(result.Records)
		}
	case dnsresolver.SecurityBogus:
		profile.Status = "bogus"
	default:
		profile.Status = "indeterminate"
	}
	return profile
}

func collectEndpointSNIProfile(ctx context.Context, cfg Config, target string, hs handshakeResult) endpointSNIProfile {
	if cfg.STARTTLS != tlsx.STARTTLSNone {
		return endpointSNIProfile{Status: "skipped_starttls"}
	}
	if net.ParseIP(target) != nil {
		return endpointSNIProfile{Status: "skipped_ip_literal"}
	}
	probeCtx, cancel := context.WithTimeout(ctx, cfg.HandshakeTimeout)
	defer cancel()
	noSNIResult, _, err := performHandshakeToEndpoint(probeCtx, cfg, "", hs.Endpoint, requestedALPN(cfg))
	if err != nil {
		return endpointSNIProfile{
			Status:        "probe_failed",
			SNILeaf:       handshakeLeafSummary(hs.State),
			SNIALPN:       emptyStringAsDash(hs.State.NegotiatedProtocol),
			SNIVersion:    tlsVersionName(hs.State.Version),
			FailureReason: err.Error(),
		}
	}
	profile := endpointSNIProfile{
		SNILeaf:      handshakeLeafSummary(hs.State),
		NoSNILeaf:    handshakeLeafSummary(noSNIResult.State),
		SNIALPN:      emptyStringAsDash(hs.State.NegotiatedProtocol),
		NoSNIALPN:    emptyStringAsDash(noSNIResult.State.NegotiatedProtocol),
		SNIVersion:   tlsVersionName(hs.State.Version),
		NoSNIVersion: tlsVersionName(noSNIResult.State.Version),
	}
	if handshakeLeafEqual(hs.State, noSNIResult.State) &&
		hs.State.NegotiatedProtocol == noSNIResult.State.NegotiatedProtocol &&
		hs.State.Version == noSNIResult.State.Version {
		profile.Status = "same"
		return profile
	}
	profile.Status = "different"
	return profile
}

func buildTransportProfileKey(profile endpointSemanticProfile) string {
	return strings.Join([]string{
		profile.Transport.ALPN,
		profile.Transport.Version,
		profile.Transport.CipherSuite,
	}, "|")
}

func buildPKIProfileKey(profile endpointSemanticProfile) string {
	return strings.Join([]string{
		profile.PKI.LeafFingerprint,
		profile.PKI.ChainFingerprint,
		string(profile.PKI.TrustState),
		strconv.Itoa(profile.PKI.PathCount),
	}, "|")
}

func buildOCSPProfileKey(profile endpointSemanticProfile) string {
	return profile.OCSP.Status + "|" + profile.OCSP.Source
}

func buildDANEProfileKey(profile endpointSemanticProfile) string {
	return strings.Join([]string{
		profile.DANE.Status,
		string(profile.DANE.Security),
		strconv.Itoa(profile.DANE.MatchedCount),
		strconv.Itoa(profile.DANE.RecordCount),
	}, "|")
}

func buildCTProfileKey(profile endpointSemanticProfile) string {
	return strings.Join([]string{
		profile.CT.Status,
		strconv.FormatBool(profile.CT.Required),
		strings.Join(profile.CT.Sources, ","),
		profile.CT.PolicyReason,
	}, "|")
}

func buildSNIProfileKey(profile endpointSemanticProfile) string {
	return strings.Join([]string{
		profile.SNI.Status,
		profile.SNI.SNILeaf,
		profile.SNI.NoSNILeaf,
		profile.SNI.SNIALPN,
		profile.SNI.NoSNIALPN,
		profile.SNI.SNIVersion,
		profile.SNI.NoSNIVersion,
		profile.SNI.FailureReason,
	}, "|")
}

func describeTransportProfile(profile endpointSemanticProfile) string {
	return fmt.Sprintf("alpn=%s version=%s cipher=%s", profile.Transport.ALPN, profile.Transport.Version, profile.Transport.CipherSuite)
}

func describePKIProfile(profile endpointSemanticProfile) string {
	return fmt.Sprintf("leaf=%s trust=%s paths=%d", profile.PKI.LeafSummary, profile.PKI.TrustState, profile.PKI.PathCount)
}

func describeOCSPProfile(profile endpointSemanticProfile) string {
	return fmt.Sprintf("status=%s source=%s", profile.OCSP.Status, profile.OCSP.Source)
}

func describeCTProfile(profile endpointSemanticProfile) string {
	sources := "none"
	if len(profile.CT.Sources) > 0 {
		sources = strings.Join(profile.CT.Sources, ",")
	}
	return fmt.Sprintf("status=%s required=%t sources=%s", profile.CT.Status, profile.CT.Required, sources)
}

func describeDANEProfile(profile endpointSemanticProfile) string {
	return fmt.Sprintf("status=%s security=%s matched=%d/%d", profile.DANE.Status, profile.DANE.Security, profile.DANE.MatchedCount, profile.DANE.RecordCount)
}

func describeSNIProfile(profile endpointSemanticProfile) string {
	if profile.SNI.FailureReason != "" {
		return fmt.Sprintf("status=%s sni_leaf=%s error=%s", profile.SNI.Status, emptyStringAsDash(profile.SNI.SNILeaf), profile.SNI.FailureReason)
	}
	return fmt.Sprintf("status=%s sni_leaf=%s no_sni_leaf=%s alpn=%s/%s version=%s/%s",
		profile.SNI.Status,
		emptyStringAsDash(profile.SNI.SNILeaf),
		emptyStringAsDash(profile.SNI.NoSNILeaf),
		emptyStringAsDash(profile.SNI.SNIALPN),
		emptyStringAsDash(profile.SNI.NoSNIALPN),
		emptyStringAsDash(profile.SNI.SNIVersion),
		emptyStringAsDash(profile.SNI.NoSNIVersion),
	)
}

func buildEndpointProfileEvidenceItems(profiles []endpointSemanticProfile) []checkreport.EvidenceItem {
	items := make([]checkreport.EvidenceItem, 0, len(profiles))
	for _, profile := range profiles {
		item := checkreport.EvidenceItem{
			ID:      "endpoint_profile",
			Subject: profile.Endpoint,
			Summary: "structured endpoint semantic profile",
			Attributes: []checkreport.KV{
				{Key: "endpoint", Value: profile.Endpoint},
				{Key: "transport.alpn", Value: profile.Transport.ALPN},
				{Key: "transport.version", Value: profile.Transport.Version},
				{Key: "transport.cipher_suite", Value: profile.Transport.CipherSuite},
				{Key: "pki.leaf_summary", Value: profile.PKI.LeafSummary},
				{Key: "pki.leaf_fingerprint", Value: profile.PKI.LeafFingerprint},
				{Key: "pki.chain_fingerprint", Value: profile.PKI.ChainFingerprint},
				{Key: "pki.trust_state", Value: string(profile.PKI.TrustState)},
				{Key: "pki.path_count", Value: strconv.Itoa(profile.PKI.PathCount)},
				{Key: "ocsp.status", Value: profile.OCSP.Status},
				{Key: "ocsp.source", Value: profile.OCSP.Source},
				{Key: "ct.status", Value: profile.CT.Status},
				{Key: "ct.required", Value: strconv.FormatBool(profile.CT.Required)},
				{Key: "ct.sources", Value: emptyStringAsDash(strings.Join(profile.CT.Sources, ","))},
				{Key: "ct.policy_reason", Value: profile.CT.PolicyReason},
				{Key: "dane.status", Value: profile.DANE.Status},
				{Key: "dane.security", Value: string(profile.DANE.Security)},
				{Key: "dane.matched_count", Value: strconv.Itoa(profile.DANE.MatchedCount)},
				{Key: "dane.record_count", Value: strconv.Itoa(profile.DANE.RecordCount)},
				{Key: "sni.status", Value: profile.SNI.Status},
				{Key: "sni.sni_leaf", Value: emptyStringAsDash(profile.SNI.SNILeaf)},
				{Key: "sni.no_sni_leaf", Value: emptyStringAsDash(profile.SNI.NoSNILeaf)},
				{Key: "sni.sni_alpn", Value: emptyStringAsDash(profile.SNI.SNIALPN)},
				{Key: "sni.no_sni_alpn", Value: emptyStringAsDash(profile.SNI.NoSNIALPN)},
				{Key: "sni.sni_version", Value: emptyStringAsDash(profile.SNI.SNIVersion)},
				{Key: "sni.no_sni_version", Value: emptyStringAsDash(profile.SNI.NoSNIVersion)},
			},
		}
		if profile.SNI.FailureReason != "" {
			item.Attributes = append(item.Attributes, checkreport.KV{Key: "sni.failure_reason", Value: profile.SNI.FailureReason})
		}
		items = append(items, item)
	}
	return items
}

func lookupTLSAResult(ctx context.Context, resolver dnsResolver, port int, target string) (dnsresolver.LookupResult, error, string) {
	tlsaName := fmt.Sprintf("_%d._tcp.%s", port, dns.Fqdn(target))
	result, err := resolver.Lookup(ctx, tlsaName, dns.TypeTLSA)
	return result, err, tlsaName
}

func chainFingerprint(chain []*x509.Certificate) string {
	sum := sha256.New()
	for _, cert := range chain {
		if cert == nil {
			continue
		}
		_, _ = sum.Write(cert.Raw)
	}
	return fmt.Sprintf("%x", sum.Sum(nil))
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:])
}

func addressCoverageState(successCount, failureCount int) checkreport.CheckState {
	if successCount == 0 {
		return checkreport.CheckCritical
	}
	if failureCount > 0 {
		return checkreport.CheckWarning
	}
	return checkreport.CheckPass
}

func addressCoverageMessage(successCount, failureCount int) string {
	switch {
	case successCount == 0:
		return fmt.Sprintf("no resolved endpoints completed the TLS handshake and %d endpoint(s) failed", failureCount)
	case failureCount == 0:
		return fmt.Sprintf("all %d resolved endpoint(s) completed the TLS handshake", successCount)
	default:
		return fmt.Sprintf("%d resolved endpoint(s) completed the TLS handshake while %d endpoint(s) failed", successCount, failureCount)
	}
}

func requestedALPN(cfg Config) []string {
	return append([]string(nil), cfg.ExpectALPN...)
}

func evaluateNoSNIProfile(ctx context.Context, cfg Config, target, serviceTarget string, handshake handshakeResult, endpoints []string) ([]checkreport.Check, *checkreport.Finding) {
	if cfg.STARTTLS != tlsx.STARTTLSNone {
		return []checkreport.Check{{
			ID:      "sni.profile",
			State:   checkreport.CheckNote,
			Subject: string(cfg.STARTTLS),
			Message: "no-SNI comparison is skipped for STARTTLS transports",
		}}, nil
	}
	if net.ParseIP(target) != nil {
		return []checkreport.Check{{
			ID:      "sni.profile",
			State:   checkreport.CheckNote,
			Subject: target,
			Message: "no-SNI comparison is skipped for IP-literal targets",
		}}, nil
	}

	probeCtx, cancel := context.WithTimeout(ctx, cfg.HandshakeTimeout)
	defer cancel()
	noSNIResult, _, err := performSingleHandshake(probeCtx, cfg, "", endpoints, requestedALPN(cfg))
	if err != nil {
		return []checkreport.Check{{
			ID:           "sni.profile",
			State:        checkreport.CheckNote,
			Subject:      handshake.Endpoint,
			Message:      fmt.Sprintf("no-SNI comparison could not be completed: %v", err),
			MinVerbosity: 1,
		}}, nil
	}

	sniLeaf := handshakeLeafSummary(handshake.State)
	noSNILeaf := handshakeLeafSummary(noSNIResult.State)
	sameLeaf := handshakeLeafEqual(handshake.State, noSNIResult.State)
	sameALPN := handshake.State.NegotiatedProtocol == noSNIResult.State.NegotiatedProtocol
	sameVersion := handshake.State.Version == noSNIResult.State.Version
	message := fmt.Sprintf(
		"SNI and no-SNI handshakes selected %s leaf, %s ALPN, and %s protocol versions",
		compareWord(sameLeaf),
		compareWord(sameALPN),
		compareWord(sameVersion),
	)
	check := checkreport.Check{
		ID:           "sni.profile",
		State:        checkreport.CheckPass,
		Subject:      serviceTarget,
		Message:      message,
		MinVerbosity: 1,
		Evidence: []checkreport.Evidence{{
			Kind:    "tls",
			Summary: "SNI and no-SNI handshake comparison",
			Attributes: []checkreport.KV{
				{Key: "endpoint", Value: handshake.Endpoint},
				{Key: "sni_leaf", Value: sniLeaf},
				{Key: "sni_alpn", Value: emptyStringAsDash(handshake.State.NegotiatedProtocol)},
				{Key: "sni_version", Value: tlsVersionName(handshake.State.Version)},
				{Key: "no_sni_leaf", Value: noSNILeaf},
				{Key: "no_sni_alpn", Value: emptyStringAsDash(noSNIResult.State.NegotiatedProtocol)},
				{Key: "no_sni_version", Value: tlsVersionName(noSNIResult.State.Version)},
			},
		}},
	}
	if sameLeaf && sameALPN && sameVersion {
		return []checkreport.Check{check}, nil
	}

	finding := makeFinding(
		"tls_sni_profile_differs",
		checkreport.StatusWarning,
		serviceTarget,
		fmt.Sprintf(
			"no-SNI handshake diverged from the SNI-selected profile: sni leaf=%s alpn=%s version=%s; no-sni leaf=%s alpn=%s version=%s",
			sniLeaf,
			emptyStringAsDash(handshake.State.NegotiatedProtocol),
			tlsVersionName(handshake.State.Version),
			noSNILeaf,
			emptyStringAsDash(noSNIResult.State.NegotiatedProtocol),
			tlsVersionName(noSNIResult.State.Version),
		),
	)
	check.State = checkreport.CheckNote
	check.Message = finding.Message
	return []checkreport.Check{check}, nil
}

func performSingleHandshake(ctx context.Context, cfg Config, serverName string, endpoints []string, nextProtos []string) (handshakeResult, []string, error) {
	started := time.Now()
	var errs []string
	for _, endpoint := range endpoints {
		result, _, err := performHandshakeToEndpoint(ctx, cfg, serverName, endpoint, nextProtos)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", endpoint, err))
			continue
		}
		result.Duration = time.Since(started)
		return result, errs, nil
	}
	if len(errs) == 0 {
		return handshakeResult{}, nil, errors.New("no TLS endpoints available for no-SNI comparison")
	}
	return handshakeResult{}, errs, errors.New(strings.Join(errs, "; "))
}

func performHandshakeToEndpoint(ctx context.Context, cfg Config, serverName, endpoint string, nextProtos []string) (handshakeResult, []checkreport.Check, error) {
	tlsConfig := &tls.Config{
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		NextProtos:         append([]string(nil), nextProtos...),
	}
	connRaw, transportChecks, err := dialTLSService(ctx, cfg, serverName, endpoint, tlsConfig)
	if err != nil {
		return handshakeResult{}, transportChecks, err
	}
	defer connRaw.Close()
	conn, ok := connRaw.(*tls.Conn)
	if !ok {
		return handshakeResult{}, transportChecks, fmt.Errorf("unexpected TLS connection type %T", connRaw)
	}
	state := conn.ConnectionState()
	return handshakeResult{
		State:      state,
		Duration:   0,
		RemoteAddr: conn.RemoteAddr().String(),
		Endpoint:   endpoint,
	}, transportChecks, nil
}

func handshakeLeafEqual(left, right tls.ConnectionState) bool {
	if len(left.PeerCertificates) == 0 || len(right.PeerCertificates) == 0 {
		return false
	}
	return bytes.Equal(left.PeerCertificates[0].Raw, right.PeerCertificates[0].Raw)
}

func handshakeLeafSummary(state tls.ConnectionState) string {
	if len(state.PeerCertificates) == 0 {
		return "-"
	}
	leaf := state.PeerCertificates[0]
	if len(leaf.DNSNames) > 0 {
		return leaf.DNSNames[0]
	}
	if leaf.Subject.CommonName != "" {
		return leaf.Subject.CommonName
	}
	return leaf.Subject.String()
}

func compareWord(same bool) string {
	if same {
		return "the same"
	}
	return "different"
}

func dialTLSService(ctx context.Context, cfg Config, serverName, endpoint string, tlsConfig *tls.Config) (net.Conn, []checkreport.Check, error) {
	rawConn, err := (&net.Dialer{Timeout: cfg.HandshakeTimeout}).DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return nil, nil, err
	}

	if cfg.STARTTLS == tlsx.STARTTLSNone {
		tlsConn := tls.Client(rawConn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = rawConn.Close()
			return nil, nil, err
		}
		return tlsConn, []checkreport.Check{
			{
				ID:           "transport.mode",
				State:        checkreport.CheckPass,
				Subject:      endpoint,
				Message:      "direct TLS transport was used without a pre-flight upgrade",
				MinVerbosity: 1,
			},
			{
				ID:      "transport.direct_tls",
				State:   checkreport.CheckPass,
				Subject: endpoint,
				Message: "direct TLS transport was used without a pre-flight upgrade",
			},
		}, nil
	}

	upgradeChecks, err := performSTARTTLSUpgrade(ctx, cfg.STARTTLS, endpoint, rawConn)
	if err != nil {
		_ = rawConn.Close()
		return nil, upgradeChecks, err
	}
	tlsConn := tls.Client(rawConn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, upgradeChecks, err
	}
	return tlsConn, upgradeChecks, nil
}

func transportAttemptState(success bool, errs []string) checkreport.CheckState {
	if len(errs) == 0 {
		return checkreport.CheckPass
	}
	if success {
		return checkreport.CheckNote
	}
	return checkreport.CheckCritical
}

func transportAttemptMessage(success bool, errs []string) string {
	if len(errs) == 0 {
		return "no transport-level endpoint attempts failed during TLS transport probing"
	}
	if success {
		return fmt.Sprintf("%d endpoint transport attempt(s) failed while at least one working TLS session was established", len(errs))
	}
	return fmt.Sprintf("all %d endpoint transport attempt(s) failed", len(errs))
}

func transportAttemptEvidence(errs, skipped []string) []checkreport.Evidence {
	if len(errs) == 0 && len(skipped) == 0 {
		return nil
	}
	attributes := []checkreport.KV{}
	if len(errs) > 0 {
		attributes = append(attributes, checkreport.KV{Key: "attempt_errors", Value: strings.Join(errs, " | ")})
	}
	if len(skipped) > 0 {
		attributes = append(attributes, checkreport.KV{Key: "skipped_endpoints", Value: strings.Join(skipped, " | ")})
	}
	return []checkreport.Evidence{{
		Kind:       "transport",
		Summary:    "transport endpoint attempt failures",
		Attributes: attributes,
	}}
}

func performSTARTTLSUpgrade(ctx context.Context, profile tlsx.STARTTLSProfile, endpoint string, conn net.Conn) ([]checkreport.Check, error) {
	switch profile {
	case tlsx.STARTTLSSMTP:
		return smtpSTARTTLS(ctx, endpoint, conn)
	case tlsx.STARTTLSIMAP:
		return imapSTARTTLS(ctx, endpoint, conn)
	default:
		return nil, fmt.Errorf("unsupported STARTTLS profile %q", profile)
	}
}

func smtpSTARTTLS(ctx context.Context, endpoint string, conn net.Conn) ([]checkreport.Check, error) {
	reader := bufio.NewReader(conn)
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return nil, err
	}
	line, err := readSMTPReply(reader)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(line, "220") {
		return nil, fmt.Errorf("SMTP banner did not start with 220: %s", strings.TrimSpace(line))
	}
	if _, err := fmt.Fprintf(conn, "EHLO check-tls.local\r\n"); err != nil {
		return nil, err
	}
	ehlo, err := readSMTPReply(reader)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(ehlo, "250") {
		return nil, fmt.Errorf("SMTP EHLO failed: %s", strings.TrimSpace(ehlo))
	}
	if !strings.Contains(strings.ToUpper(ehlo), "STARTTLS") {
		return nil, fmt.Errorf("SMTP server did not advertise STARTTLS")
	}
	if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
		return nil, err
	}
	reply, err := readSMTPReply(reader)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(reply, "220") {
		return nil, fmt.Errorf("SMTP STARTTLS command failed: %s", strings.TrimSpace(reply))
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	_ = ctx
	return []checkreport.Check{
		{
			ID:           "transport.starttls.profile",
			State:        checkreport.CheckPass,
			Subject:      endpoint,
			Message:      "SMTP STARTTLS pre-flight completed successfully",
			MinVerbosity: 1,
		},
		{
			ID:      "transport.starttls",
			State:   checkreport.CheckPass,
			Subject: endpoint,
			Message: "SMTP pre-flight succeeded and the session upgraded to TLS",
		},
	}, nil
}

func imapSTARTTLS(ctx context.Context, endpoint string, conn net.Conn) ([]checkreport.Check, error) {
	reader := bufio.NewReader(conn)
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return nil, err
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), "* OK") {
		return nil, fmt.Errorf("IMAP banner did not start with * OK: %s", strings.TrimSpace(line))
	}
	if _, err := fmt.Fprintf(conn, "a001 CAPABILITY\r\n"); err != nil {
		return nil, err
	}
	capability, err := readUntilTagged(reader, "a001")
	if err != nil {
		return nil, err
	}
	if !strings.Contains(strings.ToUpper(capability), "STARTTLS") {
		return nil, fmt.Errorf("IMAP server did not advertise STARTTLS")
	}
	if _, err := fmt.Fprintf(conn, "a002 STARTTLS\r\n"); err != nil {
		return nil, err
	}
	reply, err := readUntilTagged(reader, "a002")
	if err != nil {
		return nil, err
	}
	if !strings.Contains(strings.ToUpper(reply), "A002 OK") {
		return nil, fmt.Errorf("IMAP STARTTLS command failed: %s", strings.TrimSpace(reply))
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	_ = ctx
	return []checkreport.Check{
		{
			ID:           "transport.starttls.profile",
			State:        checkreport.CheckPass,
			Subject:      endpoint,
			Message:      "IMAP STARTTLS pre-flight completed successfully",
			MinVerbosity: 1,
		},
		{
			ID:      "transport.starttls",
			State:   checkreport.CheckPass,
			Subject: endpoint,
			Message: "IMAP pre-flight succeeded and the session upgraded to TLS",
		},
	}, nil
}

func readSMTPReply(reader *bufio.Reader) (string, error) {
	var lines []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		lines = append(lines, line)
		if len(line) < 4 || line[3] != '-' {
			break
		}
	}
	return strings.Join(lines, ""), nil
}

func readUntilTagged(reader *bufio.Reader, tag string) (string, error) {
	var lines []string
	tag = strings.ToUpper(tag)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		lines = append(lines, line)
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), tag+" ") {
			break
		}
	}
	return strings.Join(lines, ""), nil
}

func evaluateALPN(cfg Config, state tls.ConnectionState) (checkreport.Check, *checkreport.Finding) {
	if len(cfg.ExpectALPN) == 0 {
		return checkreport.Check{
			ID:      "handshake.alpn",
			State:   checkreport.CheckNote,
			Subject: emptyStringAsDash(state.NegotiatedProtocol),
			Message: fmt.Sprintf("negotiated ALPN %s", emptyStringAsDash(state.NegotiatedProtocol)),
		}, nil
	}
	if slices.Contains(cfg.ExpectALPN, state.NegotiatedProtocol) {
		return checkreport.Check{
			ID:      "handshake.alpn",
			State:   checkreport.CheckPass,
			Subject: state.NegotiatedProtocol,
			Message: fmt.Sprintf("negotiated expected ALPN %s", state.NegotiatedProtocol),
		}, nil
	}
	finding := makeFinding("tls_alpn_unexpected", checkreport.StatusWarning, "", fmt.Sprintf("server negotiated ALPN %s, expected one of %s", emptyStringAsDash(state.NegotiatedProtocol), strings.Join(cfg.ExpectALPN, ",")))
	return checkreport.Check{
		ID:      "handshake.alpn",
		State:   checkreport.CheckWarning,
		Subject: emptyStringAsDash(state.NegotiatedProtocol),
		Message: finding.Message,
	}, &finding
}

func evaluateNegotiatedCipher(target string, state tls.ConnectionState) (checkreport.Check, *checkreport.Finding) {
	name := cipherSuiteName(state.CipherSuite)
	reasons := weakCipherReasons(name)
	if len(reasons) == 0 {
		return checkreport.Check{
			ID:      "cipher.negotiated",
			State:   checkreport.CheckPass,
			Subject: name,
			Message: fmt.Sprintf("negotiated cipher suite %s satisfies the current TLS 1.2 policy baseline", name),
		}, nil
	}
	msg := fmt.Sprintf("negotiated cipher suite %s is considered weak: %s", name, strings.Join(reasons, ", "))
	finding := makeFinding("tls_cipher_weak_supported", checkreport.StatusWarning, target, msg)
	return checkreport.Check{
		ID:      "cipher.negotiated",
		State:   checkreport.CheckWarning,
		Subject: name,
		Message: msg,
	}, &finding
}

func evaluateOCSP(ctx context.Context, cfg Config, target, serverName string, resolver dnsResolver, state tls.ConnectionState) ocspAssessment {
	value := 0.0
	metric := checkreport.Metric{Name: "ocsp_stapling_status", Type: "binary", Unit: "state", Value: "0", Number: &value}
	assessment := ocspAssessment{
		Check: checkreport.Check{
			ID:      "revocation.ocsp_stapling",
			State:   checkreport.CheckNote,
			Subject: target,
			Message: "OCSP stapling is not present",
		},
		Metric: metric,
		Status: "not_present",
		Source: "stapled",
	}
	if cfg.OCSPMode == pkix.OCSPOff {
		assessment.Check.Message = "OCSP validation is disabled by policy"
		assessment.Status = "disabled"
		return assessment
	}
	if len(state.OCSPResponse) > 0 {
		assessment = evaluateStapledOCSP(target, state, metric)
		if cfg.OCSPMode == pkix.OCSPStapled {
			return assessment
		}
		if cfg.OCSPMode == pkix.OCSPActive && assessment.Status == "good" {
			return assessment
		}
	} else if cfg.OCSPMode == pkix.OCSPStapled {
		return assessment
	}

	if len(state.PeerCertificates) < 2 {
		finding := makeFinding("tls_ocsp_lookup_failed", checkreport.StatusWarning, target, "OCSP responder validation requires both leaf and issuer certificates")
		return ocspAssessment{
			Check: checkreport.Check{
				ID:      "revocation.ocsp_responder",
				State:   checkreport.CheckWarning,
				Subject: target,
				Message: finding.Message,
			},
			Finding: &finding,
			Metric:  metric,
			Status:  "lookup_failed",
			Source:  "responder",
		}
	}

	active := evaluateActiveOCSP(ctx, cfg, target, serverName, resolver, state.PeerCertificates[0], state.PeerCertificates[1], metric)
	if cfg.OCSPMode == pkix.OCSPStrict && assessment.Status != "" && assessment.Status != "disabled" && assessment.Status != "not_present" {
		if mismatch := compareOCSPAssessments(target, assessment, active); mismatch != nil {
			return *mismatch
		}
	}
	return active
}

func evaluateOCSPDetailed(ctx context.Context, cfg Config, target, serverName string, resolver dnsResolver, state tls.ConnectionState) ocspDetails {
	summary := evaluateOCSP(ctx, cfg, target, serverName, resolver, state)
	checks := []checkreport.Check{
		{
			ID:           "revocation.ocsp.policy",
			State:        boolToCheckState(cfg.OCSPMode != pkix.OCSPOff, checkreport.CheckPass, checkreport.CheckNote),
			Subject:      target,
			Message:      fmt.Sprintf("OCSP policy mode is %s", cfg.OCSPMode),
			MinVerbosity: 1,
		},
	}

	stapledCheck := checkreport.Check{
		ID:           "revocation.ocsp.source.stapled",
		State:        checkreport.CheckNote,
		Subject:      target,
		Message:      "no stapled OCSP response was observed",
		MinVerbosity: 1,
	}
	if len(state.OCSPResponse) > 0 {
		stapled := evaluateStapledOCSP(target, state, summary.Metric)
		stapledCheck = stapled.Check
		stapledCheck.ID = "revocation.ocsp.source.stapled"
		stapledCheck.MinVerbosity = 1
	}
	checks = append(checks, stapledCheck)

	responderCheck := checkreport.Check{
		ID:           "revocation.ocsp.source.responder",
		State:        checkreport.CheckNote,
		Subject:      target,
		Message:      "OCSP responder was not queried by policy",
		MinVerbosity: 1,
	}
	if cfg.OCSPMode == pkix.OCSPActive || cfg.OCSPMode == pkix.OCSPStrict {
		if len(state.PeerCertificates) >= 2 {
			active := evaluateActiveOCSP(ctx, cfg, target, serverName, resolver, state.PeerCertificates[0], state.PeerCertificates[1], summary.Metric)
			responderCheck = active.Check
			responderCheck.ID = "revocation.ocsp.source.responder"
			responderCheck.MinVerbosity = 1
		} else {
			responderCheck = checkreport.Check{
				ID:           "revocation.ocsp.source.responder",
				State:        checkreport.CheckWarning,
				Subject:      target,
				Message:      "OCSP responder validation requires both leaf and issuer certificates",
				MinVerbosity: 1,
			}
		}
	}
	checks = append(checks, responderCheck)

	summaryCheck := summary.Check
	summaryCheck.ID = "revocation.ocsp"
	summaryCheck.MinVerbosity = 1
	checks = append(checks, summaryCheck)

	return ocspDetails{Summary: summary, Checks: checks}
}

func evaluateStapledOCSP(target string, state tls.ConnectionState, metric checkreport.Metric) ocspAssessment {
	if len(state.PeerCertificates) < 2 {
		finding := makeFinding("tls_ocsp_stapling_invalid", checkreport.StatusWarning, target, "OCSP stapling is present but the issuer certificate needed for validation was not provided")
		return ocspAssessment{
			Check: checkreport.Check{
				ID:      "revocation.ocsp_stapling",
				State:   checkreport.CheckWarning,
				Subject: target,
				Message: finding.Message,
			},
			Finding: &finding,
			Metric:  metric,
			Status:  "invalid",
			Source:  "stapled",
		}
	}
	return evaluateParsedOCSP("revocation.ocsp_stapling", target, state.OCSPResponse, state.PeerCertificates[0], state.PeerCertificates[1], metric, "tls_ocsp_stapling_invalid", "tls_ocsp_stapling_revoked", "stapled")
}

func evaluateActiveOCSP(ctx context.Context, cfg Config, target, serverName string, resolver dnsResolver, leaf, issuer *x509.Certificate, metric checkreport.Metric) ocspAssessment {
	if len(leaf.OCSPServer) == 0 {
		return ocspAssessment{
			Check: checkreport.Check{
				ID:      "revocation.ocsp_responder",
				State:   checkreport.CheckNote,
				Subject: target,
				Message: "certificate does not advertise an OCSP responder URL",
			},
			Metric: metric,
			Status: "not_present",
			Source: "responder",
		}
	}

	requestBytes, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		finding := makeFinding("tls_ocsp_lookup_failed", checkreport.StatusWarning, target, fmt.Sprintf("failed to build OCSP request: %v", err))
		return ocspAssessment{
			Check: checkreport.Check{
				ID:      "revocation.ocsp_responder",
				State:   checkreport.CheckWarning,
				Subject: target,
				Message: finding.Message,
			},
			Finding: &finding,
			Metric:  metric,
			Status:  "lookup_failed",
			Source:  "responder",
		}
	}

	client := httpx.NewClient(cfg.HandshakeTimeout, httpx.Options{
		DNSResolver:           resolver,
		DNSLookupTimeout:      cfg.DNSTimeout,
		CacheBackend:          cfg.CacheBackend,
		TransportFamilyPolicy: cfg.TransportFamilyPolicy,
	})
	var lastErr error
	for _, url := range leaf.OCSPServer {
		reqCtx, cancel := context.WithTimeout(ctx, cfg.HandshakeTimeout)
		req, reqErr := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(requestBytes))
		if reqErr != nil {
			cancel()
			lastErr = reqErr
			continue
		}
		req.Header.Set("Content-Type", "application/ocsp-request")
		req.Header.Set("Accept", "application/ocsp-response")
		req.Header.Set("Host", req.URL.Host)
		resp, doErr := client.Do(req)
		if doErr != nil {
			cancel()
			lastErr = doErr
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		cancel()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			lastErr = fmt.Errorf("HTTP %d from OCSP responder", resp.StatusCode)
			continue
		}
		return evaluateParsedOCSP("revocation.ocsp_responder", target, body, leaf, issuer, metric, "tls_ocsp_response_invalid", "tls_ocsp_response_revoked", "responder")
	}

	msg := "OCSP responder lookup failed"
	if lastErr != nil {
		msg = fmt.Sprintf("OCSP responder lookup failed: %v", lastErr)
	}
	finding := makeFinding("tls_ocsp_lookup_failed", checkreport.StatusWarning, target, msg)
	return ocspAssessment{
		Check: checkreport.Check{
			ID:      "revocation.ocsp_responder",
			State:   checkreport.CheckWarning,
			Subject: serverName,
			Message: finding.Message,
		},
		Finding: &finding,
		Metric:  metric,
		Status:  "lookup_failed",
		Source:  "responder",
	}
}

func evaluateParsedOCSP(checkID, target string, responseBytes []byte, leaf, issuer *x509.Certificate, metric checkreport.Metric, invalidCode, revokedCode, source string) ocspAssessment {
	resp, err := ocsp.ParseResponseForCert(responseBytes, leaf, issuer)
	if err != nil {
		finding := makeFinding(invalidCode, checkreport.StatusWarning, target, fmt.Sprintf("OCSP %s response could not be validated: %v", source, err))
		return ocspAssessment{
			Check: checkreport.Check{
				ID:      checkID,
				State:   checkreport.CheckWarning,
				Subject: target,
				Message: finding.Message,
			},
			Finding: &finding,
			Metric:  metric,
			Status:  "invalid",
			Source:  source,
		}
	}

	now := time.Now().UTC()
	check := checkreport.Check{
		ID:      checkID,
		Subject: target,
		Evidence: []checkreport.Evidence{{
			Kind:    "ocsp",
			Summary: fmt.Sprintf("%s OCSP response", source),
			Attributes: []checkreport.KV{
				{Key: "status", Value: ocspStatusName(resp.Status)},
				{Key: "this_update", Value: resp.ThisUpdate.UTC().Format(time.RFC3339)},
				{Key: "next_update", Value: timeOrDash(resp.NextUpdate)},
				{Key: "source", Value: source},
			},
		}},
	}

	switch resp.Status {
	case ocsp.Good:
	case ocsp.Revoked:
		finding := makeFinding(revokedCode, checkreport.StatusCritical, target, fmt.Sprintf("OCSP %s response reported the certificate as revoked at %s", source, resp.RevokedAt.UTC().Format(time.RFC3339)))
		check.State = checkreport.CheckCritical
		check.Message = finding.Message
		return ocspAssessment{Check: check, Finding: &finding, Metric: metric, Status: "revoked", Source: source, Parsed: resp}
	default:
		finding := makeFinding(invalidCode, checkreport.StatusWarning, target, fmt.Sprintf("OCSP %s response returned status %s", source, ocspStatusName(resp.Status)))
		check.State = checkreport.CheckWarning
		check.Message = finding.Message
		return ocspAssessment{Check: check, Finding: &finding, Metric: metric, Status: "invalid", Source: source, Parsed: resp}
	}

	if resp.ThisUpdate.After(now.Add(5 * time.Minute)) {
		finding := makeFinding(invalidCode, checkreport.StatusWarning, target, fmt.Sprintf("OCSP %s response is not yet valid until %s", source, resp.ThisUpdate.UTC().Format(time.RFC3339)))
		check.State = checkreport.CheckWarning
		check.Message = finding.Message
		return ocspAssessment{Check: check, Finding: &finding, Metric: metric, Status: "invalid", Source: source, Parsed: resp}
	}
	if !resp.NextUpdate.IsZero() && now.After(resp.NextUpdate) {
		finding := makeFinding(invalidCode, checkreport.StatusWarning, target, fmt.Sprintf("OCSP %s response expired at %s", source, resp.NextUpdate.UTC().Format(time.RFC3339)))
		check.State = checkreport.CheckWarning
		check.Message = finding.Message
		return ocspAssessment{Check: check, Finding: &finding, Metric: metric, Status: "invalid", Source: source, Parsed: resp}
	}

	if metric.Number != nil {
		*metric.Number = 1
	}
	metric.Value = "1"
	check.State = checkreport.CheckPass
	check.Message = fmt.Sprintf("OCSP %s response is present and valid", source)
	return ocspAssessment{Check: check, Metric: metric, Status: "good", Source: source, Parsed: resp}
}

func compareOCSPAssessments(target string, stapled, active ocspAssessment) *ocspAssessment {
	if stapled.Status == "" || active.Status == "" || stapled.Status == active.Status {
		return nil
	}
	finding := makeFinding("tls_ocsp_staple_responder_mismatch", checkreport.StatusWarning, target, fmt.Sprintf("stapled OCSP status %s and live responder status %s did not agree", stapled.Status, active.Status))
	return &ocspAssessment{
		Check: checkreport.Check{
			ID:      "revocation.ocsp_consistency",
			State:   checkreport.CheckWarning,
			Subject: target,
			Message: finding.Message,
		},
		Finding: &finding,
		Metric:  active.Metric,
		Status:  "mismatch",
	}
}

func evaluateSCT(target string, state tls.ConnectionState, policy ctPolicy, ocspAssessments ...ocspAssessment) ctAssessment {
	presence := ctSourcePresence(state, ocspAssessments...)
	checks := []checkreport.Check{
		{
			ID:           "ct.policy",
			State:        boolToCheckState(policy.Required, checkreport.CheckPass, checkreport.CheckNote),
			Subject:      target,
			Message:      ctPolicyMessage(policy),
			MinVerbosity: 1,
			Meta: []checkreport.KV{
				{Key: "required", Value: strconv.FormatBool(policy.Required)},
			},
		},
		ctSourceCheck("ct.source.tls", target, "tls", presence.TLS),
		ctSourceCheck("ct.source.certificate", target, "certificate", presence.Certificate),
		ctSourceCheck("ct.source.stapled", target, "stapled OCSP", presence.Stapled),
		ctSourceCheck("ct.source.responder", target, "OCSP responder", presence.Responder),
	}

	sources := presence.list()
	if len(sources) > 0 {
		checks = append(checks, checkreport.Check{
			ID:      "ct.sct",
			State:   checkreport.CheckPass,
			Subject: target,
			Message: fmt.Sprintf("certificate transparency data was present via %s", strings.Join(sources, ", ")),
			Evidence: []checkreport.Evidence{{
				Kind:    "ct",
				Summary: "certificate transparency source assessment",
				Attributes: []checkreport.KV{
					{Key: "sources", Value: strings.Join(sources, ",")},
					{Key: "required", Value: strconv.FormatBool(policy.Required)},
					{Key: "policy_reason", Value: policy.Reason},
				},
			}},
		})
		return ctAssessment{Checks: checks}
	}
	if !policy.Required {
		checks = append(checks, checkreport.Check{
			ID:      "ct.sct",
			State:   checkreport.CheckNote,
			Subject: target,
			Message: fmt.Sprintf("certificate transparency data was not observed, but CT is not required: %s", policy.Reason),
			Evidence: []checkreport.Evidence{{
				Kind:    "ct",
				Summary: "certificate transparency source assessment",
				Attributes: []checkreport.KV{
					{Key: "sources", Value: "none"},
					{Key: "required", Value: "false"},
					{Key: "policy_reason", Value: policy.Reason},
				},
			}},
		})
		return ctAssessment{Checks: checks}
	}
	finding := makeFinding("tls_sct_missing", checkreport.StatusWarning, target, "certificate transparency data was not observed via TLS, certificate, or OCSP")
	checks = append(checks, checkreport.Check{
		ID:      "ct.sct",
		State:   checkreport.CheckWarning,
		Subject: target,
		Message: finding.Message,
		Evidence: []checkreport.Evidence{{
			Kind:    "ct",
			Summary: "certificate transparency source assessment",
			Attributes: []checkreport.KV{
				{Key: "sources", Value: "none"},
				{Key: "required", Value: "true"},
				{Key: "policy_reason", Value: policy.Reason},
			},
		}},
	})
	return ctAssessment{Checks: checks, Finding: &finding}
}

var embeddedSCTExtensionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
var ocspSCTExtensionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 5}

type ctPresence struct {
	TLS         bool
	Certificate bool
	Stapled     bool
	Responder   bool
}

func ctSourcePresence(state tls.ConnectionState, ocspAssessments ...ocspAssessment) ctPresence {
	presence := ctPresence{
		Stapled:     stapledOCSPHasSCT(state),
		TLS:         len(state.SignedCertificateTimestamps) > 0,
		Certificate: leafHasEmbeddedSCT(state.PeerCertificates),
	}
	for _, assessment := range ocspAssessments {
		if assessment.Status != "good" || assessment.Parsed == nil || !ocspHasSCT(assessment.Parsed) {
			continue
		}
		switch assessment.Source {
		case "responder":
			presence.Responder = true
		case "stapled":
			presence.Stapled = true
		default:
			presence.Responder = true
		}
	}
	return presence
}

func (p ctPresence) list() []string {
	var sources []string
	if p.TLS {
		sources = append(sources, "tls")
	}
	if p.Certificate {
		sources = append(sources, "certificate")
	}
	if p.Stapled {
		sources = append(sources, "stapled")
	}
	if p.Responder {
		sources = append(sources, "responder")
	}
	return sources
}

func ctPolicyMessage(policy ctPolicy) string {
	if policy.Required {
		return fmt.Sprintf("certificate transparency is required: %s", policy.Reason)
	}
	return fmt.Sprintf("certificate transparency is not required: %s", policy.Reason)
}

func ctSourceCheck(id, target, label string, present bool) checkreport.Check {
	state := checkreport.CheckNote
	message := fmt.Sprintf("no certificate transparency data was observed via %s", label)
	if present {
		state = checkreport.CheckPass
		message = fmt.Sprintf("certificate transparency data was observed via %s", label)
	}
	return checkreport.Check{
		ID:           id,
		State:        state,
		Subject:      target,
		Message:      message,
		MinVerbosity: 1,
	}
}

func boolToCheckState(v bool, yes, no checkreport.CheckState) checkreport.CheckState {
	if v {
		return yes
	}
	return no
}

func determineCTPolicy(cfg Config, rootSource string, rootErr error, chain chainAssessment) ctPolicy {
	if rootErr != nil {
		return ctPolicy{Required: false, Reason: "trust roots could not be loaded"}
	}
	if cfg.CAFile != "" || cfg.CAPath != "" {
		return ctPolicy{Required: false, Reason: "custom trust anchors were configured"}
	}
	if rootSource != "system roots" {
		return ctPolicy{Required: false, Reason: fmt.Sprintf("trust roots came from %s", rootSource)}
	}
	if chain.TrustState != chainTrustTrusted {
		reason := chain.Description
		if reason == "" {
			reason = fmt.Sprintf("certificate chain trust state was %s", chain.TrustState)
		}
		return ctPolicy{Required: false, Reason: reason}
	}
	return ctPolicy{Required: true, Reason: "certificate chain validated against system roots"}
}

func leafHasEmbeddedSCT(chain []*x509.Certificate) bool {
	if len(chain) == 0 || chain[0] == nil {
		return false
	}
	for _, ext := range chain[0].Extensions {
		if ext.Id.Equal(embeddedSCTExtensionOID) && len(ext.Value) > 0 {
			return true
		}
	}
	return false
}

func ocspHasSCT(resp *ocsp.Response) bool {
	if resp == nil {
		return false
	}
	for _, ext := range resp.Extensions {
		if ext.Id.Equal(ocspSCTExtensionOID) && len(ext.Value) > 0 {
			return true
		}
	}
	return false
}

func stapledOCSPHasSCT(state tls.ConnectionState) bool {
	if len(state.OCSPResponse) == 0 || len(state.PeerCertificates) < 2 {
		return false
	}
	resp, err := ocsp.ParseResponseForCert(state.OCSPResponse, state.PeerCertificates[0], state.PeerCertificates[1])
	if err != nil || !ocspResponseUsableForCT(resp, time.Now().UTC()) {
		return false
	}
	return ocspHasSCT(resp)
}

func ocspResponseUsableForCT(resp *ocsp.Response, now time.Time) bool {
	if resp == nil || resp.Status != ocsp.Good {
		return false
	}
	if resp.ThisUpdate.After(now.Add(5 * time.Minute)) {
		return false
	}
	if !resp.NextUpdate.IsZero() && now.After(resp.NextUpdate) {
		return false
	}
	return true
}

func evaluateLeafAndChain(cfg Config, target, serviceTarget string, roots *x509.CertPool, chain []*x509.Certificate) ([]checkreport.Check, []checkreport.Finding, chainAssessment) {
	now := time.Now()
	leaf := chain[0]
	graph := buildPKIGraphEvidence(chain, nil, chainTrustUnknown)
	checks := []checkreport.Check{
		{
			ID:      "pki.leaf",
			State:   checkreport.CheckPass,
			Subject: leaf.Subject.String(),
			Message: "leaf certificate was presented",
		},
		{
			ID:           "pki.chain.presented",
			State:        checkreport.CheckPass,
			Subject:      serviceTarget,
			Message:      describePresentedChain(chain),
			MinVerbosity: 1,
		},
		{
			ID:           "pki.chain.policy",
			State:        checkreport.CheckPass,
			Subject:      serviceTarget,
			Message:      fmt.Sprintf("untrusted root policy is %s", cfg.PolicyUntrustedRoot),
			MinVerbosity: 1,
		},
		{
			ID:           "pki.graph",
			State:        checkreport.CheckNote,
			Subject:      serviceTarget,
			Message:      fmt.Sprintf("structured PKI graph contains %d presented certificate node(s)", len(chain)),
			MinVerbosity: 1,
			Evidence:     []checkreport.Evidence{graph},
		},
	}
	var findings []checkreport.Finding

	if err := leaf.VerifyHostname(target); err != nil {
		findings = append(findings, makeFinding("tls_hostname_mismatch", checkreport.StatusCritical, serviceTarget, err.Error()))
		checks = append(checks, checkreport.Check{
			ID:      "pki.hostname",
			State:   checkreport.CheckCritical,
			Subject: target,
			Message: err.Error(),
		})
	} else {
		checks = append(checks, checkreport.Check{
			ID:      "pki.hostname",
			State:   checkreport.CheckPass,
			Subject: target,
			Message: "certificate SANs matched the requested hostname",
		})
	}

	if now.Before(leaf.NotBefore) {
		msg := fmt.Sprintf("certificate is not valid before %s", leaf.NotBefore.UTC().Format(time.RFC3339))
		findings = append(findings, makeFinding("tls_cert_not_yet_valid", checkreport.StatusCritical, serviceTarget, msg))
		checks = append(checks, checkreport.Check{ID: "pki.validity.not_before", State: checkreport.CheckCritical, Subject: serviceTarget, Message: msg})
	} else {
		checks = append(checks, checkreport.Check{ID: "pki.validity.not_before", State: checkreport.CheckPass, Subject: serviceTarget, Message: fmt.Sprintf("certificate validity already started at %s", leaf.NotBefore.UTC().Format(time.RFC3339))})
	}

	daysToExpire := int(time.Until(leaf.NotAfter).Hours() / 24)
	if now.After(leaf.NotAfter) {
		msg := fmt.Sprintf("certificate expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
		findings = append(findings, makeFinding("tls_cert_expired", checkreport.StatusCritical, serviceTarget, msg))
		checks = append(checks, checkreport.Check{ID: "pki.validity.not_after", State: checkreport.CheckCritical, Subject: serviceTarget, Message: msg})
	} else if daysToExpire < cfg.WarnExpiryDays {
		msg := fmt.Sprintf("certificate expires in %d days", daysToExpire)
		findings = append(findings, makeFinding("tls_cert_expiry_soon", checkreport.StatusWarning, serviceTarget, msg))
		checks = append(checks, checkreport.Check{ID: "pki.validity.not_after", State: checkreport.CheckWarning, Subject: serviceTarget, Message: msg})
	} else {
		checks = append(checks, checkreport.Check{ID: "pki.validity.not_after", State: checkreport.CheckPass, Subject: serviceTarget, Message: fmt.Sprintf("certificate expires in %d days", daysToExpire)})
	}

	if msg, weak := publicKeyWeakness(leaf); weak {
		findings = append(findings, makeFinding("tls_public_key_weak", checkreport.StatusWarning, serviceTarget, msg))
		checks = append(checks, checkreport.Check{ID: "pki.key_strength", State: checkreport.CheckWarning, Subject: serviceTarget, Message: msg})
	} else {
		checks = append(checks, checkreport.Check{ID: "pki.key_strength", State: checkreport.CheckPass, Subject: serviceTarget, Message: "certificate public key strength satisfies the current minimum policy"})
	}
	if msg, legacy := curveWeakness(leaf); legacy {
		findings = append(findings, makeFinding("tls_curve_legacy", checkreport.StatusWarning, serviceTarget, msg))
		checks = append(checks, checkreport.Check{ID: "pki.curve_policy", State: checkreport.CheckWarning, Subject: serviceTarget, Message: msg})
	}

	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	verifyOpts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CurrentTime:   now,
	}
	verifiedChains, err := leaf.Verify(verifyOpts)
	if err == nil {
		graph = buildPKIGraphEvidence(chain, verifiedChains, chainTrustTrusted)
		checks[3].State = checkreport.CheckPass
		checks[3].Message = fmt.Sprintf("structured PKI graph contains %d presented certificate node(s) and %d verified trust path(s)", len(chain), len(verifiedChains))
		checks[3].Evidence = []checkreport.Evidence{graph}
		checks = append(checks, checkreport.Check{
			ID:           "pki.chain.verify",
			State:        checkreport.CheckPass,
			Subject:      serviceTarget,
			Message:      fmt.Sprintf("x509 path validation succeeded with %d trust path(s)", len(verifiedChains)),
			MinVerbosity: 1,
		})
		checks = append(checks, checkreport.Check{
			ID:      "pki.chain",
			State:   checkreport.CheckPass,
			Subject: serviceTarget,
			Message: fmt.Sprintf("certificate chain validated through %d trust path(s)", len(verifiedChains)),
		})
		return checks, findings, chainAssessment{
			PathCount:   len(verifiedChains),
			TrustState:  chainTrustTrusted,
			Description: fmt.Sprintf("certificate chain validated through %d trust path(s)", len(verifiedChains)),
			Graph:       graph,
		}
	}

	switch {
	case errors.As(err, new(x509.UnknownAuthorityError)):
		if looksIncompleteChain(chain) {
			graph = buildPKIGraphEvidence(chain, nil, chainTrustInvalid)
			checks[3].Message = fmt.Sprintf("structured PKI graph contains %d presented certificate node(s) and no verified trust paths", len(chain))
			checks[3].Evidence = []checkreport.Evidence{graph}
			msg := "server did not provide the intermediate certificates needed to build a trust path"
			findings = append(findings, makeFinding("tls_chain_incomplete", checkreport.StatusCritical, serviceTarget, msg))
			checks = append(checks, checkreport.Check{
				ID:           "pki.chain.verify",
				State:        checkreport.CheckCritical,
				Subject:      serviceTarget,
				Message:      "x509 path validation failed because the presented chain does not include a matching issuer for the leaf certificate",
				MinVerbosity: 1,
			})
			checks = append(checks, checkreport.Check{ID: "pki.chain", State: checkreport.CheckCritical, Subject: serviceTarget, Message: msg})
			return checks, findings, chainAssessment{TrustState: chainTrustInvalid, Description: msg, Graph: graph}
		}
		graph = buildPKIGraphEvidence(chain, nil, chainTrustUntrusted)
		checks[3].Message = fmt.Sprintf("structured PKI graph contains %d presented certificate node(s) and no verified trust paths", len(chain))
		checks[3].Evidence = []checkreport.Evidence{graph}
		switch cfg.PolicyUntrustedRoot {
		case pkix.UntrustedRootWarning:
			msg := "certificate chain ended in an untrusted root, but policy downgraded this to warning"
			findings = append(findings, makeFinding("tls_untrusted_root_policy_degraded", checkreport.StatusWarning, serviceTarget, msg))
			checks = append(checks, checkreport.Check{
				ID:           "pki.chain.verify",
				State:        checkreport.CheckWarning,
				Subject:      serviceTarget,
				Message:      "x509 path validation reached an untrusted root and policy downgraded the result to warning",
				MinVerbosity: 1,
			})
			checks = append(checks, checkreport.Check{ID: "pki.chain", State: checkreport.CheckWarning, Subject: serviceTarget, Message: msg})
		case pkix.UntrustedRootOK:
			checks = append(checks, checkreport.Check{
				ID:           "pki.chain.verify",
				State:        checkreport.CheckNote,
				Subject:      serviceTarget,
				Message:      "x509 path validation reached an untrusted root, but policy accepts this condition",
				MinVerbosity: 1,
			})
			checks = append(checks, checkreport.Check{ID: "pki.chain", State: checkreport.CheckNote, Subject: serviceTarget, Message: "certificate chain ended in an untrusted root, but policy accepts this condition"})
		default:
			msg := "certificate chain did not terminate in a trusted root"
			findings = append(findings, makeFinding("tls_chain_untrusted", checkreport.StatusCritical, serviceTarget, msg))
			checks = append(checks, checkreport.Check{
				ID:           "pki.chain.verify",
				State:        checkreport.CheckCritical,
				Subject:      serviceTarget,
				Message:      "x509 path validation reached an untrusted root",
				MinVerbosity: 1,
			})
			checks = append(checks, checkreport.Check{ID: "pki.chain", State: checkreport.CheckCritical, Subject: serviceTarget, Message: msg})
		}
		return checks, findings, chainAssessment{TrustState: chainTrustUntrusted, Description: "certificate chain did not terminate in a trusted root", Graph: graph}
	default:
		graph = buildPKIGraphEvidence(chain, nil, chainTrustInvalid)
		checks[3].Message = fmt.Sprintf("structured PKI graph contains %d presented certificate node(s) and no verified trust paths", len(chain))
		checks[3].Evidence = []checkreport.Evidence{graph}
		msg := fmt.Sprintf("certificate chain validation failed: %v", err)
		findings = append(findings, makeFinding("tls_chain_invalid", checkreport.StatusCritical, serviceTarget, msg))
		checks = append(checks, checkreport.Check{
			ID:           "pki.chain.verify",
			State:        checkreport.CheckCritical,
			Subject:      serviceTarget,
			Message:      msg,
			MinVerbosity: 1,
		})
		checks = append(checks, checkreport.Check{ID: "pki.chain", State: checkreport.CheckCritical, Subject: serviceTarget, Message: msg})
		return checks, findings, chainAssessment{TrustState: chainTrustInvalid, Description: msg, Graph: graph}
	}
}

func buildPKIGraphEvidence(presented []*x509.Certificate, verifiedChains [][]*x509.Certificate, trustState chainTrustState) checkreport.Evidence {
	type graphNode struct {
		cert               *x509.Certificate
		roles              []string
		presented          bool
		presentedIndex     int
		verifiedPathCount  int
		verifiedPathBitmap map[int]struct{}
		trustAnchor        bool
	}

	nodeOrder := make([]string, 0, len(presented)+len(verifiedChains))
	nodes := map[string]*graphNode{}
	edgeItems := make([]checkreport.EvidenceItem, 0, len(presented)+len(verifiedChains)*2)

	appendRole := func(node *graphNode, role string) {
		if node == nil || role == "" {
			return
		}
		if !slices.Contains(node.roles, role) {
			node.roles = append(node.roles, role)
		}
	}

	upsertNode := func(cert *x509.Certificate) (string, *graphNode) {
		if cert == nil {
			return "", nil
		}
		nodeID := "cert:" + shortFingerprint(cert.Raw)
		node := nodes[nodeID]
		if node == nil {
			node = &graphNode{
				cert:               cert,
				presentedIndex:     -1,
				verifiedPathBitmap: map[int]struct{}{},
			}
			nodes[nodeID] = node
			nodeOrder = append(nodeOrder, nodeID)
		}
		return nodeID, node
	}

	appendEdge := func(edgeID, summary, relation, fromNode, toNode string, pathIndex, order int) {
		edgeItems = append(edgeItems, checkreport.EvidenceItem{
			ID:      edgeID,
			Subject: fromNode,
			Summary: summary,
			Attributes: []checkreport.KV{
				{Key: "kind", Value: "edge"},
				{Key: "relation", Value: relation},
				{Key: "from", Value: fromNode},
				{Key: "to", Value: toNode},
				{Key: "path_index", Value: strconv.Itoa(pathIndex)},
				{Key: "order", Value: strconv.Itoa(order)},
			},
		})
	}

	for i, cert := range presented {
		role := "intermediate"
		if i == 0 {
			role = "leaf"
		} else if i == len(presented)-1 {
			role = "presented_root_or_tail"
		}
		_, node := upsertNode(cert)
		node.presented = true
		node.presentedIndex = i
		appendRole(node, role)
	}
	for i := 0; i+1 < len(presented); i++ {
		fromNode := "cert:" + shortFingerprint(presented[i].Raw)
		toNode := "cert:" + shortFingerprint(presented[i+1].Raw)
		appendEdge(fmt.Sprintf("presented:%d", i), "presented chain edge", "presented_chain", fromNode, toNode, -1, i)
	}

	for pathIndex, path := range verifiedChains {
		for i, cert := range path {
			role := "verified_path"
			if i == 0 {
				role = "leaf"
			} else if i == len(path)-1 {
				role = "trust_anchor"
			}
			_, node := upsertNode(cert)
			if _, ok := node.verifiedPathBitmap[pathIndex]; !ok {
				node.verifiedPathBitmap[pathIndex] = struct{}{}
				node.verifiedPathCount++
			}
			if containsCertificate(presented, cert) {
				node.presented = true
			}
			if i == len(path)-1 {
				node.trustAnchor = true
			}
			appendRole(node, role)
		}
		for i := 0; i+1 < len(path); i++ {
			fromNode := "cert:" + shortFingerprint(path[i].Raw)
			toNode := "cert:" + shortFingerprint(path[i+1].Raw)
			appendEdge(fmt.Sprintf("verified:%d:%d", pathIndex, i), "verified trust path edge", "verified_path", fromNode, toNode, pathIndex, i)
		}
	}

	items := make([]checkreport.EvidenceItem, 0, len(nodeOrder)+len(edgeItems))
	edgeCount := len(edgeItems)
	presentedOnlyCount := 0
	presentedTailCount := 0
	verifiedOnlyCount := 0
	trustAnchorCount := 0
	for _, nodeID := range nodeOrder {
		node := nodes[nodeID]
		if node == nil || node.cert == nil {
			continue
		}
		classification := "presented_and_verified"
		switch {
		case node.presented && node.verifiedPathCount == 0:
			classification = "presented_only"
			presentedOnlyCount++
		case !node.presented && node.verifiedPathCount > 0:
			classification = "verified_only"
			verifiedOnlyCount++
		}
		presentedTail := len(verifiedChains) > 0 && node.presentedIndex > 0 && node.verifiedPathCount == 0
		if presentedTail {
			presentedTailCount++
		}
		if node.trustAnchor {
			trustAnchorCount++
		}
		role := "intermediate"
		if len(node.roles) > 0 {
			role = node.roles[0]
		}
		attrs := []checkreport.KV{
			{Key: "kind", Value: "node"},
			{Key: "node_id", Value: nodeID},
			{Key: "role", Value: role},
			{Key: "roles", Value: strings.Join(node.roles, ",")},
			{Key: "classification", Value: classification},
			{Key: "presented", Value: strconv.FormatBool(node.presented)},
			{Key: "in_verified_path", Value: strconv.FormatBool(node.verifiedPathCount > 0)},
			{Key: "verified_path_count", Value: strconv.Itoa(node.verifiedPathCount)},
			{Key: "presented_tail", Value: strconv.FormatBool(presentedTail)},
			{Key: "is_trust_anchor", Value: strconv.FormatBool(node.trustAnchor)},
			{Key: "subject", Value: node.cert.Subject.String()},
			{Key: "issuer", Value: node.cert.Issuer.String()},
			{Key: "serial", Value: node.cert.SerialNumber.String()},
			{Key: "fingerprint_sha256", Value: sha256Hex(node.cert.Raw)},
			{Key: "not_before", Value: node.cert.NotBefore.UTC().Format(time.RFC3339)},
			{Key: "not_after", Value: node.cert.NotAfter.UTC().Format(time.RFC3339)},
			{Key: "is_ca", Value: strconv.FormatBool(node.cert.IsCA)},
			{Key: "self_signed", Value: strconv.FormatBool(node.cert.Subject.String() == node.cert.Issuer.String())},
		}
		if node.presentedIndex >= 0 {
			attrs = append(attrs, checkreport.KV{Key: "presented_index", Value: strconv.Itoa(node.presentedIndex)})
		}
		items = append(items, checkreport.EvidenceItem{
			ID:         nodeID,
			Subject:    node.cert.Subject.String(),
			Summary:    "certificate node",
			Attributes: attrs,
		})
	}
	items = append(items, edgeItems...)

	return checkreport.Evidence{
		Kind:    "pki_graph",
		Summary: "structured PKI graph",
		Attributes: []checkreport.KV{
			{Key: "scope", Value: "primary_endpoint"},
			{Key: "trust_state", Value: string(trustState)},
			{Key: "node_count", Value: strconv.Itoa(len(nodeOrder))},
			{Key: "edge_count", Value: strconv.Itoa(edgeCount)},
			{Key: "presented_chain_count", Value: strconv.Itoa(len(presented))},
			{Key: "verified_path_count", Value: strconv.Itoa(len(verifiedChains))},
			{Key: "trust_anchor_count", Value: strconv.Itoa(trustAnchorCount)},
			{Key: "presented_only_count", Value: strconv.Itoa(presentedOnlyCount)},
			{Key: "presented_tail_count", Value: strconv.Itoa(presentedTailCount)},
			{Key: "has_presented_tail", Value: strconv.FormatBool(presentedTailCount > 0)},
			{Key: "verified_only_count", Value: strconv.Itoa(verifiedOnlyCount)},
		},
		Items: items,
	}
}

func containsCertificate(chain []*x509.Certificate, cert *x509.Certificate) bool {
	for _, item := range chain {
		if item == nil || cert == nil {
			continue
		}
		if bytes.Equal(item.Raw, cert.Raw) {
			return true
		}
	}
	return false
}

func shortFingerprint(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:8])
}

func describePresentedChain(chain []*x509.Certificate) string {
	if len(chain) == 0 {
		return "server did not present any certificate material"
	}
	if len(chain) == 1 {
		return "server presented 1 certificate and no additional chain elements"
	}
	return fmt.Sprintf("server presented %d certificates, including %d additional chain element(s)", len(chain), len(chain)-1)
}

func resolveServiceAddresses(ctx context.Context, cfg Config, target string, resolver dnsResolver) (serviceAddressResults, error) {
	return resolveServiceAddressesAtName(ctx, cfg, target, resolver, map[string]bool{})
}

func resolveServiceAddressesAtName(ctx context.Context, cfg Config, target string, resolver dnsResolver, visited map[string]bool) (serviceAddressResults, error) {
	var out serviceAddressResults
	var errs []string
	fqdn := dns.Fqdn(target)
	if visited[fqdn] {
		return out, fmt.Errorf("detected a CNAME resolution loop at %s", fqdn)
	}
	visited[fqdn] = true

	addressQuestions := []dnsresolver.Question{
		{QName: target, QType: dns.TypeA},
		{QName: target, QType: dns.TypeAAAA},
	}
	if batchResolver, ok := resolver.(dnsBatchResolver); ok {
		for _, item := range batchResolver.LookupBatch(ctx, addressQuestions) {
			if item.Err != nil {
				errs = append(errs, fmt.Sprintf("%s lookup failed: %v", dns.TypeToString[item.Question.QType], item.Err))
				continue
			}
			for _, rr := range item.Result.Records {
				switch v := rr.(type) {
				case *dns.A:
					out.Endpoints = append(out.Endpoints, net.JoinHostPort(v.A.String(), strconv.Itoa(cfg.Port)))
					out.Records = append(out.Records, rr)
				case *dns.AAAA:
					out.Endpoints = append(out.Endpoints, net.JoinHostPort(v.AAAA.String(), strconv.Itoa(cfg.Port)))
					out.Records = append(out.Records, rr)
				}
			}
		}
	} else {
		for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
			result, err := resolver.Lookup(ctx, target, qtype)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s lookup failed: %v", dns.TypeToString[qtype], err))
				continue
			}
			for _, rr := range result.Records {
				switch v := rr.(type) {
				case *dns.A:
					out.Endpoints = append(out.Endpoints, net.JoinHostPort(v.A.String(), strconv.Itoa(cfg.Port)))
					out.Records = append(out.Records, rr)
				case *dns.AAAA:
					out.Endpoints = append(out.Endpoints, net.JoinHostPort(v.AAAA.String(), strconv.Itoa(cfg.Port)))
					out.Records = append(out.Records, rr)
				}
			}
		}
	}

	familyCaps := cfg.TransportFamilyPolicy.EffectiveCapabilities(ipfamily.Capabilities{})
	if cfg.TransportFamilyPolicy.RequiresDetection() {
		familyCaps = cfg.TransportFamilyPolicy.EffectiveCapabilities(detectTransportFamilyCapabilities(ctx, cfg.HandshakeTimeout))
	}
	out.Endpoints = filterServiceEndpointsByFamily(out.Endpoints, familyCaps)
	out.Endpoints = uniqueRawStrings(out.Endpoints)
	if len(out.Endpoints) > 0 {
		return out, nil
	}

	cnameResult, cnameErr := resolver.Lookup(ctx, target, dns.TypeCNAME)
	if cnameErr == nil && len(cnameResult.Records) > 0 {
		for _, rr := range cnameResult.Records {
			cname, ok := rr.(*dns.CNAME)
			if !ok {
				continue
			}
			followed, err := resolveServiceAddressesAtName(ctx, cfg, cname.Target, resolver, visited)
			if err != nil {
				errs = append(errs, fmt.Sprintf("CNAME %s follow failed: %v", dns.Fqdn(cname.Target), err))
				continue
			}
			followed.Records = append(append([]dns.RR{}, cnameResult.Records...), followed.Records...)
			followed.Endpoints = uniqueRawStrings(followed.Endpoints)
			if len(followed.Endpoints) > 0 {
				return followed, nil
			}
		}
	}
	if cnameErr != nil {
		errs = append(errs, fmt.Sprintf("CNAME lookup failed: %v", cnameErr))
	}

	if len(errs) == 0 {
		return out, fmt.Errorf("authoritative DNS lookups returned no A or AAAA records for %s", target)
	}
	return out, errors.New(strings.Join(errs, "; "))
}

func filterServiceEndpointsByFamily(values []string, caps ipfamily.Capabilities) []string {
	if caps.IPv4 == caps.IPv6 {
		return append([]string(nil), values...)
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		host, _, err := net.SplitHostPort(value)
		if err != nil {
			out = append(out, value)
			continue
		}
		ip := net.ParseIP(host)
		if ip == nil || ipfamily.AllowIP(ip, caps) {
			out = append(out, value)
		}
	}
	return out
}

func evaluateDNSLayer(ctx context.Context, cfg Config, target, serviceTarget string, endpoints []handshakeResult, resolver dnsResolver, stage *checkreport.Stage, report *checkreport.Report) checkreport.Metric {
	daneMetricValue := 0.0
	daneMetric := checkreport.Metric{
		Name:   "dane_status",
		Type:   "state",
		Unit:   "status",
		Value:  "0",
		Number: &daneMetricValue,
	}

	caaResult, err := resolver.LookupEffectiveCAA(ctx, target)
	if err != nil {
		stage.Checks = append(stage.Checks, checkreport.Check{
			ID:      "dns.caa_lookup",
			State:   checkreport.CheckUnknown,
			Subject: target,
			Message: fmt.Sprintf("CAA lookup failed: %v", err),
		})
		report.Findings = append(report.Findings, makeFinding("tls_caa_lookup_failed", checkreport.StatusUnknown, target, fmt.Sprintf("CAA lookup failed: %v", err)))
	} else {
		caaAssessment := evaluateCAA(caaResult, target)
		stage.Checks = append(stage.Checks, caaAssessment.Checks...)
		if caaAssessment.Finding != nil {
			report.Findings = append(report.Findings, *caaAssessment.Finding)
		}
	}

	tlsaName := fmt.Sprintf("_%d._tcp.%s", cfg.Port, target)
	tlsaResult, err := resolver.Lookup(ctx, tlsaName, dns.TypeTLSA)
	if err != nil {
		stage.Checks = append(stage.Checks, checkreport.Check{
			ID:      "dns.dane_lookup",
			State:   checkreport.CheckUnknown,
			Subject: tlsaName,
			Message: fmt.Sprintf("TLSA lookup failed: %v", err),
		})
		report.Findings = append(report.Findings, makeFinding("tls_dane_lookup_failed", checkreport.StatusUnknown, tlsaName, fmt.Sprintf("TLSA lookup failed: %v", err)))
		return daneMetric
	}

	daneAssessment := evaluateDANE(tlsaResult, endpoints[0].State)
	daneMetricValue = daneAssessment.Metric
	daneMetric.Value = fmt.Sprintf("%.0f", daneAssessment.Metric)
	stage.Checks = append(stage.Checks, daneAssessment.Checks...)
	if daneAssessment.Finding != nil {
		report.Findings = append(report.Findings, *daneAssessment.Finding)
	}
	checks, findings := evaluateAdditionalDANEEndpoints(tlsaResult, endpoints[1:])
	stage.Checks = append(stage.Checks, checks...)
	report.Findings = append(report.Findings, findings...)
	if len(findings) > 0 {
		daneMetricValue = 0
		daneMetric.Value = "0"
	}
	return daneMetric
}

func evaluateAdditionalDANEEndpoints(result dnsresolver.LookupResult, endpoints []handshakeResult) ([]checkreport.Check, []checkreport.Finding) {
	if result.Security != dnsresolver.SecuritySecure || len(result.Records) == 0 {
		return nil, nil
	}
	var checks []checkreport.Check
	var findings []checkreport.Finding
	for _, endpoint := range endpoints {
		assessment := assessTLSARecords(result.Records, endpoint.State.PeerCertificates)
		if assessment.Matched {
			continue
		}
		message := fmt.Sprintf("secure TLSA records did not match the certificate or SPKI presented by %s", endpoint.Endpoint)
		checks = append(checks, checkreport.Check{
			ID: "dns.dane.endpoint_match", State: checkreport.CheckCritical,
			Subject: endpoint.Endpoint, Message: message, Evidence: assessment.Evidence,
		})
		findings = append(findings, makeFinding("tls_dane_mismatch", checkreport.StatusCritical, endpoint.Endpoint, message))
	}
	return checks, findings
}

func formatCAACheck(result dnsresolver.EffectiveCAAResult) checkreport.Check {
	subject := result.EffectiveName
	if subject == "" {
		subject = result.Lookup.QName
	}
	check := checkreport.Check{
		ID:      "dns.caa_lookup",
		Subject: subject,
	}

	switch result.Lookup.Security {
	case dnsresolver.SecuritySecure:
		check.State = checkreport.CheckPass
		if len(result.Lookup.Records) == 0 {
			check.Message = fmt.Sprintf("no effective CAA records were found up to %s and the denial path was DNSSEC-validated", result.EffectiveName)
		} else {
			check.Message = fmt.Sprintf("effective CAA RRset found at %s and validated with DNSSEC", result.EffectiveName)
		}
	case dnsresolver.SecurityInsecure:
		check.State = checkreport.CheckNote
		check.Message = fmt.Sprintf("effective CAA lookup resolved at %s without a secure DS-backed DNSSEC chain", result.EffectiveName)
	case dnsresolver.SecurityBogus:
		check.State = checkreport.CheckWarning
		check.Message = fmt.Sprintf("CAA response at %s failed DNSSEC validation: %s", result.EffectiveName, emptyStringAsDash(result.Lookup.ValidationMessage))
	default:
		check.State = checkreport.CheckUnknown
		check.Message = fmt.Sprintf("CAA lookup for %s was inconclusive: %s", result.EffectiveName, emptyStringAsDash(result.Lookup.ValidationMessage))
	}

	if len(result.Lookup.Records) > 0 {
		check.Evidence = []checkreport.Evidence{{
			Kind:    "dns",
			Summary: "effective CAA records",
			Attributes: []checkreport.KV{
				{Key: "effective_name", Value: result.EffectiveName},
				{Key: "records", Value: rrSummary(result.Lookup.Records)},
				{Key: "security", Value: string(result.Lookup.Security)},
			},
		}}
	}
	return check
}

func evaluateCAA(result dnsresolver.EffectiveCAAResult, target string) dnsAssessment {
	subject := result.EffectiveName
	if subject == "" {
		subject = result.Lookup.QName
	}
	checks := []checkreport.Check{
		{
			ID:           "dns.caa.effective_name",
			State:        checkreport.CheckPass,
			Subject:      subject,
			Message:      fmt.Sprintf("effective CAA evaluation resolved at %s", subject),
			MinVerbosity: 1,
		},
		{
			ID:           "dns.caa.records",
			State:        boolToCheckState(len(result.Lookup.Records) > 0, checkreport.CheckPass, checkreport.CheckNote),
			Subject:      subject,
			Message:      caaRecordMessage(result),
			MinVerbosity: 1,
		},
		{
			ID:           "dns.caa.security",
			State:        caaSecurityState(result.Lookup.Security),
			Subject:      subject,
			Message:      caaSecurityMessage(result),
			MinVerbosity: 1,
		},
		formatCAACheck(result),
	}
	if result.Lookup.Security == dnsresolver.SecurityBogus {
		finding := makeFinding("tls_caa_dnssec_invalid", checkreport.StatusWarning, target, fmt.Sprintf("CAA response failed DNSSEC validation: %s", emptyStringAsDash(result.Lookup.ValidationMessage)))
		return dnsAssessment{Checks: checks, Finding: &finding}
	}
	return dnsAssessment{Checks: checks}
}

func caaRecordMessage(result dnsresolver.EffectiveCAAResult) string {
	if len(result.Lookup.Records) == 0 {
		return fmt.Sprintf("no effective CAA records were found at or above %s", result.EffectiveName)
	}
	return fmt.Sprintf("%d effective CAA record(s) were found at %s", len(result.Lookup.Records), result.EffectiveName)
}

func caaSecurityState(security dnsresolver.SecurityState) checkreport.CheckState {
	switch security {
	case dnsresolver.SecuritySecure:
		return checkreport.CheckPass
	case dnsresolver.SecurityInsecure:
		return checkreport.CheckNote
	case dnsresolver.SecurityBogus:
		return checkreport.CheckWarning
	default:
		return checkreport.CheckUnknown
	}
}

func caaSecurityMessage(result dnsresolver.EffectiveCAAResult) string {
	switch result.Lookup.Security {
	case dnsresolver.SecuritySecure:
		return "CAA lookup was protected by a secure DNSSEC chain"
	case dnsresolver.SecurityInsecure:
		return "CAA lookup completed without a secure DS-backed DNSSEC chain"
	case dnsresolver.SecurityBogus:
		return fmt.Sprintf("CAA lookup failed DNSSEC validation: %s", emptyStringAsDash(result.Lookup.ValidationMessage))
	default:
		return fmt.Sprintf("CAA lookup security state was inconclusive: %s", emptyStringAsDash(result.Lookup.ValidationMessage))
	}
}

func daneSecurityState(security dnsresolver.SecurityState) checkreport.CheckState {
	switch security {
	case dnsresolver.SecuritySecure:
		return checkreport.CheckPass
	case dnsresolver.SecurityInsecure:
		return checkreport.CheckNote
	case dnsresolver.SecurityBogus:
		return checkreport.CheckCritical
	default:
		return checkreport.CheckUnknown
	}
}

func daneSecurityMessage(result dnsresolver.LookupResult) string {
	switch result.Security {
	case dnsresolver.SecuritySecure:
		return "TLSA lookup was protected by a secure DNSSEC chain"
	case dnsresolver.SecurityInsecure:
		return "TLSA lookup completed without a secure DS-backed DNSSEC chain"
	case dnsresolver.SecurityBogus:
		return fmt.Sprintf("TLSA lookup failed DNSSEC validation: %s", emptyStringAsDash(result.ValidationMessage))
	default:
		return fmt.Sprintf("TLSA lookup security state was inconclusive: %s", emptyStringAsDash(result.ValidationMessage))
	}
}

func daneRecordMessage(result dnsresolver.LookupResult) string {
	if len(result.Records) == 0 {
		return fmt.Sprintf("no TLSA records were published for %s", result.QName)
	}
	return fmt.Sprintf("%d TLSA record(s) were published for %s", len(result.Records), result.QName)
}

func evaluateDANE(result dnsresolver.LookupResult, state tls.ConnectionState) dnsAssessment {
	check := checkreport.Check{
		ID:      "dns.dane_lookup",
		Subject: result.QName,
	}
	checks := []checkreport.Check{
		{
			ID:           "dns.dane.security",
			State:        daneSecurityState(result.Security),
			Subject:      result.QName,
			Message:      daneSecurityMessage(result),
			MinVerbosity: 1,
		},
		{
			ID:           "dns.dane.records",
			State:        boolToCheckState(len(result.Records) > 0, checkreport.CheckPass, checkreport.CheckNote),
			Subject:      result.QName,
			Message:      daneRecordMessage(result),
			MinVerbosity: 1,
		},
	}

	switch result.Security {
	case dnsresolver.SecuritySecure:
		if len(result.Records) == 0 {
			check.State = checkreport.CheckPass
			check.Message = "no TLSA records were published and the negative answer was DNSSEC-validated"
			checks = append(checks, checkreport.Check{
				ID:           "dns.dane.match",
				State:        checkreport.CheckNote,
				Subject:      result.QName,
				Message:      "no TLSA records were present, so no certificate match was required",
				MinVerbosity: 1,
			}, check)
			return dnsAssessment{Checks: checks, Metric: 1}
		}

		assessment := assessTLSARecords(result.Records, state.PeerCertificates)
		check.Evidence = assessment.Evidence
		if assessment.Matched {
			check.State = checkreport.CheckPass
			check.Message = fmt.Sprintf("TLSA records matched the observed certificate material under a secure DNSSEC chain (%d of %d record(s) matched)", assessment.MatchedCount, assessment.RecordCount)
			checks = append(checks, checkreport.Check{
				ID:           "dns.dane.match",
				State:        checkreport.CheckPass,
				Subject:      result.QName,
				Message:      fmt.Sprintf("%d of %d TLSA record(s) matched the observed certificate material", assessment.MatchedCount, assessment.RecordCount),
				MinVerbosity: 1,
				Evidence:     assessment.Evidence,
			}, check)
			return dnsAssessment{Checks: checks, Metric: 2}
		}

		finding := makeFinding("tls_dane_mismatch", checkreport.StatusCritical, result.QName, fmt.Sprintf("secure TLSA records did not match the observed certificate or SPKI material (%d record(s) checked)", assessment.RecordCount))
		check.State = checkreport.CheckCritical
		check.Message = finding.Message
		checks = append(checks, checkreport.Check{
			ID:           "dns.dane.match",
			State:        checkreport.CheckCritical,
			Subject:      result.QName,
			Message:      fmt.Sprintf("no TLSA record matched the observed certificate material (%d record(s) checked)", assessment.RecordCount),
			MinVerbosity: 1,
			Evidence:     assessment.Evidence,
		}, check)
		return dnsAssessment{Checks: checks, Finding: &finding, Metric: 0}

	case dnsresolver.SecurityInsecure:
		if len(result.Records) == 0 {
			check.State = checkreport.CheckNote
			check.Message = "no TLSA records were published, but the lookup was not protected by a secure DS-backed DNSSEC chain"
			checks = append(checks, checkreport.Check{
				ID:           "dns.dane.match",
				State:        checkreport.CheckNote,
				Subject:      result.QName,
				Message:      "TLSA matching was not applicable because no TLSA records were published",
				MinVerbosity: 1,
			}, check)
			return dnsAssessment{Checks: checks, Metric: 1}
		}
		check.State = checkreport.CheckNote
		check.Message = "TLSA records were published, but the lookup was not protected by a secure DS-backed DNSSEC chain"
		check.Evidence = []checkreport.Evidence{{
			Kind:    "dane",
			Summary: "insecure TLSA records",
			Attributes: []checkreport.KV{
				{Key: "records", Value: rrSummary(result.Records)},
			},
		}}
		checks = append(checks, checkreport.Check{
			ID:           "dns.dane.match",
			State:        checkreport.CheckNote,
			Subject:      result.QName,
			Message:      "TLSA records were present, but matching cannot be trusted without a secure DNSSEC chain",
			MinVerbosity: 1,
		}, check)
		return dnsAssessment{Checks: checks, Metric: 0}

	case dnsresolver.SecurityBogus:
		finding := makeFinding("tls_dane_dnssec_invalid", checkreport.StatusCritical, result.QName, fmt.Sprintf("TLSA response failed DNSSEC validation: %s", emptyStringAsDash(result.ValidationMessage)))
		check.State = checkreport.CheckCritical
		check.Message = finding.Message
		checks = append(checks, checkreport.Check{
			ID:           "dns.dane.match",
			State:        checkreport.CheckUnknown,
			Subject:      result.QName,
			Message:      "TLSA matching could not be trusted because DNSSEC validation failed",
			MinVerbosity: 1,
		}, check)
		return dnsAssessment{Checks: checks, Finding: &finding, Metric: 0}

	default:
		check.State = checkreport.CheckUnknown
		check.Message = fmt.Sprintf("TLSA lookup was inconclusive: %s", emptyStringAsDash(result.ValidationMessage))
		checks = append(checks, checkreport.Check{
			ID:           "dns.dane.match",
			State:        checkreport.CheckUnknown,
			Subject:      result.QName,
			Message:      "TLSA matching was inconclusive because the lookup did not reach a usable security state",
			MinVerbosity: 1,
		}, check)
		return dnsAssessment{Checks: checks, Metric: 0}
	}
}

type tlsaAssessment struct {
	Matched      bool
	RecordCount  int
	MatchedCount int
	Evidence     []checkreport.Evidence
}

func assessTLSARecords(records []dns.RR, chain []*x509.Certificate) tlsaAssessment {
	if len(chain) == 0 {
		return tlsaAssessment{}
	}

	var assessment tlsaAssessment
	for _, rr := range records {
		tlsa, ok := rr.(*dns.TLSA)
		if !ok {
			continue
		}
		assessment.RecordCount++
		matchedThisRecord := false
		candidates := candidateCertificatesForTLSA(tlsa.Usage, chain)
		for _, cert := range candidates {
			if tlsaMatchesCertificate(tlsa, cert) {
				assessment.Matched = true
				assessment.MatchedCount++
				matchedThisRecord = true
				assessment.Evidence = append(assessment.Evidence, checkreport.Evidence{
					Kind:    "dane",
					Summary: "TLSA record matched observed certificate material",
					Attributes: []checkreport.KV{
						{Key: "usage", Value: fmt.Sprintf("%d", tlsa.Usage)},
						{Key: "usage_name", Value: tlsaUsageName(tlsa.Usage)},
						{Key: "selector", Value: fmt.Sprintf("%d", tlsa.Selector)},
						{Key: "selector_name", Value: tlsaSelectorName(tlsa.Selector)},
						{Key: "matching_type", Value: fmt.Sprintf("%d", tlsa.MatchingType)},
						{Key: "matching_type_name", Value: tlsaMatchingTypeName(tlsa.MatchingType)},
						{Key: "subject", Value: cert.Subject.String()},
					},
				})
				break
			}
		}
		if matchedThisRecord {
			continue
		}
		assessment.Evidence = append(assessment.Evidence, checkreport.Evidence{
			Kind:    "dane",
			Summary: "TLSA record did not match the observed certificate material",
			Attributes: []checkreport.KV{
				{Key: "usage", Value: fmt.Sprintf("%d", tlsa.Usage)},
				{Key: "usage_name", Value: tlsaUsageName(tlsa.Usage)},
				{Key: "selector", Value: fmt.Sprintf("%d", tlsa.Selector)},
				{Key: "selector_name", Value: tlsaSelectorName(tlsa.Selector)},
				{Key: "matching_type", Value: fmt.Sprintf("%d", tlsa.MatchingType)},
				{Key: "matching_type_name", Value: tlsaMatchingTypeName(tlsa.MatchingType)},
			},
		})
	}
	return assessment
}

func candidateCertificatesForTLSA(usage uint8, chain []*x509.Certificate) []*x509.Certificate {
	switch usage {
	case 1, 3:
		return chain[:1]
	default:
		return chain
	}
}

func tlsaMatchesCertificate(tlsa *dns.TLSA, cert *x509.Certificate) bool {
	var material []byte
	switch tlsa.Selector {
	case 0:
		material = cert.Raw
	case 1:
		material = cert.RawSubjectPublicKeyInfo
	default:
		return false
	}

	switch tlsa.MatchingType {
	case 0:
		return strings.EqualFold(strings.TrimSpace(tlsa.Certificate), strings.ToUpper(fmt.Sprintf("%X", material)))
	case 1:
		sum := sha256.Sum256(material)
		return strings.EqualFold(strings.TrimSpace(tlsa.Certificate), strings.ToUpper(fmt.Sprintf("%X", sum[:])))
	case 2:
		sum := sha512.Sum512(material)
		return strings.EqualFold(strings.TrimSpace(tlsa.Certificate), strings.ToUpper(fmt.Sprintf("%X", sum[:])))
	default:
		return false
	}
}

func tlsaUsageName(usage uint8) string {
	switch usage {
	case 0:
		return "pkix-ta"
	case 1:
		return "pkix-ee"
	case 2:
		return "dane-ta"
	case 3:
		return "dane-ee"
	default:
		return "unknown"
	}
}

func tlsaSelectorName(selector uint8) string {
	switch selector {
	case 0:
		return "cert"
	case 1:
		return "spki"
	default:
		return "unknown"
	}
}

func tlsaMatchingTypeName(matchingType uint8) string {
	switch matchingType {
	case 0:
		return "full"
	case 1:
		return "sha256"
	case 2:
		return "sha512"
	default:
		return "unknown"
	}
}

func rrSummary(records []dns.RR) string {
	if len(records) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(records))
	for _, rr := range records {
		parts = append(parts, rr.String())
	}
	return strings.Join(parts, " | ")
}

func probeDeprecatedProtocols(ctx context.Context, cfg Config, target, serviceTarget string, endpoints []string) (deprecatedProbeResult, deprecatedProbeResult) {
	return probeSpecificVersion(ctx, cfg, target, serviceTarget, endpoints, tls.VersionTLS10), probeSpecificVersion(ctx, cfg, target, serviceTarget, endpoints, tls.VersionTLS11)
}

func evaluateWeakCipherSupport(ctx context.Context, cfg Config, target, serviceTarget string, endpoints []string) weakCipherAssessment {
	probeCtx, cancel := context.WithTimeout(ctx, cfg.HandshakeTimeout)
	defer cancel()

	weakSuites := collectWeakTLS12CipherSuites()
	checks := []checkreport.Check{
		{
			ID:           "cipher.weak_support.probe_set",
			State:        boolToCheckState(len(weakSuites) > 0, checkreport.CheckPass, checkreport.CheckUnknown),
			Subject:      serviceTarget,
			Message:      fmt.Sprintf("assembled %d weak TLS 1.2 cipher suite(s) for probing", len(weakSuites)),
			MinVerbosity: 1,
		},
	}
	if len(weakSuites) == 0 {
		checks = append(checks, checkreport.Check{
			ID:           "cipher.weak_support.probe_errors",
			State:        checkreport.CheckUnknown,
			Subject:      serviceTarget,
			Message:      "weak TLS 1.2 cipher probing could not start because the probe suite list is empty",
			MinVerbosity: 1,
		}, checkreport.Check{
			ID:      "cipher.weak_support",
			State:   checkreport.CheckUnknown,
			Subject: serviceTarget,
			Message: "weak TLS 1.2 cipher audit could not assemble a probe suite list",
		})
		return weakCipherAssessment{Checks: checks}
	}

	var errs []string
	for _, endpoint := range endpoints {
		conn, _, err := dialTLSService(probeCtx, cfg, target, endpoint, &tls.Config{
			ServerName:         target,
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS12,
			CipherSuites:       weakSuites,
			InsecureSkipVerify: true,
		})
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", endpoint, err))
			continue
		}
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			_ = conn.Close()
			errs = append(errs, fmt.Sprintf("%s: unexpected TLS connection type %T", endpoint, conn))
			continue
		}
		state := tlsConn.ConnectionState()
		_ = tlsConn.Close()
		name := cipherSuiteName(state.CipherSuite)
		reasons := weakCipherReasons(name)
		msg := fmt.Sprintf("server accepted weak TLS 1.2 cipher suite %s", name)
		if len(reasons) > 0 {
			msg = fmt.Sprintf("%s (%s)", msg, strings.Join(reasons, ", "))
		}
		finding := makeFinding("tls_cipher_weak_supported", checkreport.StatusWarning, serviceTarget, msg)
		checks = append(checks, checkreport.Check{
			ID:           "cipher.weak_support.probe_errors",
			State:        boolToCheckState(len(errs) == 0, checkreport.CheckPass, checkreport.CheckNote),
			Subject:      serviceTarget,
			Message:      weakCipherProbeErrorMessage(errs),
			MinVerbosity: 1,
		}, checkreport.Check{
			ID:      "cipher.weak_support",
			State:   checkreport.CheckWarning,
			Subject: name,
			Message: msg,
		})
		return weakCipherAssessment{Checks: checks, Finding: &finding}
	}

	if len(errs) == 0 {
		checks = append(checks, checkreport.Check{
			ID:           "cipher.weak_support.probe_errors",
			State:        checkreport.CheckPass,
			Subject:      serviceTarget,
			Message:      "all weak TLS 1.2 cipher probes completed without transport errors",
			MinVerbosity: 1,
		}, checkreport.Check{
			ID:      "cipher.weak_support",
			State:   checkreport.CheckPass,
			Subject: serviceTarget,
			Message: "server did not negotiate any weak TLS 1.2 cipher suites from the current probe set",
		})
		return weakCipherAssessment{Checks: checks}
	}
	if len(errs) > 0 && allTimeoutErrors(errs) {
		checks = append(checks, checkreport.Check{
			ID:           "cipher.weak_support.probe_errors",
			State:        checkreport.CheckNote,
			Subject:      serviceTarget,
			Message:      weakCipherProbeErrorMessage(errs),
			MinVerbosity: 1,
			Evidence: []checkreport.Evidence{{
				Kind:    "tls",
				Summary: "weak TLS 1.2 cipher probe transport errors",
				Attributes: []checkreport.KV{
					{Key: "probe_errors", Value: strings.Join(errs, " | ")},
				},
			}},
		}, checkreport.Check{
			ID:      "cipher.weak_support",
			State:   checkreport.CheckNote,
			Subject: serviceTarget,
			Message: "weak TLS 1.2 cipher audit timed out and is treated as inconclusive",
		})
		return weakCipherAssessment{Checks: checks}
	}
	checks = append(checks, checkreport.Check{
		ID:           "cipher.weak_support.probe_errors",
		State:        checkreport.CheckNote,
		Subject:      serviceTarget,
		Message:      weakCipherProbeErrorMessage(errs),
		MinVerbosity: 1,
		Evidence: []checkreport.Evidence{{
			Kind:    "tls",
			Summary: "weak TLS 1.2 cipher probe transport errors",
			Attributes: []checkreport.KV{
				{Key: "probe_errors", Value: strings.Join(errs, " | ")},
			},
		}},
	}, checkreport.Check{
		ID:      "cipher.weak_support",
		State:   checkreport.CheckPass,
		Subject: serviceTarget,
		Message: "server did not negotiate any weak TLS 1.2 cipher suites from the current probe set",
		Evidence: []checkreport.Evidence{{
			Kind:    "tls",
			Summary: "weak TLS 1.2 cipher probe results",
			Attributes: []checkreport.KV{
				{Key: "probe_errors", Value: strings.Join(errs, " | ")},
			},
		}},
	})
	return weakCipherAssessment{Checks: checks}
}

func weakCipherProbeErrorMessage(errs []string) string {
	if len(errs) == 0 {
		return "no transport-level probe errors occurred during weak TLS 1.2 cipher auditing"
	}
	return fmt.Sprintf("%d weak TLS 1.2 cipher probe transport error(s) occurred", len(errs))
}

func probeSpecificVersion(ctx context.Context, cfg Config, target, serviceTarget string, endpoints []string, version uint16) deprecatedProbeResult {
	probeCtx, cancel := context.WithTimeout(ctx, cfg.HandshakeTimeout)
	defer cancel()

	started := time.Now()
	cipherSuites := collectLegacyCipherSuites()
	var errs []string
	for _, endpoint := range endpoints {
		conn, _, err := dialTLSService(probeCtx, cfg, target, endpoint, &tls.Config{
			ServerName:         target,
			MinVersion:         version,
			MaxVersion:         version,
			CipherSuites:       cipherSuites,
			InsecureSkipVerify: true,
		})
		if err == nil {
			_ = conn.Close()
			return deprecatedProbeResult{Version: version, Duration: time.Since(started), Success: true, Errors: errs}
		}
		errs = append(errs, fmt.Sprintf("%s: %v", endpoint, err))
	}
	return deprecatedProbeResult{Version: version, Duration: time.Since(started), Err: errors.New(strings.Join(errs, "; ")), Errors: errs}
}

func formatDeprecatedProbeDetailed(target string, probe deprecatedProbeResult) deprecatedProbeAssessment {
	version := tlsVersionName(probe.Version)
	id := "protocol." + strings.ToLower(strings.ReplaceAll(version, " ", "_"))
	checks := []checkreport.Check{
		{
			ID:           id + ".policy",
			State:        checkreport.CheckPass,
			Subject:      version,
			Message:      fmt.Sprintf("%s must be rejected by policy", version),
			MinVerbosity: 1,
		},
		{
			ID:           id + ".probe_errors",
			State:        legacyProbeErrorState(probe),
			Subject:      target,
			Message:      legacyProbeErrorMessage(version, probe),
			MinVerbosity: 1,
		},
	}
	if len(probe.Errors) > 0 {
		checks[len(checks)-1].Evidence = []checkreport.Evidence{{
			Kind:    "tls",
			Summary: fmt.Sprintf("%s probe transport errors", version),
			Attributes: []checkreport.KV{
				{Key: "probe_errors", Value: strings.Join(probe.Errors, " | ")},
			},
		}}
	}

	if probe.Success {
		checks = append(checks, checkreport.Check{
			ID:      id,
			State:   checkreport.CheckCritical,
			Subject: version,
			Message: fmt.Sprintf("server accepted a %s handshake", version),
		})
		return deprecatedProbeAssessment{Checks: checks}
	}
	if isTimeoutError(probe.Err) {
		checks = append(checks, checkreport.Check{
			ID:      id,
			State:   checkreport.CheckNote,
			Subject: target,
			Message: fmt.Sprintf("%s probe timed out and is treated as inconclusive rejection", version),
		})
		return deprecatedProbeAssessment{Checks: checks}
	}
	checks = append(checks, checkreport.Check{
		ID:      id,
		State:   checkreport.CheckPass,
		Subject: version,
		Message: fmt.Sprintf("server did not accept a %s handshake", version),
	})
	return deprecatedProbeAssessment{Checks: checks}
}

func legacyProbeErrorState(probe deprecatedProbeResult) checkreport.CheckState {
	if len(probe.Errors) == 0 {
		return checkreport.CheckPass
	}
	if probe.Success {
		return checkreport.CheckNote
	}
	if isTimeoutError(probe.Err) {
		return checkreport.CheckNote
	}
	return checkreport.CheckPass
}

func legacyProbeErrorMessage(version string, probe deprecatedProbeResult) string {
	if len(probe.Errors) == 0 {
		return fmt.Sprintf("no transport-level probe errors occurred during the %s audit", version)
	}
	return fmt.Sprintf("%d transport-level probe error(s) occurred during the %s audit", len(probe.Errors), version)
}

func coveragePlaceholderStage(cfg Config, target, serviceTarget string) checkreport.Stage {
	stage := checkreport.Stage{
		ID:     "coverage.remaining",
		Title:  "Remaining Coverage",
		Status: checkreport.StatusUnknown,
		Target: serviceTarget,
		Checks: []checkreport.Check{
			{
				ID:      "coverage.starttls",
				State:   checkreport.CheckNote,
				Subject: string(cfg.STARTTLS),
				Message: starttlsPlanMessage(cfg.STARTTLS),
			},
			{
				ID:      "coverage.quic",
				State:   checkreport.CheckNote,
				Subject: string(cfg.Transport),
				Message: "QUIC and HTTP/3 validation are not implemented in this phase",
			},
			{
				ID:      "coverage.dns",
				State:   checkreport.CheckNote,
				Subject: target,
				Message: "CAA and DANE are covered, but deeper DNSSEC denial variants and richer policy checks remain for later phases",
			},
			{
				ID:      "coverage.revocation",
				State:   checkreport.CheckNote,
				Subject: serviceTarget,
				Message: "fuller SCT policy interpretation and any future non-OCSP revocation expansion remain for later phases",
			},
			{
				ID:      "coverage.cipher_breadth",
				State:   checkreport.CheckNote,
				Subject: serviceTarget,
				Message: "current cipher audit focuses on negotiated suites and weak TLS 1.2 acceptance; broader preference and QUIC-specific policy checks remain for later phases",
			},
		},
	}
	return stage
}

func classifyHandshakeError(err error, target string) (checkreport.Check, checkreport.Finding) {
	if isTimeoutError(err) {
		finding := makeFinding("tls_handshake_timeout", checkreport.StatusCritical, target, fmt.Sprintf("TLS handshake timed out: %v", err))
		return checkreport.Check{
			ID:      "handshake.connect",
			State:   checkreport.CheckCritical,
			Subject: target,
			Message: finding.Message,
		}, finding
	}
	finding := makeFinding("tls_connect_failed", checkreport.StatusCritical, target, fmt.Sprintf("TLS connection failed: %v", err))
	return checkreport.Check{
		ID:      "handshake.connect",
		State:   checkreport.CheckCritical,
		Subject: target,
		Message: finding.Message,
	}, finding
}

func finalizeReport(report *checkreport.Report, cfg Config, started time.Time, serviceTarget string, handshakeMS int64, daysToExpire int, haveDaysToExpire bool, pathCount int) {
	report.Findings, report.SuppressedFindings = checkreport.PartitionSuppressedFindings(report.Findings, cfg.IgnoreErrorSet)
	report.Status = aggregateStatus(report.Findings)
	report.Metrics = append(report.Metrics,
		countMetric("findings", len(report.Findings)),
		countMetric("ignored", len(report.SuppressedFindings)),
	)
	if handshakeMS > 0 {
		report.Metrics = append(report.Metrics, durationMetric("time_tls_handshake_ms", handshakeMS))
	}
	if pathCount > 0 {
		report.Metrics = append(report.Metrics, countMetric("chain_path_count", pathCount))
	}
	if haveDaysToExpire {
		report.Metrics = append(report.Metrics, daysMetric("days_to_expire", daysToExpire))
	}
	report.Summary = aggregateSummary(*report, serviceTarget, handshakeMS, daysToExpire, haveDaysToExpire)
	report.DurationMS = time.Since(started).Milliseconds()
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

func aggregateSummary(report checkreport.Report, serviceTarget string, handshakeMS int64, daysToExpire int, haveDaysToExpire bool) string {
	if finding, ok := primaryFinding(report.Findings); ok {
		return finding.Message
	}
	if haveDaysToExpire {
		return fmt.Sprintf("certificate expires in %d days, handshake=%dms", daysToExpire, handshakeMS)
	}
	if handshakeMS > 0 {
		return fmt.Sprintf("TLS configuration looks healthy for %s, handshake=%dms", serviceTarget, handshakeMS)
	}
	return fmt.Sprintf("TLS configuration looks healthy for %s", serviceTarget)
}

func primaryFinding(findings []checkreport.Finding) (checkreport.Finding, bool) {
	var warning *checkreport.Finding
	var unknown *checkreport.Finding
	for i := range findings {
		switch findings[i].Severity {
		case checkreport.StatusCritical:
			return findings[i], true
		case checkreport.StatusUnknown:
			if unknown == nil {
				unknown = &findings[i]
			}
		case checkreport.StatusWarning:
			if warning == nil {
				warning = &findings[i]
			}
		}
	}
	if unknown != nil {
		return *unknown, true
	}
	if warning != nil {
		return *warning, true
	}
	return checkreport.Finding{}, false
}

func durationMetric(name string, ms int64) checkreport.Metric {
	value := float64(ms)
	return checkreport.Metric{Name: name, Type: "duration", Unit: "ms", Value: strconv.FormatInt(ms, 10), Number: &value}
}

func daysMetric(name string, days int) checkreport.Metric {
	value := float64(days)
	return checkreport.Metric{Name: name, Type: "duration", Unit: "days", Value: strconv.Itoa(days), Number: &value}
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

func cipherSuiteName(id uint16) string {
	if name := tls.CipherSuiteName(id); name != "" {
		return name
	}
	return fmt.Sprintf("0x%04x", id)
}

func collectLegacyCipherSuites() []uint16 {
	suites := make([]uint16, 0, len(tls.CipherSuites())+len(tls.InsecureCipherSuites()))
	for _, suite := range tls.CipherSuites() {
		suites = append(suites, suite.ID)
	}
	for _, suite := range tls.InsecureCipherSuites() {
		suites = append(suites, suite.ID)
	}
	return suites
}

func collectWeakTLS12CipherSuites() []uint16 {
	seen := make(map[uint16]bool)
	suites := make([]uint16, 0)
	for _, suite := range tls.CipherSuites() {
		if len(weakCipherReasons(suite.Name)) == 0 {
			continue
		}
		if seen[suite.ID] {
			continue
		}
		seen[suite.ID] = true
		suites = append(suites, suite.ID)
	}
	for _, suite := range tls.InsecureCipherSuites() {
		if len(weakCipherReasons(suite.Name)) == 0 {
			continue
		}
		if seen[suite.ID] {
			continue
		}
		seen[suite.ID] = true
		suites = append(suites, suite.ID)
	}
	return suites
}

func weakCipherReasons(name string) []string {
	var reasons []string
	switch {
	case strings.Contains(name, "RC4"):
		reasons = append(reasons, "RC4")
	case strings.Contains(name, "3DES"):
		reasons = append(reasons, "3DES")
	}
	if strings.Contains(name, "_CBC_") {
		reasons = append(reasons, "CBC")
	}
	if strings.HasPrefix(name, "TLS_RSA_") || strings.HasPrefix(name, "TLS_ECDH_") {
		reasons = append(reasons, "no_pfs")
	}
	return uniqueRawStrings(reasons)
}

func publicKeyWeakness(cert *x509.Certificate) (string, bool) {
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 {
			return fmt.Sprintf("RSA public key is only %d bits", key.N.BitLen()), true
		}
	case *ecdsa.PublicKey:
		if key.Params().BitSize < 256 {
			return fmt.Sprintf("ECDSA public key uses a %d-bit curve", key.Params().BitSize), true
		}
	}
	return "", false
}

func curveWeakness(cert *x509.Certificate) (string, bool) {
	key, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", false
	}
	switch key.Curve.Params().Name {
	case "P-224":
		return "certificate uses legacy P-224 curve", true
	default:
		return "", false
	}
}

func looksIncompleteChain(chain []*x509.Certificate) bool {
	if len(chain) <= 1 {
		return true
	}
	leaf := chain[0]
	for _, parent := range chain[1:] {
		if leaf.Issuer.String() == parent.Subject.String() && leaf.CheckSignatureFrom(parent) == nil {
			return false
		}
	}
	return true
}

func loadTrustRoots(cfg Config) (*x509.CertPool, string, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	source := "system roots"
	if cfg.CAFile != "" {
		pemData, readErr := os.ReadFile(cfg.CAFile)
		if readErr != nil {
			return nil, "", readErr
		}
		if !roots.AppendCertsFromPEM(pemData) {
			return nil, "", fmt.Errorf("failed to parse CA file %s", cfg.CAFile)
		}
		source = source + "+" + filepath.Base(cfg.CAFile)
	}
	if cfg.CAPath != "" {
		entries, readErr := os.ReadDir(cfg.CAPath)
		if readErr != nil {
			return nil, "", readErr
		}
		loaded := 0
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			pemData, fileErr := os.ReadFile(filepath.Join(cfg.CAPath, entry.Name()))
			if fileErr != nil {
				return nil, "", fileErr
			}
			if roots.AppendCertsFromPEM(pemData) {
				loaded++
			}
		}
		if loaded == 0 {
			return nil, "", fmt.Errorf("no CA certificates were loaded from %s", cfg.CAPath)
		}
		source = source + "+" + filepath.Base(cfg.CAPath)
	}
	return roots, source, nil
}

func statusFromCheckState(state checkreport.CheckState) checkreport.Status {
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

func deriveStageStatus(checks []checkreport.Check, current checkreport.Status) checkreport.Status {
	status := current
	if status == "" {
		status = checkreport.StatusOK
	}
	for _, check := range checks {
		switch check.State {
		case checkreport.CheckCritical:
			return checkreport.StatusCritical
		case checkreport.CheckUnknown:
			if status != checkreport.StatusCritical {
				status = checkreport.StatusUnknown
			}
		case checkreport.CheckWarning:
			if status == checkreport.StatusOK {
				status = checkreport.StatusWarning
			}
		}
	}
	return status
}

func isTimeoutError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func allTimeoutErrors(values []string) bool {
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		if !strings.Contains(strings.ToLower(value), "timeout") {
			return false
		}
	}
	return true
}

func emptyStringAsDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func uniqueRawStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func ocspStatusName(status int) string {
	switch status {
	case ocsp.Good:
		return "good"
	case ocsp.Revoked:
		return "revoked"
	case ocsp.Unknown:
		return "unknown"
	case ocsp.ServerFailed:
		return "server_failed"
	default:
		return fmt.Sprintf("status_%d", status)
	}
}

func timeOrDash(value time.Time) string {
	if value.IsZero() {
		return "-"
	}
	return value.UTC().Format(time.RFC3339)
}
