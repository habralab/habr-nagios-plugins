package dnsresolver

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/sharedcache"
	"github.com/miekg/dns"
)

type cacheEndpoint struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Port    uint16 `json:"port,omitempty"`
}

type cacheDelegationHop struct {
	FromZone      string          `json:"from_zone"`
	ToZone        string          `json:"to_zone"`
	ParentServer  cacheEndpoint   `json:"parent_server"`
	ParentServers []cacheEndpoint `json:"parent_servers"`
	ChildNS       []string        `json:"child_ns"`
	ChildServers  []cacheEndpoint `json:"child_servers"`
	TTLSeconds    int64           `json:"ttl_seconds"`
}

type authorityArtifactPayload struct {
	Zone    string               `json:"zone"`
	Servers []cacheEndpoint      `json:"servers"`
	Hops    []cacheDelegationHop `json:"hops,omitempty"`
}

type delegationArtifactPayload struct {
	Hops []cacheDelegationHop `json:"hops"`
}

type lookupArtifactPayload struct {
	QName               string   `json:"qname"`
	QType               uint16   `json:"qtype"`
	Zone                string   `json:"zone"`
	Records             []string `json:"records"`
	Signatures          []string `json:"signatures"`
	Security            string   `json:"security"`
	AuthenticatedNoData bool     `json:"authenticated_no_data"`
	ValidationMessage   string   `json:"validation_message"`
}

type resolveArtifactPayload struct {
	Lookup      lookupArtifactPayload     `json:"lookup"`
	Zone        string                    `json:"zone"`
	Nameservers []string                  `json:"nameservers"`
	Endpoints   []string                  `json:"endpoints"`
	Responses   []resolveResponsePayload  `json:"responses"`
	Consistency resolveConsistencyPayload `json:"consistency"`
}

type resolveResponsePayload struct {
	ServerName     string   `json:"server_name"`
	Endpoint       string   `json:"endpoint"`
	Network        string   `json:"network,omitempty"`
	RTTMillis      int64    `json:"rtt_ms,omitempty"`
	RCode          int      `json:"rcode,omitempty"`
	Authoritative  bool     `json:"authoritative,omitempty"`
	Error          string   `json:"error,omitempty"`
	Records        []string `json:"records,omitempty"`
	Signatures     []string `json:"signatures,omitempty"`
	Authority      []string `json:"authority,omitempty"`
	Additional     []string `json:"additional,omitempty"`
	RawAnswerCount int      `json:"raw_answer_count,omitempty"`
}

type resolveConsistencyPayload struct {
	Mode            string   `json:"mode,omitempty"`
	ComparableCount int      `json:"comparable_count,omitempty"`
	Consistent      bool     `json:"consistent,omitempty"`
	Baseline        string   `json:"baseline,omitempty"`
	Mismatches      []string `json:"mismatches,omitempty"`
}

type validationArtifactPayload struct {
	Security string   `json:"security"`
	Keys     []string `json:"keys"`
	Message  string   `json:"message"`
}

func marshalAuthorityArtifact(value authorityResult) ([]byte, error) {
	return sharedcache.MarshalEnvelope(
		sharedCacheModuleDNSResolver,
		sharedCacheArtifactAuthority,
		sharedCacheSchemaVersionV1,
		value.CacheTTL,
		authorityArtifactPayload{
			Zone:    dns.Fqdn(value.Zone),
			Servers: marshalNSAddrs(value.Servers),
			Hops:    marshalDelegationHops(value.Hops),
		},
	)
}

func unmarshalAuthorityArtifact(data []byte) (authorityResult, sharedcache.Envelope, error) {
	var payload authorityArtifactPayload
	env, err := sharedcache.UnmarshalEnvelope(data, &payload)
	if err != nil {
		return authorityResult{}, sharedcache.Envelope{}, err
	}
	return authorityResult{
		Zone:     dns.Fqdn(payload.Zone),
		Servers:  unmarshalNSAddrs(payload.Servers),
		Hops:     unmarshalDelegationHops(payload.Hops),
		CacheTTL: time.Duration(env.TTLSeconds) * time.Second,
	}, env, nil
}

func marshalZoneChainArtifact(hops []delegationHop) ([]byte, error) {
	ttl := zoneChainTTL(hops)
	return sharedcache.MarshalEnvelope(
		sharedCacheModuleDNSResolver,
		sharedCacheArtifactDelegation,
		sharedCacheSchemaVersionV1,
		ttl,
		delegationArtifactPayload{
			Hops: marshalDelegationHops(hops),
		},
	)
}

func unmarshalZoneChainArtifact(data []byte) ([]delegationHop, sharedcache.Envelope, error) {
	var payload delegationArtifactPayload
	env, err := sharedcache.UnmarshalEnvelope(data, &payload)
	if err != nil {
		return nil, sharedcache.Envelope{}, err
	}
	return unmarshalDelegationHops(payload.Hops), env, nil
}

func marshalLookupArtifact(value LookupResult) ([]byte, error) {
	return sharedcache.MarshalEnvelope(
		sharedCacheModuleDNSResolver,
		sharedCacheArtifactLookup,
		sharedCacheSchemaVersionV1,
		value.CacheTTL,
		lookupArtifactPayload{
			QName:               dns.Fqdn(value.QName),
			QType:               value.QType,
			Zone:                dns.Fqdn(value.Zone),
			Records:             marshalRRs(value.Records),
			Signatures:          marshalRRSIGs(value.Signatures),
			Security:            string(value.Security),
			AuthenticatedNoData: value.AuthenticatedNoData,
			ValidationMessage:   value.ValidationMessage,
		},
	)
}

func unmarshalLookupArtifact(data []byte) (LookupResult, sharedcache.Envelope, error) {
	var payload lookupArtifactPayload
	env, err := sharedcache.UnmarshalEnvelope(data, &payload)
	if err != nil {
		return LookupResult{}, sharedcache.Envelope{}, err
	}
	records, err := unmarshalRRs(payload.Records)
	if err != nil {
		return LookupResult{}, sharedcache.Envelope{}, fmt.Errorf("decode lookup records: %w", err)
	}
	sigs, err := unmarshalRRSIGs(payload.Signatures)
	if err != nil {
		return LookupResult{}, sharedcache.Envelope{}, fmt.Errorf("decode lookup signatures: %w", err)
	}
	return LookupResult{
		QName:               dns.Fqdn(payload.QName),
		QType:               payload.QType,
		Zone:                dns.Fqdn(payload.Zone),
		Records:             records,
		Signatures:          sigs,
		Security:            SecurityState(payload.Security),
		AuthenticatedNoData: payload.AuthenticatedNoData,
		ValidationMessage:   payload.ValidationMessage,
		CacheTTL:            time.Duration(env.TTLSeconds) * time.Second,
	}, env, nil
}

func marshalResolveArtifact(value ResolveResult) ([]byte, error) {
	ttl := resolveResultTTL(value)
	return sharedcache.MarshalEnvelope(
		sharedCacheModuleDNSResolver,
		sharedCacheArtifactResolve,
		sharedCacheSchemaVersionV1,
		ttl,
		resolveArtifactPayload{
			Lookup: lookupArtifactPayload{
				QName:               dns.Fqdn(value.Lookup.QName),
				QType:               value.Lookup.QType,
				Zone:                dns.Fqdn(value.Lookup.Zone),
				Records:             marshalRRs(value.Lookup.Records),
				Signatures:          marshalRRSIGs(value.Lookup.Signatures),
				Security:            string(value.Lookup.Security),
				AuthenticatedNoData: value.Lookup.AuthenticatedNoData,
				ValidationMessage:   value.Lookup.ValidationMessage,
			},
			Zone:        dns.Fqdn(value.Zone),
			Nameservers: append([]string(nil), value.Nameservers...),
			Endpoints:   append([]string(nil), value.Endpoints...),
			Responses:   marshalResolveResponses(value.Responses),
			Consistency: marshalResolveConsistency(value.Consistency),
		},
	)
}

func unmarshalResolveArtifact(data []byte) (ResolveResult, sharedcache.Envelope, error) {
	var payload resolveArtifactPayload
	env, err := sharedcache.UnmarshalEnvelope(data, &payload)
	if err != nil {
		return ResolveResult{}, sharedcache.Envelope{}, err
	}
	lookupRecords, err := unmarshalRRs(payload.Lookup.Records)
	if err != nil {
		return ResolveResult{}, sharedcache.Envelope{}, fmt.Errorf("decode resolve lookup records: %w", err)
	}
	lookupSigs, err := unmarshalRRSIGs(payload.Lookup.Signatures)
	if err != nil {
		return ResolveResult{}, sharedcache.Envelope{}, fmt.Errorf("decode resolve lookup signatures: %w", err)
	}
	responses, err := unmarshalResolveResponses(payload.Responses)
	if err != nil {
		return ResolveResult{}, sharedcache.Envelope{}, err
	}
	return ResolveResult{
		Lookup: LookupResult{
			QName:               dns.Fqdn(payload.Lookup.QName),
			QType:               payload.Lookup.QType,
			Zone:                dns.Fqdn(payload.Lookup.Zone),
			Records:             lookupRecords,
			Signatures:          lookupSigs,
			Security:            SecurityState(payload.Lookup.Security),
			AuthenticatedNoData: payload.Lookup.AuthenticatedNoData,
			ValidationMessage:   payload.Lookup.ValidationMessage,
			CacheTTL:            time.Duration(env.TTLSeconds) * time.Second,
		},
		Zone:        dns.Fqdn(payload.Zone),
		Nameservers: append([]string(nil), payload.Nameservers...),
		Endpoints:   append([]string(nil), payload.Endpoints...),
		Responses:   responses,
		Consistency: unmarshalResolveConsistency(payload.Consistency),
	}, env, nil
}

func marshalValidationArtifact(value validationResult) ([]byte, error) {
	return sharedcache.MarshalEnvelope(
		sharedCacheModuleDNSResolver,
		sharedCacheArtifactValidation,
		sharedCacheSchemaVersionV1,
		value.CacheTTL,
		validationArtifactPayload{
			Security: string(value.Security),
			Keys:     marshalDNSKEYs(value.Keys),
			Message:  value.Message,
		},
	)
}

func unmarshalValidationArtifact(data []byte) (validationResult, sharedcache.Envelope, error) {
	var payload validationArtifactPayload
	env, err := sharedcache.UnmarshalEnvelope(data, &payload)
	if err != nil {
		return validationResult{}, sharedcache.Envelope{}, err
	}
	keys, err := unmarshalDNSKEYs(payload.Keys)
	if err != nil {
		return validationResult{}, sharedcache.Envelope{}, fmt.Errorf("decode validation keys: %w", err)
	}
	return validationResult{
		Security: SecurityState(payload.Security),
		Keys:     keys,
		Message:  payload.Message,
		CacheTTL: time.Duration(env.TTLSeconds) * time.Second,
	}, env, nil
}

func marshalNSAddrs(values []nsAddr) []cacheEndpoint {
	if len(values) == 0 {
		return nil
	}
	out := make([]cacheEndpoint, 0, len(values))
	for _, value := range values {
		out = append(out, marshalEndpoint(value))
	}
	return out
}

func marshalResolveResponses(values []EndpointResponse) []resolveResponsePayload {
	if len(values) == 0 {
		return nil
	}
	out := make([]resolveResponsePayload, 0, len(values))
	for _, value := range values {
		out = append(out, resolveResponsePayload{
			ServerName:     dns.Fqdn(value.ServerName),
			Endpoint:       value.Endpoint,
			Network:        value.Network,
			RTTMillis:      value.RTT.Milliseconds(),
			RCode:          value.RCode,
			Authoritative:  value.Authoritative,
			Error:          value.Error,
			Records:        marshalRRs(value.Records),
			Signatures:     marshalRRSIGs(value.Signatures),
			Authority:      marshalRRs(value.Authority),
			Additional:     marshalRRs(value.Additional),
			RawAnswerCount: value.RawAnswerCount,
		})
	}
	return out
}

func unmarshalResolveResponses(values []resolveResponsePayload) ([]EndpointResponse, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make([]EndpointResponse, 0, len(values))
	for _, value := range values {
		records, err := unmarshalRRs(value.Records)
		if err != nil {
			return nil, fmt.Errorf("decode resolve response records: %w", err)
		}
		sigs, err := unmarshalRRSIGs(value.Signatures)
		if err != nil {
			return nil, fmt.Errorf("decode resolve response signatures: %w", err)
		}
		authority, err := unmarshalRRs(value.Authority)
		if err != nil {
			return nil, fmt.Errorf("decode resolve response authority: %w", err)
		}
		additional, err := unmarshalRRs(value.Additional)
		if err != nil {
			return nil, fmt.Errorf("decode resolve response additional: %w", err)
		}
		out = append(out, EndpointResponse{
			ServerName:     dns.Fqdn(value.ServerName),
			Endpoint:       value.Endpoint,
			Network:        value.Network,
			RTT:            time.Duration(value.RTTMillis) * time.Millisecond,
			RCode:          value.RCode,
			Authoritative:  value.Authoritative,
			Error:          value.Error,
			Records:        records,
			Signatures:     sigs,
			Authority:      authority,
			Additional:     additional,
			RawAnswerCount: value.RawAnswerCount,
		})
	}
	return out, nil
}

func marshalResolveConsistency(value ConsistencyAssessment) resolveConsistencyPayload {
	return resolveConsistencyPayload{
		Mode:            string(value.Mode),
		ComparableCount: value.ComparableCount,
		Consistent:      value.Consistent,
		Baseline:        value.Baseline,
		Mismatches:      append([]string(nil), value.Mismatches...),
	}
}

func unmarshalResolveConsistency(value resolveConsistencyPayload) ConsistencyAssessment {
	return ConsistencyAssessment{
		Mode:            ConsistencyMode(value.Mode),
		ComparableCount: value.ComparableCount,
		Consistent:      value.Consistent,
		Baseline:        value.Baseline,
		Mismatches:      append([]string(nil), value.Mismatches...),
	}
}

func unmarshalNSAddrs(values []cacheEndpoint) []nsAddr {
	if len(values) == 0 {
		return nil
	}
	out := make([]nsAddr, 0, len(values))
	for _, value := range values {
		out = append(out, unmarshalEndpoint(value))
	}
	return out
}

func marshalDelegationHops(values []delegationHop) []cacheDelegationHop {
	if len(values) == 0 {
		return nil
	}
	out := make([]cacheDelegationHop, 0, len(values))
	for _, value := range values {
		out = append(out, cacheDelegationHop{
			FromZone:      dns.Fqdn(value.FromZone),
			ToZone:        dns.Fqdn(value.ToZone),
			ParentServer:  marshalEndpoint(value.ParentServer),
			ParentServers: marshalNSAddrs(value.ParentServers),
			ChildNS:       append([]string(nil), value.ChildNS...),
			ChildServers:  marshalNSAddrs(value.ChildServers),
			TTLSeconds:    int64(value.CacheTTL / time.Second),
		})
	}
	return out
}

func unmarshalDelegationHops(values []cacheDelegationHop) []delegationHop {
	if len(values) == 0 {
		return nil
	}
	out := make([]delegationHop, 0, len(values))
	for _, value := range values {
		out = append(out, delegationHop{
			FromZone:      dns.Fqdn(value.FromZone),
			ToZone:        dns.Fqdn(value.ToZone),
			ParentServer:  unmarshalEndpoint(value.ParentServer),
			ParentServers: unmarshalNSAddrs(value.ParentServers),
			ChildNS:       append([]string(nil), value.ChildNS...),
			ChildServers:  unmarshalNSAddrs(value.ChildServers),
			CacheTTL:      time.Duration(value.TTLSeconds) * time.Second,
		})
	}
	return out
}

func marshalEndpoint(value nsAddr) cacheEndpoint {
	host, port, err := net.SplitHostPort(value.Addr)
	if err != nil {
		return cacheEndpoint{Name: dns.Fqdn(value.Name), Address: value.Addr}
	}
	out := cacheEndpoint{Name: dns.Fqdn(value.Name), Address: host}
	if parsed, err := strconv.ParseUint(port, 10, 16); err == nil && parsed != 53 {
		out.Port = uint16(parsed)
	}
	return out
}

func unmarshalEndpoint(value cacheEndpoint) nsAddr {
	port := value.Port
	if port == 0 {
		port = 53
	}
	return nsAddr{
		Name: dns.Fqdn(value.Name),
		Addr: net.JoinHostPort(value.Address, strconv.FormatUint(uint64(port), 10)),
	}
}

func marshalRRs(values []dns.RR) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, value.String())
	}
	return out
}

func unmarshalRRs(values []string) ([]dns.RR, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make([]dns.RR, 0, len(values))
	for _, value := range values {
		rr, err := dns.NewRR(value)
		if err != nil {
			return nil, err
		}
		out = append(out, rr)
	}
	return out, nil
}

func marshalRRSIGs(values []*dns.RRSIG) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != nil {
			out = append(out, value.String())
		}
	}
	return out
}

func unmarshalRRSIGs(values []string) ([]*dns.RRSIG, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make([]*dns.RRSIG, 0, len(values))
	for _, value := range values {
		rr, err := dns.NewRR(value)
		if err != nil {
			return nil, err
		}
		sig, ok := rr.(*dns.RRSIG)
		if !ok {
			return nil, fmt.Errorf("RR %q was not an RRSIG", value)
		}
		out = append(out, sig)
	}
	return out, nil
}

func marshalDNSKEYs(values []*dns.DNSKEY) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != nil {
			out = append(out, value.String())
		}
	}
	return out
}

func unmarshalDNSKEYs(values []string) ([]*dns.DNSKEY, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make([]*dns.DNSKEY, 0, len(values))
	for _, value := range values {
		rr, err := dns.NewRR(value)
		if err != nil {
			return nil, err
		}
		key, ok := rr.(*dns.DNSKEY)
		if !ok {
			return nil, fmt.Errorf("RR %q was not a DNSKEY", value)
		}
		out = append(out, key)
	}
	return out, nil
}
