package dnschain

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const maxIterativeHops = 32

const defaultDNSQueryTimeout = 3 * time.Second

type dnsQueryTimeoutContextKey struct{}

type exchangeResult struct {
	Server  nsAddr
	Network string
	Msg     *dns.Msg
	RTT     time.Duration
}

type referral struct {
	Zone string
	NS   []string
}

type iterativeResult struct {
	Response exchangeResult
	Hops     []delegationHop
}

type delegationHop struct {
	FromZone      string
	ToZone        string
	ParentServer  nsAddr
	ParentServers []nsAddr
	ChildNS       []string
	ChildServers  []nsAddr
}

func exchangeDNS(ctx context.Context, server, qname string, qtype uint16, do bool) (*exchangeResult, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(qname), qtype)
	msg.RecursionDesired = false
	if do {
		msg.SetEdns0(1232, true)
	}

	timeout := dnsQueryTimeoutFromContext(ctx)
	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	udp := &dns.Client{Net: "udp", Timeout: timeout}
	resp, rtt, err := udp.ExchangeContext(queryCtx, msg, server)
	if err != nil {
		return nil, err
	}
	if resp != nil && resp.Truncated {
		tcp := &dns.Client{Net: "tcp", Timeout: timeout}
		resp, rtt, err = tcp.ExchangeContext(queryCtx, msg, server)
		if err != nil {
			return nil, err
		}
		return &exchangeResult{
			Server:  nsAddr{Name: server, Addr: server},
			Network: "tcp",
			Msg:     resp,
			RTT:     rtt,
		}, nil
	}
	return &exchangeResult{
		Server:  nsAddr{Name: server, Addr: server},
		Network: "udp",
		Msg:     resp,
		RTT:     rtt,
	}, nil
}

func withDNSQueryTimeout(ctx context.Context, timeout time.Duration) context.Context {
	if timeout <= 0 {
		timeout = defaultDNSQueryTimeout
	}
	return context.WithValue(ctx, dnsQueryTimeoutContextKey{}, timeout)
}

func dnsQueryTimeoutFromContext(ctx context.Context) time.Duration {
	timeout := defaultDNSQueryTimeout
	if v, ok := ctx.Value(dnsQueryTimeoutContextKey{}).(time.Duration); ok && v > 0 {
		timeout = v
	}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		switch {
		case remaining <= 0:
			return time.Millisecond
		case remaining < timeout:
			return remaining
		}
	}
	return timeout
}

func queryAny(ctx context.Context, servers []nsAddr, qname string, qtype uint16, do bool) (*exchangeResult, error) {
	var errs []string
	for _, server := range servers {
		res, err := exchangeDNS(ctx, server.Addr, qname, qtype, do)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", server.Addr, err))
			continue
		}
		res.Server = server
		return res, nil
	}
	if len(errs) == 0 {
		return nil, errors.New("no authoritative servers available")
	}
	return nil, fmt.Errorf("all authoritative servers failed: %s", strings.Join(errs, "; "))
}

func extractReferral(msg *dns.Msg) *referral {
	if msg == nil || msg.Authoritative {
		return nil
	}
	nsByZone := map[string][]string{}
	for _, rr := range msg.Ns {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		owner := dns.Fqdn(ns.Header().Name)
		nsByZone[owner] = append(nsByZone[owner], dns.Fqdn(ns.Ns))
	}
	if len(nsByZone) == 0 {
		return nil
	}
	var bestZone string
	for zone := range nsByZone {
		if bestZone == "" || dns.CountLabel(zone) > dns.CountLabel(bestZone) {
			bestZone = zone
		}
	}
	return &referral{Zone: bestZone, NS: uniqueStrings(nsByZone[bestZone])}
}

func extractDelegation(msg *dns.Msg, zone string) *referral {
	if msg == nil {
		return nil
	}
	target := dns.Fqdn(zone)
	var nsNames []string
	for _, rr := range msg.Answer {
		ns, ok := rr.(*dns.NS)
		if !ok || dns.Fqdn(ns.Header().Name) != target {
			continue
		}
		nsNames = append(nsNames, dns.Fqdn(ns.Ns))
	}
	if len(nsNames) == 0 {
		for _, rr := range msg.Ns {
			ns, ok := rr.(*dns.NS)
			if !ok || dns.Fqdn(ns.Header().Name) != target {
				continue
			}
			nsNames = append(nsNames, dns.Fqdn(ns.Ns))
		}
	}
	if len(nsNames) == 0 {
		return nil
	}
	return &referral{Zone: target, NS: uniqueStrings(nsNames)}
}

func extractGlue(msg *dns.Msg, nsNames []string) []nsAddr {
	want := map[string]bool{}
	for _, name := range nsNames {
		want[dns.Fqdn(name)] = true
	}
	var out []nsAddr
	for _, rr := range msg.Extra {
		switch v := rr.(type) {
		case *dns.A:
			name := dns.Fqdn(v.Header().Name)
			if want[name] {
				out = append(out, nsAddr{Name: name, Addr: net.JoinHostPort(v.A.String(), "53")})
			}
		case *dns.AAAA:
			name := dns.Fqdn(v.Header().Name)
			if want[name] {
				out = append(out, nsAddr{Name: name, Addr: net.JoinHostPort(v.AAAA.String(), "53")})
			}
		}
	}
	return uniqueNSAddrs(out)
}

func resolveIterative(ctx context.Context, qname string, qtype uint16) (*iterativeResult, error) {
	servers := append([]nsAddr(nil), rootHintsAny...)
	currentZone := "."
	var hops []delegationHop

	for range make([]struct{}, maxIterativeHops) {
		res, err := queryAny(ctx, servers, qname, qtype, true)
		if err != nil {
			return nil, err
		}
		if ref := extractReferral(res.Msg); ref != nil {
			childServers, err := completeReferralServers(ctx, ref.NS, extractGlue(res.Msg, ref.NS))
			if err != nil {
				return nil, fmt.Errorf("resolve referral name servers for %s: %w", ref.Zone, err)
			}
			hops = append(hops, delegationHop{
				FromZone:      currentZone,
				ToZone:        ref.Zone,
				ParentServer:  res.Server,
				ParentServers: append([]nsAddr(nil), servers...),
				ChildNS:       append([]string(nil), ref.NS...),
				ChildServers:  append([]nsAddr(nil), childServers...),
			})
			servers = childServers
			currentZone = ref.Zone
			continue
		}
		return &iterativeResult{
			Response: *res,
			Hops:     hops,
		}, nil
	}
	return nil, fmt.Errorf("iterative resolution exceeded %d hops for %s", maxIterativeHops, qname)
}

func zoneAncestry(zone string) []string {
	fqdn := dns.Fqdn(zone)
	if fqdn == "." {
		return nil
	}
	labels := dns.SplitDomainName(fqdn)
	ancestry := make([]string, 0, len(labels))
	for i := len(labels) - 1; i >= 0; i-- {
		ancestry = append(ancestry, dns.Fqdn(strings.Join(labels[i:], ".")))
	}
	return ancestry
}

func buildZoneChain(ctx context.Context, zone string) ([]delegationHop, error) {
	return buildZoneChainWithResolver(ctx, zone, queryAny, resolveNameServers)
}

func buildZoneChainWithResolver(
	ctx context.Context,
	zone string,
	query func(context.Context, []nsAddr, string, uint16, bool) (*exchangeResult, error),
	resolver func(context.Context, []string) ([]nsAddr, error),
) ([]delegationHop, error) {
	ancestry := zoneAncestry(zone)
	if len(ancestry) == 0 {
		return nil, nil
	}

	parentZone := "."
	parentServers := append([]nsAddr(nil), rootHintsAny...)
	hops := make([]delegationHop, 0, len(ancestry))

	for _, childZone := range ancestry {
		res, err := query(ctx, parentServers, childZone, dns.TypeNS, true)
		if err != nil {
			return nil, fmt.Errorf("query delegation for %s from %s: %w", childZone, parentZone, err)
		}
		ref := extractDelegation(res.Msg, childZone)
		if ref == nil {
			return nil, fmt.Errorf("no NS delegation material found for %s from parent %s", childZone, parentZone)
		}
		childServers, err := completeReferralServersWithResolver(ctx, ref.NS, extractGlue(res.Msg, ref.NS), resolver)
		if err != nil {
			return nil, fmt.Errorf("resolve delegation name servers for %s: %w", childZone, err)
		}
		hops = append(hops, delegationHop{
			FromZone:      parentZone,
			ToZone:        childZone,
			ParentServer:  res.Server,
			ParentServers: append([]nsAddr(nil), parentServers...),
			ChildNS:       append([]string(nil), ref.NS...),
			ChildServers:  append([]nsAddr(nil), childServers...),
		})
		parentZone = childZone
		parentServers = childServers
	}

	return hops, nil
}

func completeReferralServers(ctx context.Context, nsNames []string, glue []nsAddr) ([]nsAddr, error) {
	return completeReferralServersWithResolver(ctx, nsNames, glue, resolveNameServers)
}

func completeReferralServersWithResolver(ctx context.Context, nsNames []string, glue []nsAddr, resolver func(context.Context, []string) ([]nsAddr, error)) ([]nsAddr, error) {
	if len(nsNames) == 0 {
		return nil, errors.New("referral did not contain any NS names")
	}

	out := append([]nsAddr(nil), glue...)
	missing := missingNSNames(nsNames, glue)
	if len(missing) == 0 {
		return uniqueNSAddrs(out), nil
	}

	resolved, err := resolver(ctx, missing)
	if err != nil {
		return nil, err
	}
	out = append(out, resolved...)
	return uniqueNSAddrs(out), nil
}

func missingNSNames(nsNames []string, known []nsAddr) []string {
	seen := map[string]bool{}
	for _, addr := range known {
		seen[dns.Fqdn(addr.Name)] = true
	}
	var missing []string
	for _, name := range uniqueStrings(nsNames) {
		if !seen[dns.Fqdn(name)] {
			missing = append(missing, dns.Fqdn(name))
		}
	}
	return missing
}

func resolveNameServers(ctx context.Context, names []string) ([]nsAddr, error) {
	var out []nsAddr
	for _, name := range uniqueStrings(names) {
		addrs, err := resolveHostAddresses(ctx, name)
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			out = append(out, nsAddr{Name: dns.Fqdn(name), Addr: addr})
		}
	}
	return uniqueNSAddrs(out), nil
}

func resolveHostAddresses(ctx context.Context, name string) ([]string, error) {
	var addrs []string

	aRes, aErr := resolveIterative(ctx, name, dns.TypeA)
	if aErr == nil {
		for _, rr := range aRes.Response.Msg.Answer {
			if a, ok := rr.(*dns.A); ok {
				addrs = append(addrs, net.JoinHostPort(a.A.String(), "53"))
			}
		}
	}
	aaaaRes, aaaaErr := resolveIterative(ctx, name, dns.TypeAAAA)
	if aaaaErr == nil {
		for _, rr := range aaaaRes.Response.Msg.Answer {
			if aaaa, ok := rr.(*dns.AAAA); ok {
				addrs = append(addrs, net.JoinHostPort(aaaa.AAAA.String(), "53"))
			}
		}
	}
	if len(addrs) > 0 {
		return uniqueRawStrings(addrs), nil
	}
	if aErr != nil {
		if aaaaErr != nil {
			return nil, fmt.Errorf("A lookup failed: %v; AAAA lookup failed: %v", aErr, aaaaErr)
		}
		return nil, fmt.Errorf("A lookup failed: %v", aErr)
	}
	return nil, fmt.Errorf("no addresses found for %s", name)
}

func rrsetNames(msg *dns.Msg, owner string, rrtype uint16) []string {
	var values []string
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype != rrtype || dns.Fqdn(rr.Header().Name) != dns.Fqdn(owner) {
			continue
		}
		if ns, ok := rr.(*dns.NS); ok {
			values = append(values, dns.Fqdn(ns.Ns))
		}
	}
	return uniqueStrings(values)
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		value = dns.Fqdn(value)
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func uniqueRawStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func uniqueNSAddrs(values []nsAddr) []nsAddr {
	seen := map[string]bool{}
	var out []nsAddr
	for _, value := range values {
		key := value.Name + "|" + value.Addr
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, value)
	}
	return out
}
