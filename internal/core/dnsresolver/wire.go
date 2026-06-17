package dnsresolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
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

type dnsExchangeFunc func(context.Context, string, string, uint16, bool) (*exchangeResult, error)

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
	return queryAnyWithExchanger(ctx, servers, qname, qtype, do, resolveExchangeFn)
}

func queryAnyWithExchanger(ctx context.Context, servers []nsAddr, qname string, qtype uint16, do bool, exchanger dnsExchangeFunc) (*exchangeResult, error) {
	if caps, ok := resolverFamilyConstraintsFromContext(ctx); ok {
		servers = filterNSAddrsByCapabilities(servers, caps)
	}
	servers = orderNSAddrsByHealth(ctx, servers)
	if len(servers) == 0 {
		return nil, errors.New("no authoritative servers available")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type outcome struct {
		result *exchangeResult
		server nsAddr
		err    error
	}
	results := make(chan outcome, len(servers))
	for _, server := range servers {
		server := server
		go func() {
			res, err := exchanger(ctx, server.Addr, qname, qtype, do)
			results <- outcome{result: res, server: server, err: err}
		}()
	}

	var errs []string
	for range servers {
		outcome := <-results
		if outcome.err != nil {
			if tracker, ok := endpointHealthTrackerFromContext(ctx); ok {
				tracker.recordFailure(outcome.server.Addr, outcome.err)
			}
			errs = append(errs, fmt.Sprintf("%s: %v", outcome.server.Addr, outcome.err))
			continue
		}
		outcome.result.Server = outcome.server
		if tracker, ok := endpointHealthTrackerFromContext(ctx); ok {
			tracker.recordSuccess(outcome.server.Addr, outcome.result.RTT)
		}
		cancel()
		return outcome.result, nil
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
			childServers, err := completeReferralServers(ctx, ref.Zone, ref.NS, extractGlue(res.Msg, ref.NS))
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
	return buildZoneChainWithResolver(ctx, zone, queryAny, resolveNameServersBestEffort)
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
		childServers, err := completeReferralServersWithResolver(ctx, ref.Zone, ref.NS, extractGlue(res.Msg, ref.NS), resolver, defaultExecutionPolicy())
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

func completeReferralServers(ctx context.Context, zone string, nsNames []string, glue []nsAddr) ([]nsAddr, error) {
	return completeReferralServersWithResolver(ctx, zone, nsNames, glue, resolveNameServersBestEffort, defaultExecutionPolicy())
}

func completeReferralServersWithResolver(ctx context.Context, zone string, nsNames []string, glue []nsAddr, resolver func(context.Context, []string) ([]nsAddr, error), policy executionPolicy) ([]nsAddr, error) {
	if len(nsNames) == 0 {
		return nil, errors.New("referral did not contain any NS names")
	}

	out := acceptedGlueAddrs(zone, nsNames, glue, policy.GlueMode)
	missing := missingNSNames(nsNames, glue)
	if len(missing) == 0 {
		return uniqueNSAddrs(out), nil
	}

	resolvable, cyclical := bootstrapResolvableNSNames(zone, missing)
	if len(resolvable) == 0 {
		if len(out) > 0 {
			return uniqueNSAddrs(out), nil
		}
		if len(cyclical) > 0 {
			return nil, fmt.Errorf("missing glue for in-bailiwick name servers in %s: %s", dns.Fqdn(zone), strings.Join(cyclical, ", "))
		}
		return nil, errors.New("no bootstrap-resolvable referral name server names remained")
	}

	resolved, err := resolver(ctx, resolvable)
	if err != nil {
		return nil, err
	}
	out = append(out, resolved...)
	return uniqueNSAddrs(out), nil
}

func acceptedGlueAddrs(zone string, nsNames []string, glue []nsAddr, mode glueAcceptanceMode) []nsAddr {
	if len(glue) == 0 {
		return nil
	}
	want := map[string]bool{}
	for _, name := range nsNames {
		want[dns.Fqdn(name)] = true
	}
	zone = dns.Fqdn(zone)
	var out []nsAddr
	for _, addr := range glue {
		name := dns.Fqdn(addr.Name)
		if !want[name] {
			continue
		}
		switch mode {
		case glueAcceptancePermissive:
			out = append(out, addr)
		case glueAcceptanceStrict, glueAcceptanceNormal:
			if zone == "." || dns.IsSubDomain(zone, name) {
				out = append(out, addr)
			}
		default:
			out = append(out, addr)
		}
	}
	return uniqueNSAddrs(out)
}

func bootstrapResolvableNSNames(zone string, names []string) ([]string, []string) {
	zone = dns.Fqdn(zone)
	var resolvable []string
	var cyclical []string
	for _, name := range uniqueStrings(names) {
		name = dns.Fqdn(name)
		if zone != "." && dns.IsSubDomain(zone, name) {
			cyclical = append(cyclical, name)
			continue
		}
		resolvable = append(resolvable, name)
	}
	return resolvable, cyclical
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

func resolveNameServersBestEffort(ctx context.Context, names []string) ([]nsAddr, error) {
	return resolveNameServersBestEffortWithResolver(ctx, names, 2, resolveHostAddresses)
}

func resolveNameServersBestEffortWithResolver(ctx context.Context, names []string, targetResolvedNames int, addrResolver func(context.Context, string) ([]string, error)) ([]nsAddr, error) {
	names = uniqueStrings(names)
	if len(names) == 0 {
		return nil, errors.New("no referral name server names were provided")
	}
	if targetResolvedNames <= 0 {
		targetResolvedNames = 1
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type outcome struct {
		name  string
		addrs []string
		err   error
	}
	results := make(chan outcome, len(names))
	for _, name := range names {
		name := name
		go func() {
			addrs, err := addrResolver(ctx, name)
			results <- outcome{name: dns.Fqdn(name), addrs: addrs, err: err}
		}()
	}

	var (
		out          []nsAddr
		resolvedName int
		errs         []string
	)
	for range names {
		outcome := <-results
		if outcome.err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", outcome.name, outcome.err))
			continue
		}
		if len(outcome.addrs) == 0 {
			continue
		}
		resolvedName++
		for _, addr := range outcome.addrs {
			out = append(out, nsAddr{Name: outcome.name, Addr: addr})
		}
		if resolvedName >= targetResolvedNames {
			cancel()
			break
		}
	}

	out = uniqueNSAddrs(out)
	if len(out) > 0 {
		return out, nil
	}
	if len(errs) == 0 {
		return nil, errors.New("no referral name server addresses could be resolved")
	}
	return nil, fmt.Errorf("resolve referral name servers: %s", strings.Join(errs, "; "))
}

func resolveHostAddresses(ctx context.Context, name string) ([]string, error) {
	if cache, ok := hostAddressCacheFromContext(ctx); ok {
		return cache.do(ctx, name, func(callCtx context.Context) ([]string, error) {
			return resolveHostAddressesUncached(callCtx, name)
		})
	}
	return resolveHostAddressesUncached(ctx, name)
}

func resolveHostAddressesUncached(ctx context.Context, name string) ([]string, error) {
	type familyOutcome struct {
		qtype uint16
		iter  *iterativeResult
		err   error
	}

	results := make(chan familyOutcome, 2)
	var wg sync.WaitGroup
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		qtype := qtype
		wg.Add(1)
		go func() {
			defer wg.Done()
			iter, err := resolveIterative(ctx, name, qtype)
			results <- familyOutcome{qtype: qtype, iter: iter, err: err}
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	var (
		addrs   []string
		aErr    error
		aaaaErr error
	)
	for outcome := range results {
		switch outcome.qtype {
		case dns.TypeA:
			aErr = outcome.err
			if outcome.err == nil {
				for _, rr := range outcome.iter.Response.Msg.Answer {
					if a, ok := rr.(*dns.A); ok {
						addrs = append(addrs, net.JoinHostPort(a.A.String(), "53"))
					}
				}
			}
		case dns.TypeAAAA:
			aaaaErr = outcome.err
			if outcome.err == nil {
				for _, rr := range outcome.iter.Response.Msg.Answer {
					if aaaa, ok := rr.(*dns.AAAA); ok {
						addrs = append(addrs, net.JoinHostPort(aaaa.AAAA.String(), "53"))
					}
				}
			}
		}
	}
	if len(addrs) > 0 {
		return uniqueRawStrings(addrs), nil
	}
	if aErr != nil {
		if aaaaErr != nil {
			return nil, fmt.Errorf("a lookup failed: %v; AAAA lookup failed: %v", aErr, aaaaErr)
		}
		return nil, fmt.Errorf("a lookup failed: %v", aErr)
	}
	return nil, fmt.Errorf("no addresses found for %s", name)
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
