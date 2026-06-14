package dnschain

import (
	"embed"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

//go:embed embeddata/root.hints
var rootHintsFS embed.FS

type nsAddr struct {
	Name string
	Addr string
}

var rootHintsV4 = mustLoadRootHintsV4()
var rootHintsV6 = mustLoadRootHintsV6()
var rootHintsAny = append(append([]nsAddr(nil), rootHintsV4...), rootHintsV6...)

func mustLoadRootHintsV4() []nsAddr {
	return mustLoadRootHintsByType(dns.TypeA)
}

func mustLoadRootHintsV6() []nsAddr {
	return mustLoadRootHintsByType(dns.TypeAAAA)
}

func mustLoadRootHintsByType(qtype uint16) []nsAddr {
	raw, err := rootHintsFS.ReadFile("embeddata/root.hints")
	if err != nil {
		panic(fmt.Sprintf("read embedded root hints: %v", err))
	}

	rootNS := map[string]bool{}
	addresses := map[string]string{}

	parser := dns.NewZoneParser(strings.NewReader(string(raw)), ".", "")
	for rr, ok := parser.Next(); ok; rr, ok = parser.Next() {
		switch v := rr.(type) {
		case *dns.NS:
			if dns.Fqdn(v.Header().Name) == "." {
				rootNS[dns.Fqdn(v.Ns)] = true
			}
		case *dns.A:
			if qtype == dns.TypeA {
				addresses[dns.Fqdn(v.Header().Name)] = v.A.String()
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA {
				addresses[dns.Fqdn(v.Header().Name)] = v.AAAA.String()
			}
		}
	}
	if err := parser.Err(); err != nil {
		panic(fmt.Sprintf("parse embedded root hints: %v", err))
	}

	var out []nsAddr
	for nsName := range rootNS {
		ip, ok := addresses[nsName]
		if !ok {
			continue
		}
		out = append(out, nsAddr{
			Name: nsName,
			Addr: net.JoinHostPort(ip, "53"),
		})
	}
	out = uniqueNSAddrs(out)
	if len(out) == 0 {
		panic(fmt.Sprintf("embedded root hints produced no addresses for qtype %d", qtype))
	}
	return out
}
