package dnsresolver

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

var rootHintsAny = mustLoadRootHints()

func mustLoadRootHints() []nsAddr {
	raw, err := rootHintsFS.ReadFile("embeddata/root.hints")
	if err != nil {
		panic(fmt.Sprintf("read embedded root hints: %v", err))
	}

	rootNS := map[string]bool{}
	addresses := map[string][]string{}

	parser := dns.NewZoneParser(strings.NewReader(string(raw)), ".", "")
	for rr, ok := parser.Next(); ok; rr, ok = parser.Next() {
		switch v := rr.(type) {
		case *dns.NS:
			if dns.Fqdn(v.Header().Name) == "." {
				rootNS[dns.Fqdn(v.Ns)] = true
			}
		case *dns.A:
			addresses[dns.Fqdn(v.Header().Name)] = append(addresses[dns.Fqdn(v.Header().Name)], v.A.String())
		case *dns.AAAA:
			addresses[dns.Fqdn(v.Header().Name)] = append(addresses[dns.Fqdn(v.Header().Name)], v.AAAA.String())
		}
	}
	if err := parser.Err(); err != nil {
		panic(fmt.Sprintf("parse embedded root hints: %v", err))
	}

	var out []nsAddr
	for nsName := range rootNS {
		for _, ip := range addresses[nsName] {
			out = append(out, nsAddr{Name: nsName, Addr: net.JoinHostPort(ip, "53")})
		}
	}
	out = uniqueNSAddrs(out)
	if len(out) == 0 {
		panic("embedded root hints produced no addresses")
	}
	return out
}
