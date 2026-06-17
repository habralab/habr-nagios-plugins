package dnstest

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestStartAuthoritativeServerServesUDPAndTCP(t *testing.T) {
	server, err := StartAuthoritativeServer(func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Authoritative = true
		resp.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   []byte{192, 0, 2, 10},
			},
		}
		return resp
	})
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("local DNS listener is not permitted in this environment: %v", err)
		}
		t.Fatalf("StartAuthoritativeServer() error = %v", err)
	}
	defer func() { _ = server.Close() }()

	for _, network := range []string{"udp", "tcp"} {
		client := &dns.Client{Net: network}
		req := new(dns.Msg)
		req.SetQuestion("example.com.", dns.TypeA)
		msg, _, err := client.Exchange(req, map[string]string{
			"udp": server.UDPAddress(),
			"tcp": server.TCPAddress(),
		}[network])
		if err != nil {
			t.Fatalf("%s Exchange() error = %v", network, err)
		}
		if !msg.Authoritative {
			t.Fatalf("%s response authoritative = false, want true", network)
		}
		if len(msg.Answer) != 1 {
			t.Fatalf("%s len(answer) = %d, want 1", network, len(msg.Answer))
		}
	}
}
