package dnschain

import "testing"

func TestEmbeddedRootHintsLoadIPv4Servers(t *testing.T) {
	if len(rootHintsV4) == 0 {
		t.Fatalf("rootHintsV4 is empty")
	}
	found := false
	for _, server := range rootHintsV4 {
		if server.Name == "A.ROOT-SERVERS.NET." && server.Addr == "198.41.0.4:53" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("rootHintsV4 does not contain A.ROOT-SERVERS.NET. 198.41.0.4:53")
	}
}

func TestEmbeddedRootHintsLoadIPv6Servers(t *testing.T) {
	if len(rootHintsV6) == 0 {
		t.Fatalf("rootHintsV6 is empty")
	}
	found := false
	for _, server := range rootHintsV6 {
		if server.Name == "A.ROOT-SERVERS.NET." && server.Addr == "[2001:503:ba3e::2:30]:53" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("rootHintsV6 does not contain A.ROOT-SERVERS.NET. [2001:503:ba3e::2:30]:53")
	}
}
