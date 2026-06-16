package dnsresolver

import "testing"

func TestEmbeddedRootHintsIncludeIPv4Server(t *testing.T) {
	if len(rootHintsAny) == 0 {
		t.Fatalf("rootHintsAny is empty")
	}
	found := false
	for _, server := range rootHintsAny {
		if server.Name == "A.ROOT-SERVERS.NET." && server.Addr == "198.41.0.4:53" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("rootHintsAny does not contain A.ROOT-SERVERS.NET. 198.41.0.4:53")
	}
}

func TestEmbeddedRootHintsIncludeIPv6Server(t *testing.T) {
	found := false
	for _, server := range rootHintsAny {
		if server.Name == "A.ROOT-SERVERS.NET." && server.Addr == "[2001:503:ba3e::2:30]:53" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("rootHintsAny does not contain A.ROOT-SERVERS.NET. [2001:503:ba3e::2:30]:53")
	}
}
