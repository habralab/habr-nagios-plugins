package robots

import "testing"

func TestKnownDirectivesLoadedFromCatalog(t *testing.T) {
	specs := KnownDirectives()
	if len(specs) == 0 {
		t.Fatal("KnownDirectives() returned no entries")
	}

	spec, ok := lookupDirective("Request-rate")
	if !ok {
		t.Fatal("lookupDirective(Request-rate) did not resolve")
	}
	if spec.Provenance != ProvenanceVendorDoc {
		t.Fatalf("Request-rate provenance = %q, want %q", spec.Provenance, ProvenanceVendorDoc)
	}
	if spec.ReferenceURL == "" {
		t.Fatal("Request-rate reference URL is empty")
	}
}

func TestKnownAgentsLoadedFromCatalog(t *testing.T) {
	specs := KnownAgents()
	if len(specs) == 0 {
		t.Fatal("KnownAgents() returned no entries")
	}

	for _, token := range []string{
		"GPTBot",
		"Baiduspider",
		"DuckDuckBot",
		"YandexBot",
		"YandexAdditionalBot",
		"MojeekBot",
		"FreshBot",
	} {
		spec, ok := lookupAgent(token)
		if !ok {
			t.Fatalf("lookupAgent(%s) did not resolve", token)
		}
		if spec.Provenance != ProvenanceVendorDoc {
			t.Fatalf("%s provenance = %q, want %q", token, spec.Provenance, ProvenanceVendorDoc)
		}
		if spec.ReferenceURL == "" {
			t.Fatalf("%s reference URL is empty", token)
		}
	}
}

func TestKnownAgentBehaviorsLoadedFromCatalog(t *testing.T) {
	specs := KnownAgentBehaviors()
	if len(specs) == 0 {
		t.Fatal("KnownAgentBehaviors() returned no entries")
	}

	spec, ok := lookupAgentBehavior("Yeti")
	if !ok {
		t.Fatal("lookupAgentBehavior(Yeti) did not resolve")
	}
	if len(spec.Claims) == 0 {
		t.Fatal("lookupAgentBehavior(Yeti) returned no claims")
	}

	found := false
	for _, claim := range spec.Claims {
		if claim.Category == BehaviorHTTPStatus && claim.Subject == "5xx" && claim.Disposition == BehaviorDisallowAll {
			found = true
			if claim.ReferenceURL == "" {
				t.Fatal("Yeti 5xx behavior reference URL is empty")
			}
		}
	}
	if !found {
		t.Fatal("Yeti 5xx -> disallow-all behavior claim not found")
	}
}
