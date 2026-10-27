package dnsprobe

import "testing"

func TestEvaluatePresenceMode(t *testing.T) {
	if _, ok, _, _ := EvaluatePresenceMode(PresenceAny, "TXT", "example.com.", 2, 1, 1, nil); !ok {
		t.Fatal("PresenceAny with one present endpoint should succeed")
	}
	if _, ok, _, _ := EvaluatePresenceMode(PresenceAll, "TXT", "example.com.", 2, 2, 0, nil); !ok {
		t.Fatal("PresenceAll with all endpoints present should succeed")
	}
	if _, ok, _, _ := EvaluatePresenceMode(PresenceNone, "TXT", "example.com.", 2, 0, 0, nil); !ok {
		t.Fatal("PresenceNone with no endpoints present should succeed")
	}
	if _, ok, _, _ := EvaluatePresenceMode(PresenceMaster, "TXT", "ns1.example.com.", 1, 0, 0, nil); ok {
		t.Fatal("PresenceMaster without present endpoints should fail")
	}
}

func TestEvaluatePresenceModeIncompleteAuthoritativeCoverage(t *testing.T) {
	tests := []struct {
		mode          PresenceMode
		authoritative int
		present       int
		failed        int
		wantCode      string
	}{
		{PresenceAny, 1, 0, 1, "dnsrr_inconclusive"},
		{PresenceMaster, 1, 0, 1, "dnsrr_inconclusive"},
		{PresenceAll, 1, 1, 1, "dnsrr_inconclusive"},
		{PresenceNone, 1, 0, 1, "dnsrr_inconclusive"},
		{PresenceAll, 1, 0, 1, "dnsrr_not_found"},
		{PresenceNone, 1, 1, 1, "dnsrr_unexpected_presence"},
	}
	for _, tt := range tests {
		_, ok, code, _ := EvaluatePresenceMode(tt.mode, "TLSA", "example.com.", tt.authoritative, tt.present, tt.failed, nil)
		if ok || code != tt.wantCode {
			t.Errorf("mode=%s authoritative=%d present=%d failed=%d: ok=%t code=%s, want %s", tt.mode, tt.authoritative, tt.present, tt.failed, ok, code, tt.wantCode)
		}
	}
}
