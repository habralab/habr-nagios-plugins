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
