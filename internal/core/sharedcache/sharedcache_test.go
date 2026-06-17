package sharedcache

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNoopBackendMissesReadsAndIgnoresWrites(t *testing.T) {
	var backend NoopBackend

	_, err := backend.Get(context.Background(), "dnsresolver:v1:authority:example.com")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() error = %v, want ErrNotFound", err)
	}
	if err := backend.Set(context.Background(), "dnsresolver:v1:authority:example.com", []byte("x"), time.Minute); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
}

func TestKeyBuildsNamespacedEscapedKey(t *testing.T) {
	got := Key("dnsresolver", "v1", "lookup", "_443._tcp.www.example.com.", "TLSA")
	want := "dnsresolver:v1:lookup:_443._tcp.www.example.com.:TLSA"
	if got != want {
		t.Fatalf("Key() = %q, want %q", got, want)
	}
}

func TestMarshalAndUnmarshalEnvelope(t *testing.T) {
	type payload struct {
		Zone string `json:"zone"`
	}

	data, err := MarshalEnvelope("dnsresolver", "authority", "v1", 45*time.Second, payload{Zone: "example.com."})
	if err != nil {
		t.Fatalf("MarshalEnvelope() error = %v", err)
	}

	var got payload
	env, err := UnmarshalEnvelope(data, &got)
	if err != nil {
		t.Fatalf("UnmarshalEnvelope() error = %v", err)
	}
	if got.Zone != "example.com." {
		t.Fatalf("payload.Zone = %q, want example.com.", got.Zone)
	}
	if env.Module != "dnsresolver" || env.ArtifactKind != "authority" || env.SchemaVersion != "v1" {
		t.Fatalf("envelope = %#v, want dnsresolver/authority/v1", env)
	}
	if env.TTLSeconds != 45 {
		t.Fatalf("TTLSeconds = %d, want 45", env.TTLSeconds)
	}
	if env.StoredAt.IsZero() {
		t.Fatal("StoredAt is zero")
	}
}

func TestUnmarshalEnvelopeRejectsBrokenPayload(t *testing.T) {
	_, err := UnmarshalEnvelope([]byte(`{"module":"dnsresolver","artifact_kind":"authority","schema_version":"v1","stored_at":"2026-06-17T00:00:00Z","ttl_seconds":30,"payload":"oops"}`), &struct{}{})
	if err == nil || !strings.Contains(err.Error(), "unmarshal envelope payload") {
		t.Fatalf("UnmarshalEnvelope() error = %v, want payload decode error", err)
	}
}
