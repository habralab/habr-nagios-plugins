package sharedcache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

var ErrNotFound = errors.New("sharedcache: not found")

// Backend is a minimal external shared-cache transport contract.
// Callers remain responsible for cache policy and payload semantics.
type Backend interface {
	Get(context.Context, string) ([]byte, error)
	Set(context.Context, string, []byte, time.Duration) error
}

type Envelope struct {
	Module        string          `json:"module"`
	ArtifactKind  string          `json:"artifact_kind"`
	SchemaVersion string          `json:"schema_version"`
	StoredAt      time.Time       `json:"stored_at"`
	TTLSeconds    int64           `json:"ttl_seconds"`
	Payload       json.RawMessage `json:"payload"`
}

type NoopBackend struct{}

func (NoopBackend) Get(context.Context, string) ([]byte, error) {
	return nil, ErrNotFound
}

func (NoopBackend) Set(context.Context, string, []byte, time.Duration) error {
	return nil
}

func Key(module, version, artifactKind string, idParts ...string) string {
	parts := []string{
		encodePart(module),
		encodePart(version),
		encodePart(artifactKind),
	}
	for _, part := range idParts {
		parts = append(parts, encodePart(part))
	}
	return strings.Join(parts, ":")
}

func MarshalEnvelope(module, artifactKind, schemaVersion string, ttl time.Duration, payload any) ([]byte, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal envelope payload: %w", err)
	}
	return json.Marshal(Envelope{
		Module:        strings.TrimSpace(module),
		ArtifactKind:  strings.TrimSpace(artifactKind),
		SchemaVersion: strings.TrimSpace(schemaVersion),
		StoredAt:      time.Now().UTC(),
		TTLSeconds:    int64(ttl / time.Second),
		Payload:       raw,
	})
}

func UnmarshalEnvelope(data []byte, out any) (Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return Envelope{}, fmt.Errorf("unmarshal envelope: %w", err)
	}
	if out != nil {
		if err := json.Unmarshal(env.Payload, out); err != nil {
			return Envelope{}, fmt.Errorf("unmarshal envelope payload: %w", err)
		}
	}
	return env, nil
}

func encodePart(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "_"
	}
	return url.PathEscape(value)
}
