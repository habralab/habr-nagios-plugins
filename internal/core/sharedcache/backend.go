package sharedcache

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	BackendDSNInternal = "internal://"
	BackendDSNNone     = "none://"
)

var ErrUnsupportedBackendMode = errors.New("sharedcache: unsupported backend mode")

type BackendDescriptor struct {
	RawDSN          string   `json:"raw_dsn,omitempty"`
	Kind            string   `json:"kind"`
	Transport       string   `json:"transport,omitempty"`
	External        bool     `json:"external"`
	Supported       bool     `json:"supported"`
	Description     string   `json:"description,omitempty"`
	Warnings        []string `json:"warnings,omitempty"`
	UnsupportedMode string   `json:"unsupported_mode,omitempty"`
}

func NewBackendFromDSN(raw string, timeout time.Duration) (Backend, error) {
	backend, _, err := NewBackendWithDescriptorFromDSN(raw, timeout)
	return backend, err
}

func NewBackendWithDescriptorFromDSN(raw string, timeout time.Duration) (Backend, BackendDescriptor, error) {
	dsn := strings.TrimSpace(raw)
	if dsn == "" {
		return NoopBackend{}, BackendDescriptor{
			Kind:        "internal",
			External:    false,
			Supported:   true,
			Description: "per-run internal cache only; no external shared cache backend is configured",
		}, nil
	}

	lower := strings.ToLower(dsn)
	switch {
	case lower == "internal", lower == "internal://", lower == "memory", lower == "memory://", lower == "none", lower == "none://", lower == "noop", lower == "noop://":
		return NoopBackend{}, BackendDescriptor{
			RawDSN:      dsn,
			Kind:        "internal",
			External:    false,
			Supported:   true,
			Description: "per-run internal cache only; external shared cache backend is disabled by configuration",
		}, nil
	case strings.HasPrefix(lower, "redis://"), strings.HasPrefix(lower, "redis+unix://"), strings.HasPrefix(lower, "redis+sentinel://"), strings.HasPrefix(lower, "sentinel://"):
		backend, descriptor, err := NewRedisBackendFromDSN(dsn, timeout)
		return backend, descriptor, err
	default:
		return nil, BackendDescriptor{
			RawDSN:      dsn,
			Kind:        "unknown",
			External:    true,
			Supported:   false,
			Description: "the configured shared cache backend DSN uses an unsupported scheme",
		}, fmt.Errorf("sharedcache: unsupported backend DSN %q", dsn)
	}
}
