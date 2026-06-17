package sharedcache

import (
	"testing"
	"time"
)

func TestNewBackendFromDSNDefaultsToNoop(t *testing.T) {
	backend, err := NewBackendFromDSN("", time.Second)
	if err != nil {
		t.Fatalf("NewBackendFromDSN() error = %v", err)
	}
	if _, ok := backend.(NoopBackend); !ok {
		t.Fatalf("backend = %T, want NoopBackend", backend)
	}
}

func TestNewBackendFromDSNRecognizesInternalAliases(t *testing.T) {
	for _, dsn := range []string{"internal", "internal://", "memory://", "none://", "noop://"} {
		t.Run(dsn, func(t *testing.T) {
			backend, err := NewBackendFromDSN(dsn, time.Second)
			if err != nil {
				t.Fatalf("NewBackendFromDSN(%q) error = %v", dsn, err)
			}
			if _, ok := backend.(NoopBackend); !ok {
				t.Fatalf("backend = %T, want NoopBackend", backend)
			}
		})
	}
}

func TestNewBackendFromDSNBuildsRedisBackend(t *testing.T) {
	backend, descriptor, err := NewBackendWithDescriptorFromDSN("redis://127.0.0.1/2", 750*time.Millisecond)
	if err != nil {
		t.Fatalf("NewBackendWithDescriptorFromDSN() error = %v", err)
	}
	redisBackend, ok := backend.(*RedisBackend)
	if !ok {
		t.Fatalf("backend = %T, want *RedisBackend", backend)
	}
	if got, want := redisBackend.config.Timeout, 750*time.Millisecond; got != want {
		t.Fatalf("timeout = %v, want %v", got, want)
	}
	if got, want := redisBackend.config.DB, 2; got != want {
		t.Fatalf("db = %d, want %d", got, want)
	}
	if descriptor.Kind != "redis" || !descriptor.External || !descriptor.Supported {
		t.Fatalf("descriptor = %#v, want supported external redis", descriptor)
	}
}

func TestNewBackendFromDSNRejectsUnknownScheme(t *testing.T) {
	if _, err := NewBackendFromDSN("memcached://127.0.0.1:11211", time.Second); err == nil {
		t.Fatal("NewBackendFromDSN() error = nil, want unsupported backend error")
	}
}

func TestNewBackendFromDSNDescribesUnsupportedSentinel(t *testing.T) {
	_, descriptor, err := NewBackendWithDescriptorFromDSN("redis+sentinel://127.0.0.1:26379?master=mymaster", time.Second)
	if err == nil {
		t.Fatal("NewBackendWithDescriptorFromDSN() error = nil, want unsupported sentinel error")
	}
	if descriptor.UnsupportedMode != "redis_sentinel" {
		t.Fatalf("descriptor.UnsupportedMode = %q, want redis_sentinel", descriptor.UnsupportedMode)
	}
	if descriptor.Supported {
		t.Fatalf("descriptor.Supported = true, want false")
	}
}
