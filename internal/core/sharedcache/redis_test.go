package sharedcache

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestParseRedisDSN(t *testing.T) {
	tests := []struct {
		name          string
		raw           string
		want          RedisConfig
		wantTransport string
	}{
		{
			name:          "tcp default port and db",
			raw:           "redis://127.0.0.1",
			want:          RedisConfig{Network: "tcp", Address: "127.0.0.1:6379"},
			wantTransport: "tcp",
		},
		{
			name:          "tcp password and db",
			raw:           "redis://:secret@cache.local:6380/2",
			want:          RedisConfig{Network: "tcp", Address: "cache.local:6380", Password: "secret", DB: 2},
			wantTransport: "tcp",
		},
		{
			name:          "unix socket",
			raw:           "redis+unix:///tmp/redis.sock?db=3&password=secret",
			want:          RedisConfig{Network: "unix", Address: "/tmp/redis.sock", Password: "secret", DB: 3},
			wantTransport: "unix",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, descriptor, err := ParseRedisDSN(tt.raw)
			if err != nil {
				t.Fatalf("ParseRedisDSN() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("ParseRedisDSN() = %#v, want %#v", got, tt.want)
			}
			if descriptor.Transport != tt.wantTransport {
				t.Fatalf("descriptor.Transport = %q, want %q", descriptor.Transport, tt.wantTransport)
			}
		})
	}
}

func TestParseRedisDSNRejectsSentinel(t *testing.T) {
	tests := []string{
		"redis+sentinel://127.0.0.1:26379/mymaster",
		"sentinel://127.0.0.1:26379?master=mymaster",
		"redis://127.0.0.1:26379,127.0.0.2:26379/0?master=mymaster",
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			_, descriptor, err := ParseRedisDSN(raw)
			if err == nil {
				t.Fatal("ParseRedisDSN() error = nil, want sentinel unsupported error")
			}
			if !errors.Is(err, ErrUnsupportedBackendMode) {
				t.Fatalf("error = %v, want ErrUnsupportedBackendMode", err)
			}
			if descriptor.UnsupportedMode != "redis_sentinel" {
				t.Fatalf("descriptor.UnsupportedMode = %q, want redis_sentinel", descriptor.UnsupportedMode)
			}
			if descriptor.Supported {
				t.Fatalf("descriptor.Supported = true, want false")
			}
		})
	}
}

func TestNewRedisBackendDefaultsTimeout(t *testing.T) {
	backend, err := NewRedisBackend(RedisConfig{Network: "tcp", Address: "127.0.0.1:6379"})
	if err != nil {
		t.Fatalf("NewRedisBackend() error = %v", err)
	}
	if got, want := backend.config.Timeout, 500*time.Millisecond; got != want {
		t.Fatalf("timeout = %v, want %v", got, want)
	}
}

func TestWriteRESPCommand(t *testing.T) {
	var buf bytes.Buffer
	rw := bufio.NewReadWriter(bufio.NewReader(strings.NewReader("")), bufio.NewWriter(&buf))
	if err := writeRESPCommand(rw, "SETEX", "key", "60", "value"); err != nil {
		t.Fatalf("writeRESPCommand() error = %v", err)
	}
	want := "*4\r\n$5\r\nSETEX\r\n$3\r\nkey\r\n$2\r\n60\r\n$5\r\nvalue\r\n"
	if got := buf.String(); got != want {
		t.Fatalf("RESP command = %q, want %q", got, want)
	}
}

func TestReadRESPValueBulkAndNil(t *testing.T) {
	rw := bufio.NewReadWriter(bufio.NewReader(strings.NewReader("$5\r\nvalue\r\n$-1\r\n")), bufio.NewWriter(&bytes.Buffer{}))

	prefix, payload, err := readRESPValue(rw)
	if err != nil {
		t.Fatalf("first readRESPValue() error = %v", err)
	}
	if prefix != '$' || string(payload) != "value" {
		t.Fatalf("first readRESPValue() = (%q,%q), want ($,value)", prefix, payload)
	}

	prefix, payload, err = readRESPValue(rw)
	if err != nil {
		t.Fatalf("second readRESPValue() error = %v", err)
	}
	if prefix != '$' || payload != nil {
		t.Fatalf("second readRESPValue() = (%q,%v), want ($,nil)", prefix, payload)
	}
}

func TestRedisBackendInspectDetectsRedisMaster(t *testing.T) {
	backend := mockRedisBackend(t, func(conn net.Conn) {
		expectReadThenWrite(conn, "+PONG\r\n")
		expectReadThenWrite(conn, "*3\r\n$6\r\nmaster\r\n:0\r\n*0\r\n")
	})
	inspection := backend.Inspect(t.Context())
	if inspection.Code != "backend_ok" || inspection.ServerRole != "master" {
		t.Fatalf("inspection = %#v, want backend_ok/master", inspection)
	}
}

func TestRedisBackendInspectDetectsSentinelAtRuntime(t *testing.T) {
	backend := mockRedisBackend(t, func(conn net.Conn) {
		expectReadThenWrite(conn, "+PONG\r\n")
		expectReadThenWrite(conn, "*2\r\n$8\r\nsentinel\r\n*1\r\n$8\r\nmymaster\r\n")
	})
	inspection := backend.Inspect(t.Context())
	if inspection.Code != "backend_unsupported_mode" || inspection.ServerRole != "sentinel" {
		t.Fatalf("inspection = %#v, want unsupported sentinel detection", inspection)
	}
}

func TestRedisBackendInspectDetectsAuthRequired(t *testing.T) {
	backend := mockRedisBackend(t, func(conn net.Conn) {
		expectReadThenWrite(conn, "-NOAUTH Authentication required.\r\n")
	})
	inspection := backend.Inspect(t.Context())
	if inspection.Code != "backend_auth_required" || inspection.Authenticated {
		t.Fatalf("inspection = %#v, want auth_required and unauthenticated", inspection)
	}
}

func TestRedisBackendInspectDetectsProtocolGarbage(t *testing.T) {
	backend := mockRedisBackend(t, func(conn net.Conn) {
		expectReadThenWrite(conn, "THIS IS NOT RESP\r\n")
	})
	inspection := backend.Inspect(t.Context())
	if inspection.Code != "backend_protocol_error" {
		t.Fatalf("inspection = %#v, want protocol error", inspection)
	}
}

func TestRedisBackendInspectDetectsUnixSocketMissing(t *testing.T) {
	backend := &RedisBackend{
		config: RedisConfig{Network: "unix", Address: "/tmp/missing.sock", Timeout: 200 * time.Millisecond},
		dialFn: func(context.Context, string, string) (net.Conn, error) {
			return nil, &net.OpError{Op: "dial", Net: "unix", Err: &os.PathError{Op: "connect", Path: "/tmp/missing.sock", Err: syscall.ENOENT}}
		},
	}
	inspection := backend.Inspect(t.Context())
	if inspection.Code != "backend_socket_missing" {
		t.Fatalf("inspection = %#v, want socket missing", inspection)
	}
}

func TestRedisBackendInspectDetectsTCPConnectionRefused(t *testing.T) {
	backend := &RedisBackend{
		config: RedisConfig{Network: "tcp", Address: "127.0.0.1:6379", Timeout: 200 * time.Millisecond},
		dialFn: func(context.Context, string, string) (net.Conn, error) {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
		},
	}
	inspection := backend.Inspect(t.Context())
	if inspection.Code != "backend_connection_refused" {
		t.Fatalf("inspection = %#v, want connection refused", inspection)
	}
}

func mockRedisBackend(t *testing.T, handler func(net.Conn)) *RedisBackend {
	t.Helper()
	return &RedisBackend{
		config: RedisConfig{Network: "tcp", Address: "127.0.0.1:6379", Timeout: time.Second},
		dialFn: func(context.Context, string, string) (net.Conn, error) {
			client, server := net.Pipe()
			go func() {
				defer server.Close()
				handler(server)
			}()
			return client, nil
		},
	}
}

func expectReadThenWrite(conn net.Conn, response string) {
	buf := make([]byte, 4096)
	if _, err := conn.Read(buf); err != nil {
		return
	}
	_, _ = conn.Write([]byte(response))
}
