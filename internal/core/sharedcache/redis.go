package sharedcache

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type RedisConfig struct {
	Network  string
	Address  string
	Password string
	DB       int
	Timeout  time.Duration
}

type RedisBackend struct {
	config RedisConfig
	dialFn func(context.Context, string, string) (net.Conn, error)
}

func NewRedisBackend(config RedisConfig) (*RedisBackend, error) {
	if strings.TrimSpace(config.Network) == "" {
		config.Network = "tcp"
	}
	if strings.TrimSpace(config.Address) == "" {
		return nil, errors.New("sharedcache redis: address is required")
	}
	if config.Timeout <= 0 {
		config.Timeout = 500 * time.Millisecond
	}
	switch config.Network {
	case "tcp", "unix":
	default:
		return nil, fmt.Errorf("sharedcache redis: unsupported network %q", config.Network)
	}
	return &RedisBackend{config: config}, nil
}

func NewRedisBackendFromDSN(raw string, timeout time.Duration) (*RedisBackend, BackendDescriptor, error) {
	config, descriptor, err := ParseRedisDSN(raw)
	if err != nil {
		return nil, descriptor, err
	}
	if timeout > 0 {
		config.Timeout = timeout
	}
	backend, err := NewRedisBackend(config)
	if err != nil {
		return nil, descriptor, err
	}
	return backend, descriptor, nil
}

func ParseRedisDSN(raw string) (RedisConfig, BackendDescriptor, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return RedisConfig{}, BackendDescriptor{
			RawDSN:      raw,
			Kind:        "redis",
			External:    true,
			Supported:   false,
			Description: "the Redis cache backend DSN could not be parsed",
		}, fmt.Errorf("sharedcache redis: parse DSN: %w", err)
	}
	switch u.Scheme {
	case "redis":
		if strings.Contains(u.Host, ",") || hasSentinelHint(u.Query()) {
			return RedisConfig{}, BackendDescriptor{
				RawDSN:          raw,
				Kind:            "redis",
				Transport:       "tcp",
				External:        true,
				Supported:       false,
				Description:     "Redis Sentinel discovery is not supported for shared cache backends",
				UnsupportedMode: "redis_sentinel",
				Warnings: []string{
					"use a direct Redis endpoint via redis://host:port[/db] or redis+unix:///path/to/redis.sock?db=N",
				},
			}, fmt.Errorf("%w: redis sentinel is not supported", ErrUnsupportedBackendMode)
		}
		host := u.Host
		if !strings.Contains(host, ":") {
			host = net.JoinHostPort(host, "6379")
		}
		db, err := parseRedisDB(strings.TrimPrefix(u.Path, "/"))
		if err != nil {
			return RedisConfig{}, BackendDescriptor{}, err
		}
		password, _ := u.User.Password()
		return RedisConfig{
			Network:  "tcp",
			Address:  host,
			Password: password,
			DB:       db,
		}, BackendDescriptor{
			RawDSN:      raw,
			Kind:        "redis",
			Transport:   "tcp",
			External:    true,
			Supported:   true,
			Description: "Redis shared cache backend over TCP",
		}, nil
	case "redis+unix":
		db, err := parseRedisDB(u.Query().Get("db"))
		if err != nil {
			return RedisConfig{}, BackendDescriptor{}, err
		}
		return RedisConfig{
			Network:  "unix",
			Address:  u.Path,
			Password: u.Query().Get("password"),
			DB:       db,
		}, BackendDescriptor{
			RawDSN:      raw,
			Kind:        "redis",
			Transport:   "unix",
			External:    true,
			Supported:   true,
			Description: "Redis shared cache backend over Unix socket",
		}, nil
	case "redis+sentinel", "sentinel":
		return RedisConfig{}, BackendDescriptor{
			RawDSN:          raw,
			Kind:            "redis",
			Transport:       "tcp",
			External:        true,
			Supported:       false,
			Description:     "Redis Sentinel discovery is not supported for shared cache backends",
			UnsupportedMode: "redis_sentinel",
			Warnings: []string{
				"use a direct Redis endpoint via redis://host:port[/db] or redis+unix:///path/to/redis.sock?db=N",
			},
		}, fmt.Errorf("%w: redis sentinel is not supported", ErrUnsupportedBackendMode)
	default:
		return RedisConfig{}, BackendDescriptor{
			RawDSN:      raw,
			Kind:        "redis",
			External:    true,
			Supported:   false,
			Description: "the Redis cache backend DSN uses an unsupported scheme",
		}, fmt.Errorf("sharedcache redis: unsupported scheme %q", u.Scheme)
	}
}

func hasSentinelHint(values url.Values) bool {
	for _, key := range []string{"master", "master_name", "sentinel_master", "service_name"} {
		if strings.TrimSpace(values.Get(key)) != "" {
			return true
		}
	}
	return false
}

func parseRedisDB(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	db, err := strconv.Atoi(raw)
	if err != nil || db < 0 {
		return 0, fmt.Errorf("sharedcache redis: invalid DB %q", raw)
	}
	return db, nil
}

func (b *RedisBackend) Get(ctx context.Context, key string) ([]byte, error) {
	conn, rw, err := b.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := writeRESPCommand(rw, "GET", key); err != nil {
		return nil, err
	}
	prefix, payload, err := readRESPValue(rw)
	if err != nil {
		return nil, err
	}
	switch prefix {
	case '$':
		if payload == nil {
			return nil, ErrNotFound
		}
		return payload, nil
	case '-':
		return nil, fmt.Errorf("sharedcache redis GET: %s", string(payload))
	default:
		return nil, fmt.Errorf("sharedcache redis GET: unexpected RESP prefix %q", prefix)
	}
}

func (b *RedisBackend) Inspect(ctx context.Context) BackendInspection {
	inspection := BackendInspection{
		Descriptor: BackendDescriptor{
			Kind:        "redis",
			Transport:   b.config.Network,
			External:    true,
			Supported:   true,
			Description: "Redis shared cache backend",
		},
		ServerKind: "redis",
		Endpoint:   b.config.Address,
	}

	conn, rw, err := b.connect(ctx)
	if err != nil {
		inspection.Code, inspection.Message = classifyRedisConnectionError(err, b.config.Network)
		return inspection
	}
	defer conn.Close()

	inspection.Reachable = true
	inspection.Authenticated = true

	if err := writeRESPCommand(rw, "PING"); err != nil {
		inspection.Code = "backend_write_failed"
		inspection.Message = err.Error()
		return inspection
	}
	prefix, payload, err := readRESPValue(rw)
	if err != nil {
		inspection.Code = "backend_protocol_error"
		inspection.Message = fmt.Sprintf("PING response could not be parsed: %v", err)
		return inspection
	}
	switch prefix {
	case '+':
		if string(payload) != "PONG" {
			inspection.Code = "backend_protocol_error"
			inspection.Message = fmt.Sprintf("PING returned unexpected simple response %q", string(payload))
			return inspection
		}
	case '-':
		inspection.Authenticated = false
		inspection.Code, inspection.Message = classifyRedisCommandError("PING", string(payload))
		return inspection
	default:
		inspection.Code = "backend_protocol_error"
		inspection.Message = fmt.Sprintf("PING returned unexpected RESP prefix %q", prefix)
		return inspection
	}
	inspection.ProtocolOK = true

	if err := writeRESPCommand(rw, "ROLE"); err != nil {
		inspection.Code = "backend_write_failed"
		inspection.Message = err.Error()
		return inspection
	}
	role, errPayload, err := readRedisRole(rw)
	if err != nil {
		inspection.Code = "backend_protocol_error"
		inspection.Message = fmt.Sprintf("ROLE response could not be parsed: %v", err)
		return inspection
	}
	if errPayload != "" {
		inspection.Code, inspection.Message = classifyRedisCommandError("ROLE", errPayload)
		if inspection.Code == "backend_auth_required" {
			inspection.Authenticated = false
		}
		return inspection
	}
	inspection.ServerRole = role
	switch role {
	case "master", "slave", "replica":
		inspection.Code = "backend_ok"
		inspection.Message = fmt.Sprintf("connected to Redis over %s; server role=%s", b.config.Network, role)
		return inspection
	case "sentinel":
		inspection.Descriptor.Supported = false
		inspection.Descriptor.UnsupportedMode = "redis_sentinel"
		inspection.Descriptor.Description = "Redis Sentinel was detected at runtime; direct Redis backends only are supported"
		inspection.Descriptor.Warnings = []string{
			"use a direct Redis endpoint via redis://host:port[/db] or redis+unix:///path/to/redis.sock?db=N",
		}
		inspection.Code = "backend_unsupported_mode"
		inspection.Message = "connected successfully, but ROLE reported a Redis Sentinel instance"
		return inspection
	default:
		inspection.Code = "backend_protocol_error"
		inspection.Message = fmt.Sprintf("ROLE returned unsupported Redis role %q", role)
		return inspection
	}
}

func (b *RedisBackend) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}
	conn, rw, err := b.connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := writeRESPCommand(rw, "SETEX", key, strconv.FormatInt(int64(ttl/time.Second), 10), string(value)); err != nil {
		return err
	}
	prefix, payload, err := readRESPValue(rw)
	if err != nil {
		return err
	}
	switch prefix {
	case '+':
		return nil
	case '-':
		return fmt.Errorf("sharedcache redis SETEX: %s", string(payload))
	default:
		return fmt.Errorf("sharedcache redis SETEX: unexpected RESP prefix %q", prefix)
	}
}

func (b *RedisBackend) connect(ctx context.Context) (net.Conn, *bufio.ReadWriter, error) {
	dialFn := b.dialFn
	if dialFn == nil {
		dialer := &net.Dialer{Timeout: b.config.Timeout}
		dialFn = dialer.DialContext
	}
	conn, err := dialFn(ctx, b.config.Network, b.config.Address)
	if err != nil {
		return nil, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(b.config.Timeout))
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	if err := b.bootstrap(rw); err != nil {
		conn.Close()
		return nil, nil, err
	}
	return conn, rw, nil
}

func (b *RedisBackend) bootstrap(rw *bufio.ReadWriter) error {
	if b.config.Password != "" {
		if err := writeRESPCommand(rw, "AUTH", b.config.Password); err != nil {
			return err
		}
		if err := expectSimpleOK(rw, "AUTH"); err != nil {
			return err
		}
	}
	if b.config.DB > 0 {
		if err := writeRESPCommand(rw, "SELECT", strconv.Itoa(b.config.DB)); err != nil {
			return err
		}
		if err := expectSimpleOK(rw, "SELECT"); err != nil {
			return err
		}
	}
	return nil
}

func expectSimpleOK(rw *bufio.ReadWriter, command string) error {
	prefix, payload, err := readRESPValue(rw)
	if err != nil {
		return err
	}
	switch prefix {
	case '+':
		if string(payload) != "OK" {
			return fmt.Errorf("sharedcache redis %s: unexpected response %q", command, string(payload))
		}
		return nil
	case '-':
		return fmt.Errorf("sharedcache redis %s: %s", command, string(payload))
	default:
		return fmt.Errorf("sharedcache redis %s: unexpected RESP prefix %q", command, prefix)
	}
}

func readRedisRole(rw *bufio.ReadWriter) (string, string, error) {
	value, err := readRESPNode(rw)
	if err != nil {
		return "", "", err
	}
	if value.Kind == "error" {
		return "", value.Text, nil
	}
	if value.Kind != "array" || len(value.Values) == 0 {
		return "", "", fmt.Errorf("unexpected ROLE response kind %q", value.Kind)
	}
	first := value.Values[0]
	if first.Kind != "bulk" && first.Kind != "simple" {
		return "", "", fmt.Errorf("unexpected ROLE first element kind %q", first.Kind)
	}
	return strings.ToLower(first.Text), "", nil
}

func writeRESPCommand(rw *bufio.ReadWriter, args ...string) error {
	if _, err := fmt.Fprintf(rw, "*%d\r\n", len(args)); err != nil {
		return err
	}
	for _, arg := range args {
		if _, err := fmt.Fprintf(rw, "$%d\r\n%s\r\n", len(arg), arg); err != nil {
			return err
		}
	}
	return rw.Flush()
}

func readRESPValue(rw *bufio.ReadWriter) (byte, []byte, error) {
	prefix, err := rw.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	line, err := readRESPLine(rw)
	if err != nil {
		return 0, nil, err
	}
	switch prefix {
	case '+', '-', ':':
		return prefix, line, nil
	case '$':
		if string(line) == "-1" {
			return prefix, nil, nil
		}
		size, err := strconv.Atoi(string(line))
		if err != nil || size < 0 {
			return 0, nil, fmt.Errorf("sharedcache redis: invalid bulk size %q", string(line))
		}
		payload := make([]byte, size+2)
		if _, err := io.ReadFull(rw, payload); err != nil {
			return 0, nil, err
		}
		return prefix, payload[:size], nil
	default:
		return 0, nil, fmt.Errorf("sharedcache redis: unsupported RESP prefix %q", prefix)
	}
}

type respNode struct {
	Kind   string
	Text   string
	Values []respNode
}

func readRESPNode(rw *bufio.ReadWriter) (respNode, error) {
	prefix, err := rw.ReadByte()
	if err != nil {
		return respNode{}, err
	}
	line, err := readRESPLine(rw)
	if err != nil {
		return respNode{}, err
	}
	switch prefix {
	case '+':
		return respNode{Kind: "simple", Text: string(line)}, nil
	case '-':
		return respNode{Kind: "error", Text: string(line)}, nil
	case ':':
		return respNode{Kind: "integer", Text: string(line)}, nil
	case '$':
		if string(line) == "-1" {
			return respNode{Kind: "null"}, nil
		}
		size, err := strconv.Atoi(string(line))
		if err != nil || size < 0 {
			return respNode{}, fmt.Errorf("invalid bulk size %q", string(line))
		}
		payload := make([]byte, size+2)
		if _, err := io.ReadFull(rw, payload); err != nil {
			return respNode{}, err
		}
		return respNode{Kind: "bulk", Text: string(payload[:size])}, nil
	case '*':
		count, err := strconv.Atoi(string(line))
		if err != nil || count < 0 {
			return respNode{}, fmt.Errorf("invalid array size %q", string(line))
		}
		values := make([]respNode, 0, count)
		for range count {
			value, err := readRESPNode(rw)
			if err != nil {
				return respNode{}, err
			}
			values = append(values, value)
		}
		return respNode{Kind: "array", Values: values}, nil
	default:
		return respNode{}, fmt.Errorf("unsupported RESP prefix %q", prefix)
	}
}

func readRESPLine(rw *bufio.ReadWriter) ([]byte, error) {
	line, err := rw.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return nil, errors.New("sharedcache redis: malformed RESP line")
	}
	return line[:len(line)-2], nil
}

func classifyRedisConnectionError(err error, network string) (string, string) {
	if err == nil {
		return "backend_ok", "connected successfully"
	}
	message := err.Error()
	switch {
	case isSyscallErr(err, syscall.ENOENT) && network == "unix":
		return "backend_socket_missing", "the configured Unix socket path does not exist"
	case isSyscallErr(err, syscall.EACCES) && network == "unix":
		return "backend_socket_permission_denied", "permission was denied while opening the configured Unix socket"
	case isSyscallErr(err, syscall.ECONNREFUSED):
		if network == "unix" {
			return "backend_socket_refused", "the configured Unix socket exists but refused the connection"
		}
		return "backend_connection_refused", "the TCP connection was refused by the configured backend endpoint"
	case isTimeoutErr(err):
		if network == "unix" {
			return "backend_socket_timeout", "connecting to the configured Unix socket timed out"
		}
		return "backend_connection_timeout", "connecting to the configured backend endpoint timed out"
	default:
		if network == "unix" {
			return "backend_socket_error", message
		}
		return "backend_connection_error", message
	}
}

func classifyRedisCommandError(command, payload string) (string, string) {
	upper := strings.ToUpper(strings.TrimSpace(payload))
	switch {
	case strings.HasPrefix(upper, "NOAUTH"):
		return "backend_auth_required", fmt.Sprintf("%s requires authentication before %s can run", "the configured Redis backend", command)
	case strings.HasPrefix(upper, "WRONGPASS"):
		return "backend_auth_failed", "the configured Redis password was rejected"
	case strings.HasPrefix(upper, "ERR AUTH"):
		return "backend_auth_failed", "the configured Redis credentials were rejected"
	default:
		return "backend_command_error", fmt.Sprintf("%s failed: %s", command, payload)
	}
}

func isTimeoutErr(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func isSyscallErr(err error, target syscall.Errno) bool {
	var pathErr *os.PathError
	if errors.As(err, &pathErr) && errors.Is(pathErr.Err, target) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && errors.Is(opErr.Err, target) {
		return true
	}
	return errors.Is(err, target)
}
