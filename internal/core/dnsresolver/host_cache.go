package dnsresolver

import (
	"context"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type hostAddressCacheContextKey struct{}

type hostAddressCache struct {
	mu    sync.Mutex
	calls map[string]*hostAddressCall
}

type hostAddressCall struct {
	done  chan struct{}
	addrs []string
	err   error
}

func newHostAddressCache() *hostAddressCache {
	return &hostAddressCache{
		calls: map[string]*hostAddressCall{},
	}
}

func withHostAddressCache(ctx context.Context, cache *hostAddressCache) context.Context {
	if cache == nil {
		return ctx
	}
	return context.WithValue(ctx, hostAddressCacheContextKey{}, cache)
}

func hostAddressCacheFromContext(ctx context.Context) (*hostAddressCache, bool) {
	cache, ok := ctx.Value(hostAddressCacheContextKey{}).(*hostAddressCache)
	return cache, ok
}

func (c *hostAddressCache) do(ctx context.Context, name string, fn func(context.Context) ([]string, error)) ([]string, error) {
	key := dns.Fqdn(name)

	c.mu.Lock()
	if call, ok := c.calls[key]; ok {
		c.mu.Unlock()
		select {
		case <-call.done:
			return append([]string(nil), call.addrs...), call.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	call := &hostAddressCall{done: make(chan struct{})}
	c.calls[key] = call
	c.mu.Unlock()

	callCtx, cancel := detachedResolverContext(ctx)
	defer cancel()

	call.addrs, call.err = fn(callCtx)
	close(call.done)

	return append([]string(nil), call.addrs...), call.err
}

func detachedResolverContext(ctx context.Context) (context.Context, context.CancelFunc) {
	base := context.Background()
	if timeout, ok := ctx.Value(dnsQueryTimeoutContextKey{}).(time.Duration); ok && timeout > 0 {
		base = withDNSQueryTimeout(base, timeout)
	}
	if caps, ok := resolverFamilyConstraintsFromContext(ctx); ok {
		base = withResolverFamilyConstraints(base, caps)
	}
	if cache, ok := hostAddressCacheFromContext(ctx); ok {
		base = withHostAddressCache(base, cache)
	}
	if deadline, ok := ctx.Deadline(); ok {
		return context.WithDeadline(base, deadline)
	}
	return base, func() {}
}
