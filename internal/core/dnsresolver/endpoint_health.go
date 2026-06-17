package dnsresolver

import (
	"context"
	"errors"
	"net"
	"sort"
	"sync"
	"time"
)

type endpointHealthContextKey struct{}

type endpointHealthTracker struct {
	mu    sync.Mutex
	stats map[string]endpointHealth
}

type endpointHealth struct {
	Successes int
	Failures  int
	Timeouts  int
	EWMARTT   time.Duration
	HasRTT    bool
}

func newEndpointHealthTracker() *endpointHealthTracker {
	return &endpointHealthTracker{stats: map[string]endpointHealth{}}
}

func withEndpointHealthTracker(ctx context.Context, tracker *endpointHealthTracker) context.Context {
	if tracker == nil {
		return ctx
	}
	return context.WithValue(ctx, endpointHealthContextKey{}, tracker)
}

func endpointHealthTrackerFromContext(ctx context.Context) (*endpointHealthTracker, bool) {
	tracker, ok := ctx.Value(endpointHealthContextKey{}).(*endpointHealthTracker)
	return tracker, ok
}

func (t *endpointHealthTracker) recordSuccess(endpoint string, rtt time.Duration) {
	if t == nil || endpoint == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	stat := t.stats[endpoint]
	stat.Successes++
	if rtt > 0 {
		if !stat.HasRTT || stat.EWMARTT <= 0 {
			stat.EWMARTT = rtt
		} else {
			stat.EWMARTT = (stat.EWMARTT*3 + rtt) / 4
		}
		stat.HasRTT = true
	}
	t.stats[endpoint] = stat
}

func (t *endpointHealthTracker) recordFailure(endpoint string, err error) {
	if t == nil || endpoint == "" || err == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	stat := t.stats[endpoint]
	if isTimeoutError(err) {
		stat.Timeouts++
	} else {
		stat.Failures++
	}
	t.stats[endpoint] = stat
}

func (t *endpointHealthTracker) snapshot(endpoint string) endpointHealth {
	if t == nil || endpoint == "" {
		return endpointHealth{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.stats[endpoint]
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func orderNSAddrsByHealth(ctx context.Context, values []nsAddr) []nsAddr {
	tracker, ok := endpointHealthTrackerFromContext(ctx)
	if !ok || len(values) < 2 {
		return append([]nsAddr(nil), values...)
	}
	return orderNSAddrsByTracker(values, tracker)
}

func orderAuthoritativeServersByHealth(ctx context.Context, values []AuthoritativeServer) []AuthoritativeServer {
	tracker, ok := endpointHealthTrackerFromContext(ctx)
	if !ok || len(values) < 2 {
		return append([]AuthoritativeServer(nil), values...)
	}
	return orderAuthoritativeServersByTracker(values, tracker)
}

func orderNSAddrsByTracker(values []nsAddr, tracker *endpointHealthTracker) []nsAddr {
	out := append([]nsAddr(nil), values...)
	sort.SliceStable(out, func(i, j int) bool {
		return compareEndpointHealth(tracker.snapshot(out[i].Addr), tracker.snapshot(out[j].Addr))
	})
	return out
}

func orderAuthoritativeServersByTracker(values []AuthoritativeServer, tracker *endpointHealthTracker) []AuthoritativeServer {
	out := append([]AuthoritativeServer(nil), values...)
	sort.SliceStable(out, func(i, j int) bool {
		return compareEndpointHealth(tracker.snapshot(out[i].Endpoint), tracker.snapshot(out[j].Endpoint))
	})
	return out
}

func compareEndpointHealth(a, b endpointHealth) bool {
	aRank := endpointHealthRank(a)
	bRank := endpointHealthRank(b)
	if aRank != bRank {
		return aRank < bRank
	}
	if a.HasRTT != b.HasRTT {
		return a.HasRTT
	}
	if a.HasRTT && b.HasRTT && a.EWMARTT != b.EWMARTT {
		return a.EWMARTT < b.EWMARTT
	}
	if a.Timeouts != b.Timeouts {
		return a.Timeouts < b.Timeouts
	}
	if a.Failures != b.Failures {
		return a.Failures < b.Failures
	}
	return false
}

func endpointHealthRank(stat endpointHealth) int {
	switch {
	case stat.Successes > 0 && stat.Timeouts == 0 && stat.Failures == 0:
		return 0
	case stat.Successes > 0:
		return 1
	case stat.Successes == 0 && stat.Timeouts == 0 && stat.Failures == 0:
		return 2
	default:
		return 3
	}
}
