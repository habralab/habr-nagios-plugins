package dnsresolver

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestHostAddressCacheSingleflight(t *testing.T) {
	cache := newHostAddressCache()
	ctx := withHostAddressCache(context.Background(), cache)

	var calls atomic.Int32
	fn := func(ctx context.Context) ([]string, error) {
		calls.Add(1)
		time.Sleep(20 * time.Millisecond)
		return []string{"192.0.2.10:53"}, nil
	}

	var wg sync.WaitGroup
	results := make(chan []string, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addrs, err := cache.do(ctx, "ns1.example.net.", fn)
			if err != nil {
				t.Errorf("cache.do() error = %v", err)
				return
			}
			results <- addrs
		}()
	}
	wg.Wait()
	close(results)

	if got := calls.Load(); got != 1 {
		t.Fatalf("calls = %d, want 1", got)
	}
	for addrs := range results {
		if len(addrs) != 1 || addrs[0] != "192.0.2.10:53" {
			t.Fatalf("cache.do() = %#v, want cached address", addrs)
		}
	}
}

func TestHostAddressCacheDoesNotPoisonSharedCallWithCallerCancellation(t *testing.T) {
	cache := newHostAddressCache()
	parent, cancelParent := context.WithTimeout(context.Background(), time.Second)
	defer cancelParent()
	ctx := withHostAddressCache(parent, cache)

	started := make(chan struct{})
	release := make(chan struct{})

	callerCtx, cancelCaller := context.WithCancel(ctx)
	errCh := make(chan error, 1)
	go func() {
		_, err := cache.do(callerCtx, "ns1.example.net.", func(callCtx context.Context) ([]string, error) {
			close(started)
			<-release
			if err := callCtx.Err(); err != nil {
				return nil, err
			}
			return []string{"192.0.2.11:53"}, nil
		})
		errCh <- err
	}()

	<-started
	cancelCaller()
	close(release)

	if err := <-errCh; err != nil {
		t.Fatalf("first cache.do() error = %v, want shared call to continue", err)
	}

	addrs, err := cache.do(ctx, "ns1.example.net.", func(context.Context) ([]string, error) {
		t.Fatal("cache unexpectedly reran the shared call")
		return nil, nil
	})
	if err != nil {
		t.Fatalf("second cache.do() error = %v", err)
	}
	if len(addrs) != 1 || addrs[0] != "192.0.2.11:53" {
		t.Fatalf("second cache.do() = %#v, want preserved cached address", addrs)
	}
}
