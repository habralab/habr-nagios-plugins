package dnsresolver

import (
	"context"
	"sync"
)

type flightGroup[T any] struct {
	mu    sync.Mutex
	calls map[string]*flightCall[T]
}

type flightCall[T any] struct {
	done   chan struct{}
	result T
	err    error
}

func newFlightGroup[T any]() *flightGroup[T] {
	return &flightGroup[T]{
		calls: map[string]*flightCall[T]{},
	}
}

func (g *flightGroup[T]) do(
	ctx context.Context,
	key string,
	clone func(T) T,
	fn func(context.Context) (T, error),
) (T, error) {
	g.mu.Lock()
	if call, ok := g.calls[key]; ok {
		g.mu.Unlock()
		select {
		case <-call.done:
			return clone(call.result), call.err
		case <-ctx.Done():
			var zero T
			return zero, ctx.Err()
		}
	}

	call := &flightCall[T]{done: make(chan struct{})}
	g.calls[key] = call
	g.mu.Unlock()

	callCtx, cancel := detachedResolverContext(ctx)
	defer cancel()

	call.result, call.err = fn(callCtx)
	close(call.done)

	g.mu.Lock()
	delete(g.calls, key)
	g.mu.Unlock()

	return clone(call.result), call.err
}
