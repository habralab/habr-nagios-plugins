package dnschain

import (
	"context"
	"sort"
	"time"
)

type nsAddr struct {
	Name string
	Addr string
}

func uniqueNSAddrs(values []nsAddr) []nsAddr {
	seen := map[string]bool{}
	var out []nsAddr
	for _, value := range values {
		key := value.Name + "|" + value.Addr
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, value)
	}
	return out
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func withDNSQueryTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return ctx, func() {}
	}
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}
