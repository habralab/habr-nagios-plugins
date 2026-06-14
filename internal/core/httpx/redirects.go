package httpx

import (
	"errors"
	"fmt"
	"net/http"
)

const DefaultMaxRedirects = 10

var (
	ErrRedirectLoopDetected  = errors.New("redirect loop detected")
	ErrRedirectLimitExceeded = errors.New("redirect limit exceeded")
)

func CloneWithRedirectPolicy(client *http.Client, maxRedirects int, onRedirect func(method, fromURL, toURL string, statusCode int)) *http.Client {
	if client == nil {
		return nil
	}
	if maxRedirects <= 0 {
		maxRedirects = DefaultMaxRedirects
	}

	cloned := *client
	original := client.CheckRedirect
	cloned.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > 0 && onRedirect != nil {
			prev := via[len(via)-1]
			status := 0
			if req.Response != nil {
				status = req.Response.StatusCode
			}
			onRedirect(prev.Method, prev.URL.String(), req.URL.String(), status)
		}

		for _, prev := range via {
			if prev.URL.String() == req.URL.String() {
				return fmt.Errorf("%w: %s", ErrRedirectLoopDetected, req.URL.String())
			}
		}
		if len(via) >= maxRedirects {
			return fmt.Errorf("%w after %d hops", ErrRedirectLimitExceeded, maxRedirects)
		}
		if original != nil {
			return original(req, via)
		}
		return nil
	}
	return &cloned
}
