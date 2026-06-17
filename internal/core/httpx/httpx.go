package httpx

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/buildinfo"
)

const (
	DefaultUserAgentProduct = "HabrNagiosPlugins"
	DefaultUserAgentURL     = "https://github.com/habralab/habr-nagios-plugins"
)

type Options struct {
	InsecureSkipVerify bool
	UserAgent          string
	DNSResolver        DNSResolver
	DNSLookupTimeout   time.Duration
	CacheBackend       string
	ResolverObserver   func(DNSResolver)
}

func DefaultUserAgent() string {
	return fmt.Sprintf("%s/%s (+%s)", DefaultUserAgentProduct, buildinfo.VersionForUserAgent(), DefaultUserAgentURL)
}

func NewClient(timeout time.Duration, opts Options) *http.Client {
	baseTransport, _ := http.DefaultTransport.(*http.Transport)
	transport := baseTransport.Clone()
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	}
	transport.TLSClientConfig.InsecureSkipVerify = opts.InsecureSkipVerify
	transport.DialContext = newResolverDialContext(timeout, opts)

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}
