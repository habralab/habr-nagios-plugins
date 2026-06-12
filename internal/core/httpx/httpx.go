package httpx

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/core/buildinfo"
	"github.com/habralab/habr-nagios-plugins/internal/core/clihelp"
)

const (
	DefaultUserAgentProduct = "HabrNagiosPlugins"
	DefaultUserAgentURL     = "https://github.com/habralab/habr-nagios-plugins"
)

type Options struct {
	InsecureSkipVerify bool
	UserAgent          string
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

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}

func HelpOptions() []clihelp.Option {
	return []clihelp.Option{
		{
			Long: "--insecure-skip-verify",
			Description: "Disable TLS certificate verification for HTTP requests.\n" +
				"Use only for diagnostics or when you intentionally want to inspect payload behavior behind broken TLS.",
		},
		{
			Long:        "--user-agent",
			Description: "Override the HTTP User-Agent header sent to robots.txt and sitemap documents.",
			Examples: []string{
				fmt.Sprintf(`--user-agent "%s"`, DefaultUserAgent()),
			},
		},
	}
}
