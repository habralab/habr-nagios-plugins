package sitemap

import (
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
)

func createsCycle(parentURL, childURL string, parents map[string]string) bool {
	if childURL == parentURL {
		return true
	}
	current := parentURL
	for current != "" {
		if current == childURL {
			return true
		}
		current = parents[current]
	}
	return false
}

func normalizeBaseSite(cfg Config) (string, error) {
	if cfg.URL != "" {
		u, err := normalizeURL(cfg.URL)
		if err != nil {
			return "", fmt.Errorf("invalid --url: %w", err)
		}
		parsed, _ := url.Parse(u)
		parsed.Path = "/"
		parsed.RawQuery = ""
		parsed.Fragment = ""
		return strings.TrimRight(parsed.String(), "/"), nil
	}
	if cfg.Hostname == "" {
		return "", nil
	}
	return normalizeURL("https://" + strings.TrimSpace(cfg.Hostname))
}

func targetSelectionTrace(cfg Config, baseSite string) string {
	switch {
	case cfg.Entrypoint != "":
		return fmt.Sprintf("effective target source=entrypoint base_site=%q hostname_ignored=%t url_ignored=%t", baseSite, cfg.Hostname != "", cfg.URL != "")
	case cfg.URL != "":
		return fmt.Sprintf("effective target source=url base_site=%q hostname=%q hostname_used_for_discovery=false", baseSite, cfg.Hostname)
	case cfg.Hostname != "":
		return fmt.Sprintf("effective target source=hostname base_site=%q", baseSite)
	default:
		return "effective target source=none"
	}
}

func targetSource(cfg Config) string {
	switch {
	case cfg.Entrypoint != "":
		return "entrypoint"
	case cfg.URL != "":
		return "url"
	case cfg.Hostname != "":
		return "hostname"
	default:
		return "none"
	}
}

func withTraceRedirects(client *http.Client, result *Result) *http.Client {
	if client == nil {
		return nil
	}

	cloned := *client
	original := client.CheckRedirect
	cloned.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if result != nil && len(via) > 0 {
			prev := via[len(via)-1]
			status := 0
			if req.Response != nil {
				status = req.Response.StatusCode
			}
			result.HTTPTrace = append(result.HTTPTrace, HTTPCall{
				Method:     prev.Method,
				URL:        prev.URL.String(),
				FinalURL:   req.URL.String(),
				StatusCode: status,
				Note:       "redirect",
			})
		}
		if original != nil {
			return original(req, via)
		}
		return nil
	}
	return &cloned
}

func normalizeURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("URL must be absolute: %q", raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("unsupported URL scheme %q", u.Scheme)
	}
	if u.Path == "" {
		u.Path = "/"
	}
	u.Fragment = ""
	return u.String(), nil
}

func uniqueURLs(items []string) []string {
	seen := make(map[string]bool, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

func sameHost(a, b *url.URL) bool {
	return strings.EqualFold(a.Hostname(), b.Hostname()) && normalizedPort(a) == normalizedPort(b)
}

func normalizedPort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

func parentDirPrefix(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "/"
	}
	dir := path.Dir(u.Path)
	if dir == "." {
		return "/"
	}
	if !strings.HasSuffix(dir, "/") {
		dir += "/"
	}
	return dir
}

func baseSiteOrHostname(baseSite, hostname string) string {
	if baseSite != "" {
		return baseSite
	}
	return hostname
}

func emptyAsDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
