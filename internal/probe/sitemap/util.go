package sitemap

import (
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/habralab/habr-nagios-plugins/internal/core/targeturl"
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
	return targeturl.BaseSite(cfg.URL, cfg.Hostname)
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

func normalizeURL(raw string) (string, error) {
	return targeturl.Normalize(raw)
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

func trustedHostKey(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if u.Hostname() == "" {
		return ""
	}
	return strings.ToLower(u.Hostname()) + ":" + normalizedPort(u)
}

func trustedHostKeyFromURL(u *url.URL) string {
	if u == nil || u.Hostname() == "" {
		return ""
	}
	return strings.ToLower(u.Hostname()) + ":" + normalizedPort(u)
}

func (r *Result) trustHost(raw string) {
	if r == nil || r.CrossHostTrust == nil {
		return
	}
	if key := trustedHostKey(raw); key != "" {
		r.CrossHostTrust[key] = true
	}
}

func (r *Result) trustsHost(raw string) bool {
	if r == nil || r.CrossHostTrust == nil {
		return false
	}
	key := trustedHostKey(raw)
	return key != "" && r.CrossHostTrust[key]
}

func (r *Result) crossHostCheck(raw string) (crossHostCheck, bool) {
	if r == nil || r.CrossHostChecks == nil {
		return crossHostCheck{}, false
	}
	key := trustedHostKey(raw)
	if key == "" {
		return crossHostCheck{}, false
	}
	check, ok := r.CrossHostChecks[key]
	return check, ok
}

func (r *Result) setCrossHostCheck(raw string, check crossHostCheck) {
	if r == nil || r.CrossHostChecks == nil {
		return
	}
	if key := trustedHostKey(raw); key != "" {
		r.CrossHostChecks[key] = check
	}
}
