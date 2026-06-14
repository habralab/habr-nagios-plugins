package robots

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/habralab/habr-nagios-plugins/internal/core/targeturl"
)

func normalizeRobotsURL(cfg Config) (string, string, string, error) {
	if cfg.RobotsURL != "" {
		u, err := targeturl.Normalize(cfg.RobotsURL)
		if err != nil {
			return "", "", "", fmt.Errorf("invalid --robots-url: %w", err)
		}
		return "robots-url", "", u, nil
	}

	baseSite, err := targeturl.BaseSite(cfg.URL, cfg.Hostname)
	if err != nil {
		return "", "", "", err
	}
	if baseSite == "" {
		return "none", "", "", nil
	}
	return targetSource(cfg), baseSite, strings.TrimRight(baseSite, "/") + "/robots.txt", nil
}

func targetSource(cfg Config) string {
	switch {
	case cfg.RobotsURL != "":
		return "robots-url"
	case cfg.URL != "":
		return "url"
	case cfg.Hostname != "":
		return "hostname"
	default:
		return "none"
	}
}

func targetSelectionTrace(cfg Config, baseSite, robotsURL string) string {
	switch {
	case cfg.RobotsURL != "":
		return fmt.Sprintf("effective target source=robots-url robots_url=%q hostname_ignored=%t url_ignored=%t", robotsURL, cfg.Hostname != "", cfg.URL != "")
	case cfg.URL != "":
		return fmt.Sprintf("effective target source=url base_site=%q robots_url=%q hostname=%q hostname_used_for_discovery=false", baseSite, robotsURL, cfg.Hostname)
	case cfg.Hostname != "":
		return fmt.Sprintf("effective target source=hostname base_site=%q robots_url=%q", baseSite, robotsURL)
	default:
		return "effective target source=none"
	}
}

func emptyAsDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func sameHost(rawA, rawB string) bool {
	a, err := url.Parse(rawA)
	if err != nil {
		return false
	}
	b, err := url.Parse(rawB)
	if err != nil {
		return false
	}
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
