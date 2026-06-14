package targeturl

import (
	"fmt"
	"net/url"
	"strings"
)

func Normalize(raw string) (string, error) {
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

func BaseSite(rawURL, hostname string) (string, error) {
	if rawURL != "" {
		u, err := Normalize(rawURL)
		if err != nil {
			return "", fmt.Errorf("invalid --url: %w", err)
		}
		parsed, _ := url.Parse(u)
		parsed.Path = "/"
		parsed.RawQuery = ""
		parsed.Fragment = ""
		return strings.TrimRight(parsed.String(), "/"), nil
	}
	if hostname == "" {
		return "", nil
	}
	return Normalize("https://" + strings.TrimSpace(hostname))
}
