package sitemap

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
)

func discoverEntrypoints(ctx context.Context, client *http.Client, cfg Config, baseSite string, result *Result) ([]string, string, []Problem) {
	if cfg.Entrypoint != "" {
		ep, err := normalizeURL(cfg.Entrypoint)
		if err != nil {
			return nil, "explicit", []Problem{makeProblem(cfg, "invalid_entrypoint", cfg.Entrypoint, err.Error())}
		}
		result.addTrace("using explicit entrypoint %s", ep)
		result.addRule("PASS", "entrypoint.explicit", ep, "using explicit sitemap entrypoint")
		return []string{ep}, "explicit", nil
	}

	robotsURL := cfg.RobotsURL
	if robotsURL == "" && baseSite != "" {
		robotsURL = strings.TrimRight(baseSite, "/") + "/robots.txt"
	}

	var problems []Problem
	if robotsURL != "" {
		result.addTrace("trying robots discovery via %s", robotsURL)
		discovery, err := parseRobots(ctx, client, cfg, robotsURL, result)
		if err != nil {
			result.addRule("WARN", "robots.fetch", robotsURL, err.Error())
			problems = append(problems, makeProblem(cfg, "robots_fetch_failed", robotsURL, err.Error()))
		} else if len(discovery.Sitemaps) > 0 {
			result.addRule("PASS", "robots.sitemap_directive", robotsURL, fmt.Sprintf("found %d sitemap entrypoints", len(discovery.Sitemaps)))
			result.addTrace("robots discovery found %d sitemap entrypoints", len(discovery.Sitemaps))
			return uniqueURLs(discovery.Sitemaps), "robots", problems
		}
		result.addRule("WARN", "robots.sitemap_directive", robotsURL, "no Sitemap directive found")
		result.addTrace("robots discovery found no Sitemap directives")
	}

	if !cfg.FallbackProbe || baseSite == "" {
		return nil, "none", problems
	}

	found := make([]string, 0, 1)
	for _, p := range cfg.FallbackPaths {
		u := strings.TrimRight(baseSite, "/") + p
		ok, err := probeURL(ctx, client, cfg, u, result)
		if err != nil {
			result.addTrace("fallback probe failed %s: %v", u, err)
			problems = append(problems, makeProblem(cfg, "fallback_probe_failed", u, err.Error()))
			continue
		}
		if ok {
			result.addTrace("fallback probe matched %s", u)
			found = append(found, u)
		} else {
			result.addTrace("fallback probe miss %s", u)
		}
	}

	if len(found) > 0 {
		severity := SeverityWarning
		if FallbackSeverity(cfg.FallbackStatus) == FallbackOK {
			severity = SeverityOK
		}
		status := "WARN"
		if severity == SeverityOK {
			status = "PASS"
		}
		result.addRule(status, "fallback.discovery", found[0], "resolved sitemap via common-path fallback")
		problems = append(problems, makeProblem(cfg, "fallback_used", found[0], "", severity))
	}

	if len(found) == 0 {
		result.addRule("FAIL", "fallback.discovery", baseSite, "no sitemap found in fallback paths")
	}

	return uniqueURLs(found), "fallback", problems
}

func parseRobots(ctx context.Context, client *http.Client, cfg Config, robotsURL string, result *Result) (*robotsDiscovery, error) {
	res, err := fetch(ctx, client, cfg, robotsURL, result)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("robots.txt returned HTTP %d", res.StatusCode)
	}

	scanner := bufio.NewScanner(bytes.NewReader(res.Body))
	out := &robotsDiscovery{}
	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(strings.ToLower(parts[0]))
		value := strings.TrimSpace(parts[1])
		if key != "sitemap" || value == "" {
			continue
		}
		normalized, err := normalizeURL(value)
		if err != nil {
			continue
		}
		out.Sitemaps = append(out.Sitemaps, normalized)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	result.addTrace("parsed robots.txt %s, sitemap_directives=%d", robotsURL, len(out.Sitemaps))
	return out, nil
}

func probeURL(ctx context.Context, client *http.Client, cfg Config, rawURL string, result *Result) (bool, error) {
	res, err := fetchHTTP(ctx, client, cfg, rawURL, http.MethodHead, result, "fallback probe")
	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusMethodNotAllowed || res.StatusCode == http.StatusNotImplemented {
		return probeURLByContent(ctx, client, cfg, rawURL, result, "fallback probe retry after HEAD rejected")
	}
	if res.StatusCode != http.StatusOK {
		return false, nil
	}
	return probeURLByContent(ctx, client, cfg, rawURL, result, "fallback probe content validation")
}

func probeURLByContent(ctx context.Context, client *http.Client, cfg Config, rawURL string, result *Result, note string) (bool, error) {
	res, err := fetchHTTP(ctx, client, cfg, rawURL, http.MethodGet, result, note)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return false, nil
	}

	body, compressed, readTime, netBytes, rawBytes, err := decodeBody(rawURL, res)
	if err != nil {
		if result != nil {
			result.attachHTTPError(rawURL, http.MethodGet, fmt.Sprintf("read error: %v", err), readTime, netBytes, rawBytes)
		}
		return false, err
	}
	if result != nil {
		result.attachHTTPRead(rawURL, http.MethodGet, readTime, netBytes, rawBytes, compressed)
	}
	parsed, _ := parseSitemapDocument(cfg, rawURL, body)
	if parsed.Kind == "unknown" {
		return false, nil
	}
	return true, nil
}
