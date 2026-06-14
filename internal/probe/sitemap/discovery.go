package sitemap

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
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
			if discovery.FinalURL != "" && discovery.FinalURL != robotsURL {
				result.addTrace("robots discovery redirected to %s", discovery.FinalURL)
				result.addRule("PASS", "robots.redirect", robotsURL, fmt.Sprintf("redirected to %s", discovery.FinalURL))
			}
			parsedURL := robotsURL
			if discovery.FinalURL != "" {
				parsedURL = discovery.FinalURL
			}
			result.addTrace("parsed robots.txt %s, sitemap_directives=%d", parsedURL, len(discovery.Sitemaps))
			ruleTarget := robotsURL
			if discovery.FinalURL != "" && discovery.FinalURL != robotsURL {
				ruleTarget = discovery.FinalURL
			}
			result.addRule("PASS", "robots.sitemap_directive", ruleTarget, fmt.Sprintf("found %d sitemap entrypoints", len(discovery.Sitemaps)))
			result.addTrace("robots discovery found %d sitemap entrypoints", len(discovery.Sitemaps))
			return uniqueURLs(discovery.Sitemaps), "robots", problems
		} else {
			if discovery.FinalURL != "" && discovery.FinalURL != robotsURL {
				result.addTrace("robots discovery redirected to %s", discovery.FinalURL)
				result.addRule("PASS", "robots.redirect", robotsURL, fmt.Sprintf("redirected to %s", discovery.FinalURL))
			}
			parsedURL := robotsURL
			if discovery.FinalURL != "" {
				parsedURL = discovery.FinalURL
			}
			result.addTrace("parsed robots.txt %s, sitemap_directives=%d", parsedURL, len(discovery.Sitemaps))
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
		result.addTrace("trying fallback probe via %s", u)
		ok, finalURL, err := probeURL(ctx, client, cfg, u, result)
		if err != nil {
			result.addTrace("fallback probe failed %s: %v", u, err)
			problems = append(problems, makeProblem(cfg, "fallback_probe_failed", u, err.Error()))
			continue
		}
		probedURL := u
		if finalURL != "" && finalURL != u {
			result.addTrace("fallback probe redirected to %s", finalURL)
			result.addRule("PASS", "fallback.redirect", u, fmt.Sprintf("redirected to %s", finalURL))
			probedURL = finalURL
		}
		if ok {
			result.addTrace("fallback probe matched %s", probedURL)
			found = append(found, probedURL)
		} else {
			result.addTrace("fallback probe miss %s", probedURL)
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
	out := &robotsDiscovery{RequestedURL: robotsURL, FinalURL: res.FinalURL}
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
	return out, nil
}

func verifyCrossSubmitHost(ctx context.Context, client *http.Client, cfg Config, hostURL, currentSitemap string, result *Result) (bool, string, error) {
	if result.trustsHost(hostURL) {
		if result != nil && cfg.Verbosity > 1 {
			result.addTrace("cross-submit trust already established for %s", hostURL)
			result.addRule("PASS", "cross_submit.verify", hostURL, "host already trusted for the current sitemap tree")
		}
		return true, "", nil
	}
	if cached, ok := result.crossHostCheck(hostURL); ok {
		if cached.Trusted {
			result.trustHost(hostURL)
			if result != nil && cfg.Verbosity > 1 {
				result.addTrace("cross-submit trust for %s reused from cache via %s", hostURL, cached.Robots)
				result.addRule("PASS", "cross_submit.verify", hostURL, fmt.Sprintf("host trust reused from cached %s", cached.Robots))
			}
		}
		return cached.Trusted, cached.Robots, cacheError(cached.Err)
	}

	targetURL, err := url.Parse(hostURL)
	if err != nil || targetURL.Scheme == "" || targetURL.Host == "" {
		return false, "", nil
	}
	robotsURL := targetURL.Scheme + "://" + targetURL.Host + "/robots.txt"
	discovery, err := parseRobots(ctx, client, cfg, robotsURL, result)
	if err != nil {
		result.setCrossHostCheck(hostURL, crossHostCheck{Trusted: false, Robots: robotsURL, Err: err.Error()})
		return false, robotsURL, err
	}

	allowed := map[string]bool{}
	for _, ep := range result.Entrypoints {
		if normalized, nerr := normalizeURL(ep); nerr == nil {
			allowed[normalized] = true
		}
	}
	if currentSitemap != "" {
		if normalized, nerr := normalizeURL(currentSitemap); nerr == nil {
			allowed[normalized] = true
		}
	}

	trusted := false
	matchedSitemap := ""
	for _, sitemap := range discovery.Sitemaps {
		if allowed[sitemap] {
			trusted = true
			matchedSitemap = sitemap
			break
		}
	}
	result.setCrossHostCheck(hostURL, crossHostCheck{Trusted: trusted, Robots: robotsURL})
	if trusted {
		result.trustHost(hostURL)
		if result != nil && cfg.Verbosity > 1 {
			result.addTrace("cross-submit trust established for %s via %s pointing to %s", hostURL, robotsURL, matchedSitemap)
			result.addRule("PASS", "cross_submit.verify", hostURL, fmt.Sprintf("host verified via %s referencing %s", robotsURL, matchedSitemap))
		}
	}
	return trusted, robotsURL, nil
}

func cacheError(message string) error {
	if message == "" {
		return nil
	}
	return fmt.Errorf("%s", message)
}

func probeURL(ctx context.Context, client *http.Client, cfg Config, rawURL string, result *Result) (bool, string, error) {
	res, err := fetchHTTP(ctx, client, cfg, rawURL, http.MethodHead, result, "fallback probe")
	if err != nil {
		return false, "", err
	}
	defer res.Body.Close()
	finalURL := rawURL
	if res.Request != nil && res.Request.URL != nil {
		finalURL = res.Request.URL.String()
	}

	if res.StatusCode == http.StatusMethodNotAllowed || res.StatusCode == http.StatusNotImplemented {
		return probeURLByContent(ctx, client, cfg, rawURL, result, "fallback probe retry after HEAD rejected")
	}
	if res.StatusCode != http.StatusOK {
		return false, finalURL, nil
	}
	return probeURLByContent(ctx, client, cfg, rawURL, result, "fallback probe content validation")
}

func probeURLByContent(ctx context.Context, client *http.Client, cfg Config, rawURL string, result *Result, note string) (bool, string, error) {
	res, err := fetchHTTP(ctx, client, cfg, rawURL, http.MethodGet, result, note)
	if err != nil {
		return false, "", err
	}
	defer res.Body.Close()
	finalURL := rawURL
	if res.Request != nil && res.Request.URL != nil {
		finalURL = res.Request.URL.String()
	}
	if res.StatusCode != http.StatusOK {
		return false, finalURL, nil
	}

	body, compressed, readTime, netBytes, rawBytes, err := decodeBody(rawURL, res)
	if err != nil {
		if result != nil {
			result.attachHTTPError(rawURL, http.MethodGet, fmt.Sprintf("read error: %v", err), readTime, netBytes, rawBytes)
		}
		return false, "", err
	}
	if result != nil {
		result.attachHTTPRead(rawURL, http.MethodGet, readTime, netBytes, rawBytes, compressed)
	}
	parsed, _ := parseSitemapDocument(cfg, rawURL, res.Header.Get("Content-Type"), body)
	if parsed.Kind == "unknown" {
		return false, finalURL, nil
	}
	return true, finalURL, nil
}
