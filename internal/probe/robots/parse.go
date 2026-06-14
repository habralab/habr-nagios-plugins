package robots

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/habralab/habr-nagios-plugins/internal/core/targeturl"
)

type parsedDocument struct {
	Groups      []Group
	Sitemaps    []string
	Hosts       []string
	Extensions  []DirectiveObservation
	KnownAgents []KnownAgentObservation
	RawLines    int
	Encoding    string
}

func parseDocument(cfg Config, sourceURL string, body []byte) (parsedDocument, []Problem) {
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return parsedDocument{Encoding: "utf-8"}, []Problem{makeProblem(cfg, "robots_empty", sourceURL, "")}
	}

	problems := make([]Problem, 0)
	out := parsedDocument{Encoding: "utf-8"}
	if !utf8.Valid(body) {
		out.Encoding = "non-utf8"
		problems = append(problems, makeProblem(cfg, "robots_non_utf8", sourceURL, "robots.txt is not valid UTF-8"))
	}

	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), maxRobotsBodyBytes+3)
	seenSitemaps := map[string]bool{}
	knownAgents := map[string]*KnownAgentObservation{}
	var current *Group
	currentHasRules := false

	for lineNo := 1; scanner.Scan(); lineNo++ {
		out.RawLines++
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
			problems = append(problems, makeProblem(cfg, "robots_invalid_line", sourceURL, fmt.Sprintf("line %d: invalid directive syntax", lineNo)))
			continue
		}

		key := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])
		switch key {
		case "user-agent":
			if value == "" {
				problems = append(problems, makeProblem(cfg, "robots_invalid_line", sourceURL, fmt.Sprintf("line %d: User-agent value is empty", lineNo)))
				continue
			}
			if current == nil || currentHasRules {
				out.Groups = append(out.Groups, Group{})
				current = &out.Groups[len(out.Groups)-1]
				currentHasRules = false
			}
			current.UserAgents = append(current.UserAgents, value)
			if spec, ok := lookupAgent(value); ok {
				key := strings.ToLower(spec.Token)
				obs, exists := knownAgents[key]
				if !exists {
					obs = &KnownAgentObservation{Token: spec.Token, Spec: spec}
					knownAgents[key] = obs
				}
				obs.Count++
				obs.GroupNames = appendUnique(obs.GroupNames, value)
			}
		case "allow":
			if current == nil || len(current.UserAgents) == 0 {
				problems = append(problems, makeProblem(cfg, "robots_invalid_line", sourceURL, fmt.Sprintf("line %d: Allow appears before any User-agent", lineNo)))
				continue
			}
			if value != "" && !isValidPathPattern(value) {
				problems = append(problems, makeProblem(cfg, "robots_invalid_path", sourceURL, fmt.Sprintf("line %d: Allow value %q is not a valid path pattern", lineNo, value)))
			}
			current.Allows = append(current.Allows, value)
			currentHasRules = true
		case "disallow":
			if current == nil || len(current.UserAgents) == 0 {
				problems = append(problems, makeProblem(cfg, "robots_invalid_line", sourceURL, fmt.Sprintf("line %d: Disallow appears before any User-agent", lineNo)))
				continue
			}
			if value != "" && !isValidPathPattern(value) {
				problems = append(problems, makeProblem(cfg, "robots_invalid_path", sourceURL, fmt.Sprintf("line %d: Disallow value %q is not a valid path pattern", lineNo, value)))
			}
			current.Disallows = append(current.Disallows, value)
			currentHasRules = true
		case "sitemap":
			if value == "" {
				problems = append(problems, makeProblem(cfg, "robots_invalid_sitemap", sourceURL, fmt.Sprintf("line %d: Sitemap value is empty", lineNo)))
				continue
			}
			u, err := targeturl.Normalize(value)
			if err != nil {
				problems = append(problems, makeProblem(cfg, "robots_invalid_sitemap", sourceURL, fmt.Sprintf("line %d: %v", lineNo, err)))
				continue
			}
			if seenSitemaps[u] {
				problems = append(problems, makeProblem(cfg, "robots_duplicate_sitemap", sourceURL, fmt.Sprintf("line %d: duplicate Sitemap %s", lineNo, u)))
				continue
			}
			seenSitemaps[u] = true
			out.Sitemaps = append(out.Sitemaps, u)
		case "host":
			if value == "" {
				problems = append(problems, makeProblem(cfg, "robots_invalid_line", sourceURL, fmt.Sprintf("line %d: Host value is empty", lineNo)))
				continue
			}
			spec, _ := lookupDirective("host")
			out.Hosts = append(out.Hosts, value)
			out.Extensions = append(out.Extensions, DirectiveObservation{
				Name:  "Host",
				Value: value,
				Line:  lineNo,
				Spec:  spec,
			})
			if cfg.Strict {
				problems = append(problems, makeProblem(cfg, "robots_extension_directive", sourceURL, fmt.Sprintf("line %d: non-standard directive %q is in use", lineNo, parts[0])))
			}
		default:
			if spec, ok := lookupDirective(key); ok && spec.Class == DirectiveExtension {
				if spec.Scope == ScopeGroup {
					if current == nil || len(current.UserAgents) == 0 {
						problems = append(problems, makeProblem(cfg, "robots_invalid_line", sourceURL, fmt.Sprintf("line %d: %s appears before any User-agent", lineNo, key)))
						continue
					}
					current.Extensions = append(current.Extensions, DirectiveObservation{
						Name:       spec.Name,
						Value:      value,
						Line:       lineNo,
						GroupIndex: len(out.Groups),
						Spec:       spec,
					})
					currentHasRules = true
				} else {
					out.Extensions = append(out.Extensions, DirectiveObservation{
						Name:  spec.Name,
						Value: value,
						Line:  lineNo,
						Spec:  spec,
					})
				}
				problems = append(problems, validateExtensionDirective(cfg, sourceURL, spec, value, lineNo)...)
				if cfg.Strict {
					problems = append(problems, makeProblem(cfg, "robots_extension_directive", sourceURL, fmt.Sprintf("line %d: non-standard directive %q is in use", lineNo, parts[0])))
				}
				continue
			}
			if current == nil || len(current.UserAgents) == 0 {
				problems = append(problems, makeProblem(cfg, "robots_invalid_line", sourceURL, fmt.Sprintf("line %d: %s appears before any User-agent", lineNo, key)))
				continue
			}
			currentHasRules = true
			problems = append(problems, makeProblem(cfg, "robots_unknown_directive", sourceURL, fmt.Sprintf("line %d: unknown directive %q", lineNo, parts[0])))
		}
	}
	if err := scanner.Err(); err != nil {
		problems = append(problems, makeProblem(cfg, "robots_fetch_failed", sourceURL, err.Error()))
	}
	for _, obs := range knownAgents {
		out.KnownAgents = append(out.KnownAgents, *obs)
	}
	return out, problems
}

func isValidPathPattern(value string) bool {
	return strings.HasPrefix(value, "/") || strings.HasPrefix(value, "*")
}

func validateExtensionDirective(cfg Config, sourceURL string, spec DirectiveSpec, value string, lineNo int) []Problem {
	switch strings.ToLower(spec.Name) {
	case "sitemap":
		if value == "" {
			return []Problem{makeProblem(cfg, "robots_invalid_sitemap", sourceURL, fmt.Sprintf("line %d: Sitemap value is empty", lineNo))}
		}
		if _, err := targeturl.Normalize(value); err != nil {
			return []Problem{makeProblem(cfg, "robots_invalid_sitemap", sourceURL, fmt.Sprintf("line %d: %v", lineNo, err))}
		}
	case "crawl-delay":
		if value == "" {
			return []Problem{makeProblem(cfg, "robots_invalid_directive_value", sourceURL, fmt.Sprintf("line %d: Crawl-delay value is empty", lineNo))}
		}
	case "clean-param":
		if err := validateCleanParamValue(value); err != nil {
			return []Problem{makeProblem(cfg, "robots_invalid_directive_value", sourceURL, fmt.Sprintf("line %d: %v", lineNo, err))}
		}
	case "request-rate":
		if !strings.Contains(value, "/") {
			return []Problem{makeProblem(cfg, "robots_invalid_directive_value", sourceURL, fmt.Sprintf("line %d: Request-rate value %q must use N/M form", lineNo, value))}
		}
	case "visit-time":
		parts := strings.Split(value, "-")
		if len(parts) != 2 || len(strings.TrimSpace(parts[0])) != 4 || len(strings.TrimSpace(parts[1])) != 4 {
			return []Problem{makeProblem(cfg, "robots_invalid_directive_value", sourceURL, fmt.Sprintf("line %d: Visit-time value %q must use HHMM-HHMM form", lineNo, value))}
		}
	case "noindex":
		if value != "" && !isValidPathPattern(value) {
			return []Problem{makeProblem(cfg, "robots_invalid_path", sourceURL, fmt.Sprintf("line %d: Noindex value %q is not a valid path pattern", lineNo, value))}
		}
	}
	return nil
}

func appendUnique(items []string, item string) []string {
	for _, existing := range items {
		if existing == item {
			return items
		}
	}
	return append(items, item)
}

func validateCleanParamValue(value string) error {
	if value == "" {
		return fmt.Errorf("Clean-param value is empty")
	}
	if len(value) > 500 {
		return fmt.Errorf("Clean-param value exceeds 500 characters")
	}
	fields := strings.Fields(value)
	if len(fields) == 0 || len(fields) > 2 {
		return fmt.Errorf("Clean-param value %q must use PARAM[&PARAM...] [PATH] form", value)
	}
	paramSpec := strings.Trim(strings.TrimSpace(fields[0]), "&")
	if paramSpec == "" {
		return fmt.Errorf("Clean-param value %q contains no parameter names", value)
	}
	for _, param := range strings.Split(paramSpec, "&") {
		if strings.TrimSpace(param) == "" {
			return fmt.Errorf("Clean-param value %q contains an empty parameter name", value)
		}
	}
	if len(fields) == 2 && !strings.HasPrefix(fields[1], "/") {
		return fmt.Errorf("Clean-param path %q must start with \"/\"", fields[1])
	}
	return nil
}
