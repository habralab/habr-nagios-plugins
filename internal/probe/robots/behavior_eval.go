package robots

import (
	"fmt"
	"strings"
)

func evaluateAgentBehaviors(cfg Config, result *Result) {
	if cfg.BehaviorProfile == BehaviorProfileRFC {
		return
	}

	target := result.finalTarget()
	result.addRule("PASS", "behavior.profile", target, fmt.Sprintf("behavior_profile=%s", cfg.BehaviorProfile))

	for idx, group := range result.Groups {
		if len(group.UserAgents) == 0 {
			continue
		}
		for _, rawAgent := range group.UserAgents {
			spec, ok := lookupAgent(rawAgent)
			if !ok {
				continue
			}
			behavior, ok := lookupAgentBehavior(spec.Token)
			if !ok {
				continue
			}
			evaluateAgentGroupBehaviors(cfg, result, idx, group, spec, behavior)
		}
	}
}

func evaluateAgentGroupBehaviors(cfg Config, result *Result, groupIndex int, group Group, agent AgentSpec, behavior AgentBehaviorSpec) {
	groupLabel := fmt.Sprintf("group %d", groupIndex+1)
	target := result.finalTarget()

	if groupHasRules(group) && behaviorWarnsForGroupRules(behavior) {
		message := fmt.Sprintf("documented behavior: %s may ignore rules in %s", agent.Token, groupLabel)
		result.addProblem(makeProblem(cfg, "robots_agent_ignores_rules", target, message))
		result.addRule("WARN", "behavior.agent_ignores_rules", target, message)
	}

	groupDirectives := collectGroupDirectives(group)
	for directiveName := range groupDirectives {
		claims := matchingBehaviorClaims(behavior, BehaviorDirective, directiveName)
		if len(claims) == 0 {
			if cfg.BehaviorProfile == BehaviorProfileStrict && isExtensionDirectiveName(directiveName) {
				message := fmt.Sprintf("documented support for %s in %s is not known for %s", directiveName, groupLabel, agent.Token)
				result.addProblem(makeProblem(cfg, "robots_agent_directive_undocumented", target, message))
				result.addRule("WARN", "behavior.agent_directive_undocumented", target, message)
			}
			continue
		}

		for _, claim := range claims {
			switch claim.Disposition {
			case BehaviorIgnores:
				message := fmt.Sprintf("documented behavior: %s ignores %s in %s", agent.Token, directiveName, groupLabel)
				result.addProblem(makeProblem(cfg, "robots_agent_ignores_directive", target, message))
				result.addRule("WARN", "behavior.agent_ignores_directive", target, message)
			case BehaviorSupports:
				result.addRule("PASS", "behavior.agent_supports_directive", target,
					fmt.Sprintf("documented behavior: %s supports %s in %s", agent.Token, directiveName, groupLabel))
			}
		}
	}
}

func behaviorWarnsForGroupRules(behavior AgentBehaviorSpec) bool {
	for _, claim := range behavior.Claims {
		if claim.Category != BehaviorRobots || claim.Disposition != BehaviorIgnores {
			continue
		}
		switch normalizeBehaviorSubject(claim.Subject) {
		case "robots.txt records", "robots.txt":
			return true
		}
	}
	return false
}

func matchingBehaviorClaims(behavior AgentBehaviorSpec, category AgentBehaviorCategory, subject string) []AgentBehaviorClaim {
	out := make([]AgentBehaviorClaim, 0)
	needle := normalizeBehaviorSubject(subject)
	for _, claim := range behavior.Claims {
		if claim.Category != category {
			continue
		}
		if normalizeBehaviorSubject(claim.Subject) != needle {
			continue
		}
		out = append(out, claim)
	}
	return out
}

func normalizeBehaviorSubject(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func collectGroupDirectives(group Group) map[string]struct{} {
	out := make(map[string]struct{})
	if len(group.Allows) > 0 {
		out["Allow"] = struct{}{}
	}
	if len(group.Disallows) > 0 {
		out["Disallow"] = struct{}{}
	}
	for _, ext := range group.Extensions {
		out[ext.Name] = struct{}{}
	}
	return out
}

func groupHasRules(group Group) bool {
	return len(group.Allows) > 0 || len(group.Disallows) > 0 || len(group.Extensions) > 0
}

func isExtensionDirectiveName(name string) bool {
	spec, ok := lookupDirective(name)
	return ok && spec.Class == DirectiveExtension
}
