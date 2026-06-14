package robots

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

type Provenance string

const (
	ProvenanceRFC          Provenance = "rfc"
	ProvenanceVendorDoc    Provenance = "vendor-doc"
	ProvenanceEcosystemDoc Provenance = "ecosystem-doc"
	ProvenanceThirdParty   Provenance = "third-party"
	ProvenanceObserved     Provenance = "observed"
)

type DirectiveClass string

const (
	DirectiveCore      DirectiveClass = "core"
	DirectiveExtension DirectiveClass = "extension"
)

type DirectiveScope string

const (
	ScopeGlobal DirectiveScope = "global"
	ScopeGroup  DirectiveScope = "group"
)

type DirectiveSpec struct {
	Name         string         `json:"name"`
	Aliases      []string       `json:"aliases,omitempty"`
	Class        DirectiveClass `json:"class"`
	Scope        DirectiveScope `json:"scope"`
	Provenance   Provenance     `json:"provenance"`
	Reference    string         `json:"reference"`
	ReferenceURL string         `json:"reference_url,omitempty"`
	Description  string         `json:"description"`
}

type AgentKind string

const (
	AgentSearch        AgentKind = "search"
	AgentTraining      AgentKind = "training"
	AgentUserTriggered AgentKind = "user-triggered"
	AgentAds           AgentKind = "ads"
	AgentArchive       AgentKind = "archive"
)

type AgentSpec struct {
	Token        string     `json:"token"`
	Aliases      []string   `json:"aliases,omitempty"`
	Kind         AgentKind  `json:"kind"`
	Vendor       string     `json:"vendor"`
	Provenance   Provenance `json:"provenance"`
	Reference    string     `json:"reference"`
	ReferenceURL string     `json:"reference_url,omitempty"`
	Description  string     `json:"description"`
}

type AgentBehaviorCategory string

const (
	BehaviorRobots      AgentBehaviorCategory = "robots"
	BehaviorDirective   AgentBehaviorCategory = "directive"
	BehaviorHTTPStatus  AgentBehaviorCategory = "http-status"
	BehaviorRedirect    AgentBehaviorCategory = "redirect"
	BehaviorContentType AgentBehaviorCategory = "content-type"
	BehaviorMetaTag     AgentBehaviorCategory = "meta-tag"
	BehaviorMatching    AgentBehaviorCategory = "matching"
	BehaviorRateLimit   AgentBehaviorCategory = "rate-limit"
)

type AgentBehaviorDisposition string

const (
	BehaviorObeys             AgentBehaviorDisposition = "obeys"
	BehaviorSupports          AgentBehaviorDisposition = "supports"
	BehaviorIgnores           AgentBehaviorDisposition = "ignores"
	BehaviorRecommends        AgentBehaviorDisposition = "recommends"
	BehaviorLimits            AgentBehaviorDisposition = "limits"
	BehaviorUsesFirstMatch    AgentBehaviorDisposition = "uses-first-match"
	BehaviorAllowAll          AgentBehaviorDisposition = "interprets-as-allow-all"
	BehaviorDisallowAll       AgentBehaviorDisposition = "interprets-as-disallow-all"
	BehaviorMayTreatAsMissing AgentBehaviorDisposition = "may-treat-as-missing"
	BehaviorMatchesSubstring  AgentBehaviorDisposition = "matches-substring"
)

type AgentBehaviorClaim struct {
	Category     AgentBehaviorCategory    `json:"category"`
	Subject      string                   `json:"subject"`
	Disposition  AgentBehaviorDisposition `json:"disposition"`
	Value        string                   `json:"value,omitempty"`
	Reference    string                   `json:"reference"`
	ReferenceURL string                   `json:"reference_url,omitempty"`
	Note         string                   `json:"note,omitempty"`
}

type AgentBehaviorSpec struct {
	Token  string               `json:"token"`
	Claims []AgentBehaviorClaim `json:"claims"`
}

type DirectiveObservation struct {
	Name       string
	Value      string
	Line       int
	GroupIndex int
	Spec       DirectiveSpec
}

type KnownAgentObservation struct {
	Token      string
	Count      int
	Spec       AgentSpec
	GroupNames []string
}

//go:embed data/directives.json data/agents.json data/agent_behaviors.json
var registryData embed.FS

type registryState struct {
	directives     map[string]DirectiveSpec
	directiveSpecs []DirectiveSpec
	agents         map[string]AgentSpec
	agentSpecs     []AgentSpec
	behaviors      map[string]AgentBehaviorSpec
	behaviorSpecs  []AgentBehaviorSpec
	err            error
}

var (
	registryOnce sync.Once
	registry     registryState
)

func lookupDirective(name string) (DirectiveSpec, bool) {
	spec, ok := loadRegistry().directives[normalizeRegistryKey(name)]
	return spec, ok
}

func lookupAgent(token string) (AgentSpec, bool) {
	spec, ok := loadRegistry().agents[normalizeRegistryKey(token)]
	return spec, ok
}

func KnownDirectives() []DirectiveSpec {
	items := loadRegistry().directiveSpecs
	out := make([]DirectiveSpec, len(items))
	copy(out, items)
	return out
}

func KnownAgents() []AgentSpec {
	items := loadRegistry().agentSpecs
	out := make([]AgentSpec, len(items))
	copy(out, items)
	return out
}

func KnownAgentBehaviors() []AgentBehaviorSpec {
	items := loadRegistry().behaviorSpecs
	out := make([]AgentBehaviorSpec, len(items))
	copy(out, items)
	return out
}

func lookupAgentBehavior(token string) (AgentBehaviorSpec, bool) {
	spec, ok := loadRegistry().behaviors[normalizeRegistryKey(token)]
	return spec, ok
}

func loadRegistry() registryState {
	registryOnce.Do(func() {
		registry.err = initRegistry(&registry)
	})
	if registry.err != nil {
		panic(registry.err)
	}
	return registry
}

func initRegistry(state *registryState) error {
	directives, err := loadDirectiveSpecs()
	if err != nil {
		return err
	}
	agents, err := loadAgentSpecs()
	if err != nil {
		return err
	}
	behaviors, err := loadAgentBehaviorSpecs()
	if err != nil {
		return err
	}

	state.directives = make(map[string]DirectiveSpec, len(directives))
	state.agents = make(map[string]AgentSpec, len(agents))
	state.behaviors = make(map[string]AgentBehaviorSpec, len(behaviors))

	for _, spec := range directives {
		if err := validateDirectiveSpec(spec); err != nil {
			return err
		}
		if err := registerDirectiveSpec(state.directives, spec); err != nil {
			return err
		}
		state.directiveSpecs = append(state.directiveSpecs, spec)
	}
	for _, spec := range agents {
		if err := validateAgentSpec(spec); err != nil {
			return err
		}
		if err := registerAgentSpec(state.agents, spec); err != nil {
			return err
		}
		state.agentSpecs = append(state.agentSpecs, spec)
	}
	for _, spec := range behaviors {
		if err := validateAgentBehaviorSpec(state.agents, spec); err != nil {
			return err
		}
		if err := registerAgentBehaviorSpec(state.behaviors, spec); err != nil {
			return err
		}
		state.behaviorSpecs = append(state.behaviorSpecs, spec)
	}

	sort.Slice(state.directiveSpecs, func(i, j int) bool {
		return state.directiveSpecs[i].Name < state.directiveSpecs[j].Name
	})
	sort.Slice(state.agentSpecs, func(i, j int) bool {
		return state.agentSpecs[i].Token < state.agentSpecs[j].Token
	})
	sort.Slice(state.behaviorSpecs, func(i, j int) bool {
		return state.behaviorSpecs[i].Token < state.behaviorSpecs[j].Token
	})

	return nil
}

func loadDirectiveSpecs() ([]DirectiveSpec, error) {
	raw, err := registryData.ReadFile("data/directives.json")
	if err != nil {
		return nil, fmt.Errorf("read directive registry: %w", err)
	}
	var specs []DirectiveSpec
	if err := json.Unmarshal(raw, &specs); err != nil {
		return nil, fmt.Errorf("decode directive registry: %w", err)
	}
	return specs, nil
}

func loadAgentSpecs() ([]AgentSpec, error) {
	raw, err := registryData.ReadFile("data/agents.json")
	if err != nil {
		return nil, fmt.Errorf("read agent registry: %w", err)
	}
	var specs []AgentSpec
	if err := json.Unmarshal(raw, &specs); err != nil {
		return nil, fmt.Errorf("decode agent registry: %w", err)
	}
	return specs, nil
}

func loadAgentBehaviorSpecs() ([]AgentBehaviorSpec, error) {
	raw, err := registryData.ReadFile("data/agent_behaviors.json")
	if err != nil {
		return nil, fmt.Errorf("read agent behavior registry: %w", err)
	}
	var specs []AgentBehaviorSpec
	if err := json.Unmarshal(raw, &specs); err != nil {
		return nil, fmt.Errorf("decode agent behavior registry: %w", err)
	}
	return specs, nil
}

func validateDirectiveSpec(spec DirectiveSpec) error {
	if strings.TrimSpace(spec.Name) == "" {
		return fmt.Errorf("directive registry entry has empty name")
	}
	if spec.Class != DirectiveCore && spec.Class != DirectiveExtension {
		return fmt.Errorf("directive %q has invalid class %q", spec.Name, spec.Class)
	}
	if spec.Scope != ScopeGlobal && spec.Scope != ScopeGroup {
		return fmt.Errorf("directive %q has invalid scope %q", spec.Name, spec.Scope)
	}
	if spec.Provenance == "" {
		return fmt.Errorf("directive %q has empty provenance", spec.Name)
	}
	if strings.TrimSpace(spec.Reference) == "" {
		return fmt.Errorf("directive %q has empty reference", spec.Name)
	}
	return nil
}

func validateAgentSpec(spec AgentSpec) error {
	if strings.TrimSpace(spec.Token) == "" {
		return fmt.Errorf("agent registry entry has empty token")
	}
	switch spec.Kind {
	case AgentSearch, AgentTraining, AgentUserTriggered, AgentAds, AgentArchive:
	default:
		return fmt.Errorf("agent %q has invalid kind %q", spec.Token, spec.Kind)
	}
	if strings.TrimSpace(spec.Vendor) == "" {
		return fmt.Errorf("agent %q has empty vendor", spec.Token)
	}
	if spec.Provenance == "" {
		return fmt.Errorf("agent %q has empty provenance", spec.Token)
	}
	if strings.TrimSpace(spec.Reference) == "" {
		return fmt.Errorf("agent %q has empty reference", spec.Token)
	}
	return nil
}

func validateAgentBehaviorSpec(agentIndex map[string]AgentSpec, spec AgentBehaviorSpec) error {
	if strings.TrimSpace(spec.Token) == "" {
		return fmt.Errorf("agent behavior registry entry has empty token")
	}
	if _, ok := agentIndex[normalizeRegistryKey(spec.Token)]; !ok {
		return fmt.Errorf("agent behavior %q references unknown agent token", spec.Token)
	}
	if len(spec.Claims) == 0 {
		return fmt.Errorf("agent behavior %q has no claims", spec.Token)
	}
	for _, claim := range spec.Claims {
		switch claim.Category {
		case BehaviorRobots, BehaviorDirective, BehaviorHTTPStatus, BehaviorRedirect, BehaviorContentType, BehaviorMetaTag, BehaviorMatching, BehaviorRateLimit:
		default:
			return fmt.Errorf("agent behavior %q has invalid category %q", spec.Token, claim.Category)
		}
		switch claim.Disposition {
		case BehaviorObeys, BehaviorSupports, BehaviorIgnores, BehaviorRecommends, BehaviorLimits, BehaviorUsesFirstMatch, BehaviorAllowAll, BehaviorDisallowAll, BehaviorMayTreatAsMissing, BehaviorMatchesSubstring:
		default:
			return fmt.Errorf("agent behavior %q has invalid disposition %q", spec.Token, claim.Disposition)
		}
		if strings.TrimSpace(claim.Subject) == "" {
			return fmt.Errorf("agent behavior %q has claim with empty subject", spec.Token)
		}
		if strings.TrimSpace(claim.Reference) == "" {
			return fmt.Errorf("agent behavior %q has claim with empty reference", spec.Token)
		}
	}
	return nil
}

func registerDirectiveSpec(index map[string]DirectiveSpec, spec DirectiveSpec) error {
	keys := append([]string{spec.Name}, spec.Aliases...)
	for _, key := range keys {
		norm := normalizeRegistryKey(key)
		if norm == "" {
			return fmt.Errorf("directive %q has empty alias", spec.Name)
		}
		if existing, ok := index[norm]; ok {
			return fmt.Errorf("directive registry key %q collides between %q and %q", key, existing.Name, spec.Name)
		}
		index[norm] = spec
	}
	return nil
}

func registerAgentSpec(index map[string]AgentSpec, spec AgentSpec) error {
	keys := append([]string{spec.Token}, spec.Aliases...)
	for _, key := range keys {
		norm := normalizeRegistryKey(key)
		if norm == "" {
			return fmt.Errorf("agent %q has empty alias", spec.Token)
		}
		if existing, ok := index[norm]; ok {
			return fmt.Errorf("agent registry key %q collides between %q and %q", key, existing.Token, spec.Token)
		}
		index[norm] = spec
	}
	return nil
}

func registerAgentBehaviorSpec(index map[string]AgentBehaviorSpec, spec AgentBehaviorSpec) error {
	norm := normalizeRegistryKey(spec.Token)
	if norm == "" {
		return fmt.Errorf("agent behavior %q has empty normalized token", spec.Token)
	}
	if existing, ok := index[norm]; ok {
		return fmt.Errorf("agent behavior registry key %q collides between %q and %q", spec.Token, existing.Token, spec.Token)
	}
	index[norm] = spec
	return nil
}

func normalizeRegistryKey(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
