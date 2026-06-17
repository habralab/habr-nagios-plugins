package probecli

import (
	"flag"
	"fmt"
	"strconv"
	"strings"
)

type InputType string

const (
	InputString InputType = "string"
	InputBool   InputType = "bool"
	InputInt    InputType = "int"
)

type InputAlias struct {
	Short string
	Long  string
	Usage string
}

type InputSpec struct {
	Key         string
	Type        InputType
	Default     string
	Aliases     []InputAlias
	Description string
	Examples    []string
}

type Inputs struct {
	specs        map[string]InputSpec
	stringValues map[string]*string
	boolValues   map[string]*bool
	intValues    map[string]*int
}

type Parser struct {
	fs     *flag.FlagSet
	common *CommonFlags
	inputs *Inputs
}

func NewParser(binName string, args []string) (*Parser, error) {
	fs, common, err := NewCommonFlagSet(binName, args)
	if err != nil {
		return nil, err
	}
	return &Parser{
		fs:     fs,
		common: common,
		inputs: newInputs(),
	}, nil
}

func newInputs() *Inputs {
	return &Inputs{
		specs:        map[string]InputSpec{},
		stringValues: map[string]*string{},
		boolValues:   map[string]*bool{},
		intValues:    map[string]*int{},
	}
}

func (p *Parser) FlagSet() *flag.FlagSet {
	return p.fs
}

func (p *Parser) Common() *CommonFlags {
	return p.common
}

func (p *Parser) RegisterCommon(defaultTimeout string) {
	p.common.Register(p.fs, defaultTimeout)
}

func (p *Parser) RegisterInputs(specs ...InputSpec) error {
	for _, spec := range specs {
		if err := p.inputs.register(p.fs, spec); err != nil {
			return err
		}
	}
	return nil
}

func (p *Parser) Parse(hasSlug func(string) bool, validate func(*Inputs) error) (CommonOptions, *Inputs, error) {
	if err := p.fs.Parse(p.common.Args()); err != nil {
		return CommonOptions{}, nil, err
	}
	common, err := p.common.Resolve(hasSlug)
	if err != nil {
		return CommonOptions{}, nil, err
	}
	if validate != nil {
		if err := validate(p.inputs); err != nil {
			return CommonOptions{}, nil, err
		}
	}
	return common, p.inputs, nil
}

func (i *Inputs) Specs() map[string]InputSpec {
	out := make(map[string]InputSpec, len(i.specs))
	for key, spec := range i.specs {
		out[key] = spec
	}
	return out
}

func (i *Inputs) String(key string) string {
	if ptr, ok := i.stringValues[key]; ok && ptr != nil {
		return *ptr
	}
	return ""
}

func (i *Inputs) Bool(key string) bool {
	if ptr, ok := i.boolValues[key]; ok && ptr != nil {
		return *ptr
	}
	return false
}

func (i *Inputs) Int(key string) int {
	if ptr, ok := i.intValues[key]; ok && ptr != nil {
		return *ptr
	}
	return 0
}

func (i *Inputs) register(fs *flag.FlagSet, spec InputSpec) error {
	key := strings.TrimSpace(spec.Key)
	if key == "" {
		return fmt.Errorf("input spec key is required")
	}
	if _, exists := i.specs[key]; exists {
		return fmt.Errorf("duplicate input spec key %q", key)
	}
	if len(spec.Aliases) == 0 {
		return fmt.Errorf("input spec %q must declare at least one alias", key)
	}

	switch spec.Type {
	case InputString:
		value := spec.Default
		i.stringValues[key] = &value
		for _, alias := range spec.Aliases {
			registerStringAlias(fs, &value, alias)
		}
	case InputBool:
		parsed, err := parseBoolDefault(spec.Default, key)
		if err != nil {
			return err
		}
		value := parsed
		i.boolValues[key] = &value
		for _, alias := range spec.Aliases {
			registerBoolAlias(fs, &value, alias)
		}
	case InputInt:
		parsed, err := parseIntDefault(spec.Default, key)
		if err != nil {
			return err
		}
		value := parsed
		i.intValues[key] = &value
		for _, alias := range spec.Aliases {
			registerIntAlias(fs, &value, alias)
		}
	default:
		return fmt.Errorf("input spec %q uses unsupported type %q", key, spec.Type)
	}

	i.specs[key] = spec
	return nil
}

func registerStringAlias(fs *flag.FlagSet, target *string, alias InputAlias) {
	if alias.Short != "" {
		fs.StringVar(target, alias.Short, *target, alias.Usage)
	}
	if alias.Long != "" {
		fs.StringVar(target, alias.Long, *target, alias.Usage)
	}
}

func registerBoolAlias(fs *flag.FlagSet, target *bool, alias InputAlias) {
	if alias.Short != "" {
		fs.BoolVar(target, alias.Short, *target, alias.Usage)
	}
	if alias.Long != "" {
		fs.BoolVar(target, alias.Long, *target, alias.Usage)
	}
}

func registerIntAlias(fs *flag.FlagSet, target *int, alias InputAlias) {
	if alias.Short != "" {
		fs.IntVar(target, alias.Short, *target, alias.Usage)
	}
	if alias.Long != "" {
		fs.IntVar(target, alias.Long, *target, alias.Usage)
	}
}

func parseBoolDefault(raw, key string) (bool, error) {
	if strings.TrimSpace(raw) == "" {
		return false, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("invalid default bool for input %q: %w", key, err)
	}
	return value, nil
}

func parseIntDefault(raw, key string) (int, error) {
	if strings.TrimSpace(raw) == "" {
		return 0, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid default int for input %q: %w", key, err)
	}
	return value, nil
}
