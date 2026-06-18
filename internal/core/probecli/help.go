package probecli

import (
	"fmt"
	"strings"

	"github.com/habralab/habr-nagios-plugins/internal/core/clihelp"
)

type CommonHelpConfig struct {
	DefaultTimeout        string
	TimeoutExamples       []string
	CacheBackendExamples  []string
	IPFamilyExamples      []string
	OutputJSONLine        string
	IgnoreErrorsExample   string
	IncludeIgnoreErrors   bool
	IncludeListErrorSlugs bool
	IncludeHelp           bool
	IncludeVersion        bool
	IncludeVerbose        bool
	IncludeOutput         bool
	IncludeTimeout        bool
	IncludeCacheBackend   bool
	IncludeIPFamily       bool
}

type HelpDocument struct {
	ProgramName  string
	Summary      string
	Usage        []string
	InputOptions []InputSpec
	ExtraOptions []clihelp.Option
	Common       CommonHelpConfig
}

func DefaultCommonHelpConfig(defaultTimeout, outputJSONLine, ignoreErrorsExample string) CommonHelpConfig {
	return CommonHelpConfig{
		DefaultTimeout:        defaultTimeout,
		OutputJSONLine:        outputJSONLine,
		IgnoreErrorsExample:   ignoreErrorsExample,
		IncludeIgnoreErrors:   true,
		IncludeListErrorSlugs: true,
		IncludeHelp:           true,
		IncludeVersion:        true,
		IncludeVerbose:        true,
		IncludeOutput:         true,
		IncludeTimeout:        true,
		IncludeCacheBackend:   true,
		IncludeIPFamily:       true,
	}
}

func RenderHelpDocument(doc HelpDocument) string {
	options := append([]clihelp.Option(nil), HelpOptionsFromInputSpecs(doc.InputOptions)...)
	options = append(options, doc.ExtraOptions...)
	options = append(options, CommonHelpOptions(doc.Common)...)
	return clihelp.RenderDocument(clihelp.Document{
		ProgramName: doc.ProgramName,
		Summary:     doc.Summary,
		Usage:       doc.Usage,
		Options:     options,
	})
}

func HelpOptionsFromInputSpecs(specs []InputSpec) []clihelp.Option {
	out := make([]clihelp.Option, 0, len(specs))
	for _, spec := range specs {
		short, long := primaryOptionNames(spec.Aliases)
		desc := strings.TrimSpace(spec.Description)
		if desc == "" {
			desc = fallbackInputDescription(spec.Aliases)
		}
		out = append(out, clihelp.Option{
			Short:       short,
			Long:        long,
			Description: desc,
			Examples:    append([]string(nil), spec.Examples...),
		})
	}
	return out
}

func CommonHelpOptions(cfg CommonHelpConfig) []clihelp.Option {
	var out []clihelp.Option
	if cfg.IncludeOutput {
		out = append(out, clihelp.Option{
			Long:        "--output",
			Description: OutputModeOptionDescription(cfg.OutputJSONLine),
			Examples:    []string{"--output nagios", "--output json"},
		})
	}
	if cfg.IncludeIgnoreErrors {
		option := clihelp.Option{
			Long:        "--ignore-errors",
			Description: IgnoreErrorsOptionDescription(),
		}
		if example := strings.TrimSpace(cfg.IgnoreErrorsExample); example != "" {
			option.Examples = []string{example}
		}
		out = append(out, option)
	}
	if cfg.IncludeListErrorSlugs {
		out = append(out, clihelp.Option{
			Long:        "--list-error-slugs",
			Description: ListErrorSlugsOptionDescription(),
		})
	}
	if cfg.IncludeTimeout {
		examples := append([]string(nil), cfg.TimeoutExamples...)
		if len(examples) == 0 {
			examples = []string{"-t " + strings.TrimSpace(cfg.DefaultTimeout)}
			if alt := alternateTimeoutExample(cfg.DefaultTimeout); alt != "" {
				examples = append(examples, "--timeout "+alt)
			}
		}
		out = append(out, clihelp.Option{
			Short:       "-t",
			Long:        "--timeout",
			Description: TimeoutOptionDescription(cfg.DefaultTimeout),
			Examples:    examples,
		})
	}
	if cfg.IncludeCacheBackend {
		examples := append([]string(nil), cfg.CacheBackendExamples...)
		if len(examples) == 0 {
			examples = []string{
				"--cache-backend internal://",
				"--cache-backend redis://127.0.0.1:6379/0",
				"--cache-backend redis+unix:///var/run/redis.sock?db=0",
			}
		}
		out = append(out, clihelp.Option{
			Long:        "--cache-backend",
			Description: CacheBackendOptionDescription(),
			Examples:    examples,
		})
	}
	if cfg.IncludeIPFamily {
		examples := append([]string(nil), cfg.IPFamilyExamples...)
		if len(examples) == 0 {
			examples = []string{
				"--ip-family auto",
				"--ip-family ipv4",
				"--ip-family dual",
				"--use-ipv4",
				"--use-ipv6",
			}
		}
		out = append(out, clihelp.Option{
			Long:        "--ip-family",
			Description: IPFamilyOptionDescription(),
			Examples:    examples,
		})
	}
	if cfg.IncludeVerbose {
		out = append(out, clihelp.Option{
			Short:       "-v",
			Long:        "--verbose",
			Description: VerboseOptionDescription(),
			Examples:    []string{"-v", "-vv", "-vvv", "--verbose=2"},
		})
	}
	if cfg.IncludeHelp {
		out = append(out, clihelp.Option{
			Short:       "-h",
			Long:        "--help",
			Description: HelpOptionDescription(),
		})
	}
	if cfg.IncludeVersion {
		out = append(out, clihelp.Option{
			Short:       "-V",
			Long:        "--version",
			Description: VersionOptionDescription(),
		})
	}
	return out
}

func primaryOptionNames(aliases []InputAlias) (string, string) {
	var short string
	var long string
	for _, alias := range aliases {
		if short == "" && strings.TrimSpace(alias.Short) != "" {
			short = "-" + strings.TrimSpace(alias.Short)
		}
		if long == "" && strings.TrimSpace(alias.Long) != "" {
			long = "--" + strings.TrimSpace(alias.Long)
		}
	}
	return short, long
}

func fallbackInputDescription(aliases []InputAlias) string {
	for _, alias := range aliases {
		if usage := strings.TrimSpace(alias.Usage); usage != "" {
			return usage
		}
	}
	return ""
}

func alternateTimeoutExample(defaultTimeout string) string {
	switch strings.TrimSpace(defaultTimeout) {
	case "30s":
		return "60s"
	case "60s":
		return "120s"
	default:
		return ""
	}
}

func WithInputHelp(spec InputSpec, description string, examples ...string) InputSpec {
	spec.Description = description
	spec.Examples = append([]string(nil), examples...)
	return spec
}

func MustSetInputHelp(specs []InputSpec, key, description string, examples ...string) []InputSpec {
	out := append([]InputSpec(nil), specs...)
	for i, spec := range out {
		if spec.Key != key {
			continue
		}
		out[i].Description = description
		out[i].Examples = append([]string(nil), examples...)
		return out
	}
	panic(fmt.Sprintf("probecli: input spec %q not found while setting help", key))
}
