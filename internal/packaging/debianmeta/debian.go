package debianmeta

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/habralab/habr-nagios-plugins/internal/packaging/catalog"
)

const (
	DefaultSourcePackage   = "habr-nagios-plugins"
	DefaultVendor          = "habr"
	DefaultHomepage        = "https://github.com/habralab/habr-nagios-plugins"
	DefaultDistribution    = "unstable"
	DefaultUrgency         = "medium"
	DefaultDebianRevision  = "1"
	DefaultSection         = "net"
	DefaultPriority        = "optional"
	DefaultStandards       = "4.7.0"
	DefaultMaintainerName  = "Local Builder"
	DefaultMaintainerEmail = "builder@example.org"
)

type Options struct {
	SourcePackage    string
	Vendor           string
	Homepage         string
	Distribution     string
	Urgency          string
	DebianRevision   string
	Section          string
	Priority         string
	StandardsVersion string
	MaintainerName   string
	MaintainerEmail  string
	Version          string
	Commit           string
	GeneratedAt      time.Time
}

type PackageFile struct {
	Path    string
	Content string
}

type PackageSpec struct {
	SourcePackage    string
	Version          string
	Distribution     string
	Urgency          string
	Maintainer       string
	Homepage         string
	Section          string
	Priority         string
	StandardsVersion string
	GeneratedAt      time.Time
	Probes           []ProbeSpec
}

type ProbeSpec struct {
	Slug              string
	Title             string
	Summary           string
	PackageName       string
	BuildBinaryName   string
	InstallBinaryName string
}

func NormalizeOptions(opts Options) Options {
	if opts.SourcePackage == "" {
		opts.SourcePackage = DefaultSourcePackage
	}
	if opts.Vendor == "" {
		opts.Vendor = DefaultVendor
	}
	if opts.Homepage == "" {
		opts.Homepage = DefaultHomepage
	}
	if opts.Distribution == "" {
		opts.Distribution = detectDistribution()
	}
	if opts.Urgency == "" {
		opts.Urgency = DefaultUrgency
	}
	if opts.DebianRevision == "" {
		opts.DebianRevision = DefaultDebianRevision
	}
	if opts.Section == "" {
		opts.Section = DefaultSection
	}
	if opts.Priority == "" {
		opts.Priority = DefaultPriority
	}
	if opts.StandardsVersion == "" {
		opts.StandardsVersion = DefaultStandards
	}
	if opts.MaintainerName == "" {
		opts.MaintainerName = DefaultMaintainerName
	}
	if opts.MaintainerEmail == "" {
		opts.MaintainerEmail = DefaultMaintainerEmail
	}
	if opts.GeneratedAt.IsZero() {
		opts.GeneratedAt = time.Now().UTC()
	}
	return opts
}

func DebianUpstreamVersion(version, commit string, now time.Time) string {
	trimmed := strings.TrimSpace(version)
	switch {
	case trimmed == "", trimmed == "dev":
		return fmt.Sprintf("0~git%s.%s", now.UTC().Format("20060102"), sanitizeCommit(commit))
	case strings.HasPrefix(trimmed, "v") && len(trimmed) > 1 && isDigit(trimmed[1]):
		return strings.TrimPrefix(trimmed, "v")
	case isDigit(trimmed[0]):
		return trimmed
	default:
		return fmt.Sprintf("0~git%s.%s", now.UTC().Format("20060102"), sanitizeCommit(commit))
	}
}

func BuildSpec(opts Options, probes []catalog.Probe) PackageSpec {
	opts = NormalizeOptions(opts)
	spec := PackageSpec{
		SourcePackage:    opts.SourcePackage,
		Version:          DebianUpstreamVersion(opts.Version, opts.Commit, opts.GeneratedAt) + "-" + opts.DebianRevision,
		Distribution:     opts.Distribution,
		Urgency:          opts.Urgency,
		Maintainer:       fmt.Sprintf("%s <%s>", opts.MaintainerName, opts.MaintainerEmail),
		Homepage:         opts.Homepage,
		Section:          opts.Section,
		Priority:         opts.Priority,
		StandardsVersion: opts.StandardsVersion,
		GeneratedAt:      opts.GeneratedAt,
	}

	for _, probe := range probes {
		spec.Probes = append(spec.Probes, ProbeSpec{
			Slug:              probe.Meta.Slug,
			Title:             probe.Meta.Title,
			Summary:           probe.Meta.Summary,
			PackageName:       probe.Meta.PackageName(opts.Vendor),
			BuildBinaryName:   probe.Meta.NamespacedBinaryName(opts.Vendor),
			InstallBinaryName: probe.Meta.NamespacedBinaryName(opts.Vendor),
		})
	}
	sort.Slice(spec.Probes, func(i, j int) bool {
		return spec.Probes[i].Slug < spec.Probes[j].Slug
	})
	return spec
}

func Render(spec PackageSpec) ([]PackageFile, error) {
	files := make([]PackageFile, 0, len(spec.Probes)*2)

	for _, probe := range spec.Probes {
		files = append(files,
			PackageFile{
				Path: "debian/" + probe.PackageName + ".install",
				Content: fmt.Sprintf("build/%s usr/lib/nagios/plugins/\n", probe.BuildBinaryName),
			},
			PackageFile{
				Path:    "debian/" + probe.PackageName + ".docs",
				Content: "README.md\nLICENSE\n",
			},
		)
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})
	return files, nil
}

func RenderChangelog(spec PackageSpec) string {
	return executeTemplate(changelogTemplate, spec)
}

func executeTemplate(src string, spec PackageSpec) string {
	tmpl := template.Must(template.New("pkg").Parse(src))
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, spec); err != nil {
		panic(err)
	}
	return buf.String()
}

func sanitizeCommit(commit string) string {
	commit = strings.TrimSpace(commit)
	if commit == "" || commit == "unknown" {
		return "nogit"
	}
	var b strings.Builder
	for _, r := range commit {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "nogit"
	}
	return b.String()
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

func detectDistribution() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return DefaultDistribution
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "VERSION_CODENAME=") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, "VERSION_CODENAME="))
		value = strings.Trim(value, `"`)
		if value != "" {
			return value
		}
	}
	return DefaultDistribution
}

const changelogTemplate = `{{ .SourcePackage }} ({{ .Version }}) {{ .Distribution }}; urgency={{ .Urgency }}

  * Package build scaffold refresh.

 -- {{ .Maintainer }}  {{ .GeneratedAt.Format "Mon, 02 Jan 2006 15:04:05 -0700" }}
`
