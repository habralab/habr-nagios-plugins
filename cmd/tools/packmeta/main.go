package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/habralab/habr-nagios-plugins/internal/packaging/catalog"
	"github.com/habralab/habr-nagios-plugins/internal/packaging/debianmeta"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "debian":
		if err := runDebian(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "changelog":
		if err := runChangelog(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "list":
		for _, probe := range catalog.All {
			fmt.Println(probe.Meta.Slug)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func runDebian(args []string) error {
	fs := flag.NewFlagSet("debian", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	outputDir := fs.String("output-dir", "debian", "directory to write generated Debian packaging files into")
	vendor := fs.String("vendor", debianmeta.DefaultVendor, "vendor namespace for installed plugin names and package names")

	if err := fs.Parse(args); err != nil {
		return err
	}

	spec := debianmeta.BuildSpec(debianmeta.Options{
		Vendor: *vendor,
	}, catalog.All)

	files, err := debianmeta.Render(spec)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		return err
	}

	for _, file := range files {
		path := file.Path
		if *outputDir != "debian" {
			path = filepath.Join(*outputDir, filepath.Base(file.Path))
		}
		if err := os.WriteFile(path, []byte(file.Content), 0o644); err != nil {
			return err
		}
		if err := os.Chmod(path, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func runChangelog(args []string) error {
	fs := flag.NewFlagSet("changelog", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	output := fs.String("output", "debian/changelog", "path to write generated Debian changelog into")
	version := fs.String("version", "", "upstream version; defaults to a derived git snapshot version when omitted")
	commit := fs.String("commit", "", "source control revision; used for snapshot version generation")
	revision := fs.String("revision", debianmeta.DefaultDebianRevision, "Debian package revision suffix")
	distribution := fs.String("distribution", debianmeta.DefaultDistribution, "Debian changelog distribution, e.g. unstable")
	urgency := fs.String("urgency", debianmeta.DefaultUrgency, "Debian changelog urgency")
	homepage := fs.String("homepage", debianmeta.DefaultHomepage, "project homepage URL")
	sourcePackage := fs.String("source-package", debianmeta.DefaultSourcePackage, "Debian source package name")

	if err := fs.Parse(args); err != nil {
		return err
	}

	spec := debianmeta.BuildSpec(debianmeta.Options{
		SourcePackage:   *sourcePackage,
		Homepage:        *homepage,
		Distribution:    *distribution,
		Urgency:         *urgency,
		DebianRevision:  *revision,
		MaintainerName:  maintainerName(),
		MaintainerEmail: maintainerEmail(),
		Version:         *version,
		Commit:          *commit,
	}, catalog.All)

	return os.WriteFile(*output, []byte(debianmeta.RenderChangelog(spec)), 0o644)
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envOrGitOrDefault(envKey, gitKey, fallback string) string {
	if value := envOrDefault(envKey, ""); value != "" {
		return value
	}
	cmd := exec.Command("git", "config", "--get", gitKey)
	output, err := cmd.Output()
	if err == nil {
		value := strings.TrimSpace(string(output))
		if value != "" {
			return value
		}
	}
	return fallback
}

func maintainerName() string {
	if value := envOrGitOrDefault("DEBFULLNAME", "user.name", ""); value != "" {
		return value
	}
	if current, err := user.Current(); err == nil {
		if value := strings.TrimSpace(current.Name); value != "" {
			return value
		}
		if value := strings.TrimSpace(current.Username); value != "" {
			return value
		}
	}
	return debianmeta.DefaultMaintainerName
}

func maintainerEmail() string {
	if value := envOrGitOrDefault("DEBEMAIL", "user.email", ""); value != "" {
		return value
	}
	return debianmeta.DefaultMaintainerEmail
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: packmeta <debian|changelog|list> [options]")
}
