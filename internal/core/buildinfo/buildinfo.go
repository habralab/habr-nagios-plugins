package buildinfo

import "fmt"

var (
	Version = "dev"
	Commit  = "unknown"
)

func String(binaryName string) string {
	switch {
	case Commit != "" && Commit != "unknown":
		return fmt.Sprintf("%s %s (%s)", binaryName, VersionOrDev(), Commit)
	default:
		return fmt.Sprintf("%s %s", binaryName, VersionOrDev())
	}
}

func VersionOrDev() string {
	if Version == "" {
		return "dev"
	}
	return Version
}
