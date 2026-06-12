package buildinfo

import (
	"fmt"
	"strings"
)

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

func VersionForUserAgent() string {
	v := VersionOrDev()
	if v == "" || v == "dev" {
		return "dev"
	}
	if strings.HasPrefix(v, "v") && len(v) > 1 && v[1] >= '0' && v[1] <= '9' {
		return v
	}
	return "dev"
}
