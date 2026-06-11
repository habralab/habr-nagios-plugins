package probemeta

import "fmt"

type Metadata struct {
	Slug    string
	Title   string
	Summary string
}

func (m Metadata) DefaultBinaryName() string {
	return m.BinaryName("check")
}

func (m Metadata) BinaryName(prefix string) string {
	if prefix == "" {
		return m.Slug
	}
	return fmt.Sprintf("%s_%s", prefix, m.Slug)
}

func (m Metadata) NamespacedBinaryName(vendor string) string {
	if vendor == "" {
		return m.DefaultBinaryName()
	}
	return fmt.Sprintf("check_%s_%s", vendor, m.Slug)
}

func (m Metadata) PackageName(vendor string) string {
	if vendor == "" {
		return fmt.Sprintf("nagios-plugin-%s", m.Slug)
	}
	return fmt.Sprintf("%s-nagios-plugin-%s", vendor, m.Slug)
}
