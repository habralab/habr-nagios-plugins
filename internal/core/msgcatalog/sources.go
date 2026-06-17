package msgcatalog

import (
	"fmt"
	"strings"
)

type Source struct {
	Name            string
	AllowedPrefixes []string
	Items           map[Key]Message
}

func Merge(locale string, sources ...Source) (Catalog, error) {
	merged := make(map[Key]Message)
	for _, source := range sources {
		for key, message := range source.Items {
			if len(source.AllowedPrefixes) > 0 && !hasAllowedPrefix(key, source.AllowedPrefixes) {
				return Catalog{}, fmt.Errorf("msgcatalog source %q: key %q does not match allowed prefixes %v", source.Name, key, source.AllowedPrefixes)
			}
			if _, exists := merged[key]; exists {
				return Catalog{}, fmt.Errorf("msgcatalog source %q: duplicate key %q", source.Name, key)
			}
			merged[key] = message
		}
	}
	return New(locale, merged), nil
}

func MustMerge(locale string, sources ...Source) Catalog {
	catalog, err := Merge(locale, sources...)
	if err != nil {
		panic(err)
	}
	return catalog
}

func hasAllowedPrefix(key Key, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(string(key), prefix) {
			return true
		}
	}
	return false
}
