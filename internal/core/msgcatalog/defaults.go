package msgcatalog

var defaultCatalog = MustMerge(
	"en",
	CommonEnglishSource(),
	DNSRREnglishSource(),
	DNSChainEnglishSource(),
	RobotsEnglishSource(),
	SitemapEnglishSource(),
	TLSEnglishSource(),
)

func DefaultCatalog() Catalog {
	return defaultCatalog
}

func DefaultSummary(key Key) (string, bool) {
	return defaultCatalog.Render(key, VariantSummary, nil)
}

func DefaultSummaryOrKey(key string) string {
	message, ok := DefaultSummary(Key(key))
	if !ok {
		return key
	}
	return message
}
