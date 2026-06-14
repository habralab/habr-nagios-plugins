package ext

const (
	NamespaceImage = "http://www.google.com/schemas/sitemap-image/1.1"
	NamespaceNews  = "http://www.google.com/schemas/sitemap-news/0.9"
	NamespaceVideo = "http://www.google.com/schemas/sitemap-video/1.1"
	NamespaceXHTML = "http://www.w3.org/1999/xhtml"
)

var registry = map[string]Validator{
	NamespaceImage: imageValidator{},
	NamespaceNews:  newsValidator{},
	NamespaceVideo: videoValidator{},
	NamespaceXHTML: xhtmlHreflangValidator{},
}

