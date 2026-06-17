package dnsresolver

import (
	"strconv"

	"github.com/habralab/habr-nagios-plugins/internal/core/sharedcache"
	"github.com/miekg/dns"
)

const (
	sharedCacheModuleDNSResolver = "dnsresolver"
	sharedCacheSchemaVersionV1   = "v1"

	sharedCacheArtifactAuthority  = "authority"
	sharedCacheArtifactDelegation = "delegation"
	sharedCacheArtifactLookup     = "lookup"
	sharedCacheArtifactResolve    = "resolve"
	sharedCacheArtifactValidation = "validation"
)

func sharedCacheAuthorityKey(owner string) string {
	return sharedcache.Key(
		sharedCacheModuleDNSResolver,
		sharedCacheSchemaVersionV1,
		sharedCacheArtifactAuthority,
		dns.Fqdn(owner),
	)
}

func sharedCacheDelegationKey(zone string) string {
	return sharedcache.Key(
		sharedCacheModuleDNSResolver,
		sharedCacheSchemaVersionV1,
		sharedCacheArtifactDelegation,
		dns.Fqdn(zone),
	)
}

func sharedCacheLookupKey(qname string, qtype uint16) string {
	return sharedcache.Key(
		sharedCacheModuleDNSResolver,
		sharedCacheSchemaVersionV1,
		sharedCacheArtifactLookup,
		dns.Fqdn(qname),
		strconv.FormatUint(uint64(qtype), 10),
	)
}

func sharedCacheResolveKey(resolveKey string) string {
	return sharedcache.Key(
		sharedCacheModuleDNSResolver,
		sharedCacheSchemaVersionV1,
		sharedCacheArtifactResolve,
		resolveKey,
	)
}

func sharedCacheValidationKey(zone string) string {
	return sharedcache.Key(
		sharedCacheModuleDNSResolver,
		sharedCacheSchemaVersionV1,
		sharedCacheArtifactValidation,
		dns.Fqdn(zone),
	)
}
