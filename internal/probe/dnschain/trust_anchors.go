package dnschain

import (
	"embed"
	"encoding/xml"
	"fmt"
	"strings"
	"time"
)

//go:embed embeddata/root-anchors.xml embeddata/root-anchors.p7s embeddata/icannbundle.pem
var trustAnchorsFS embed.FS

type trustAnchorDigest struct {
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     string
	PublicKey  string
	Flags      uint16
	ValidFrom  time.Time
	ValidUntil *time.Time
}

var rootTrustAnchors = mustLoadRootTrustAnchors(time.Now().UTC())

type trustAnchorXML struct {
	XMLName    xml.Name             `xml:"TrustAnchor"`
	ID         string               `xml:"id,attr"`
	Source     string               `xml:"source,attr"`
	Zone       string               `xml:"Zone"`
	KeyDigests []trustAnchorXMLItem `xml:"KeyDigest"`
}

type trustAnchorXMLItem struct {
	ID         string `xml:"id,attr"`
	ValidFrom  string `xml:"validFrom,attr"`
	ValidUntil string `xml:"validUntil,attr"`
	KeyTag     uint16 `xml:"KeyTag"`
	Algorithm  uint8  `xml:"Algorithm"`
	DigestType uint8  `xml:"DigestType"`
	Digest     string `xml:"Digest"`
	PublicKey  string `xml:"PublicKey"`
	Flags      uint16 `xml:"Flags"`
}

func mustLoadRootTrustAnchors(now time.Time) []trustAnchorDigest {
	raw, err := trustAnchorsFS.ReadFile("embeddata/root-anchors.xml")
	if err != nil {
		panic(fmt.Sprintf("read embedded root trust anchors: %v", err))
	}
	var doc trustAnchorXML
	if err := xml.Unmarshal(raw, &doc); err != nil {
		panic(fmt.Sprintf("parse embedded root trust anchors XML: %v", err))
	}

	var out []trustAnchorDigest
	for _, item := range doc.KeyDigests {
		validFrom, err := time.Parse(time.RFC3339, item.ValidFrom)
		if err != nil {
			panic(fmt.Sprintf("parse trust anchor validFrom %q: %v", item.ValidFrom, err))
		}
		var validUntil *time.Time
		if item.ValidUntil != "" {
			parsed, err := time.Parse(time.RFC3339, item.ValidUntil)
			if err != nil {
				panic(fmt.Sprintf("parse trust anchor validUntil %q: %v", item.ValidUntil, err))
			}
			validUntil = &parsed
		}
		if now.Before(validFrom) {
			continue
		}
		if validUntil != nil && !now.Before(*validUntil) {
			continue
		}
		out = append(out, trustAnchorDigest{
			KeyTag:     item.KeyTag,
			Algorithm:  item.Algorithm,
			DigestType: item.DigestType,
			Digest:     strings.ToUpper(strings.TrimSpace(item.Digest)),
			PublicKey:  strings.TrimSpace(item.PublicKey),
			Flags:      item.Flags,
			ValidFrom:  validFrom,
			ValidUntil: validUntil,
		})
	}
	if len(out) == 0 {
		panic("embedded root trust anchors produced no currently valid anchors")
	}
	return out
}
