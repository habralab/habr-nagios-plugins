package probecli

const (
	InputRefHostname   InputRef = "hostname"
	InputRefZone       InputRef = "zone"
	InputRefOwner      InputRef = "owner"
	InputRefRRType     InputRef = "rrtype"
	InputRefMode       InputRef = "mode"
	InputRefDNSSECMode InputRef = "dnssec_mode"
	InputRefDNSTimeout InputRef = "dns_timeout"
)

func DNSInputLabels() InputLabels {
	return InputLabels{
		InputRefHostname:   "-H/--hostname",
		InputRefZone:       "--zone",
		InputRefOwner:      "--owner",
		InputRefRRType:     "--rrtype",
		InputRefMode:       "--mode",
		InputRefDNSSECMode: "--dnssec-mode",
		InputRefDNSTimeout: "--dns-timeout",
	}
}
