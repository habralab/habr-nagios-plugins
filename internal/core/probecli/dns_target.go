package probecli

import (
	"strings"

	"github.com/miekg/dns"
)

type DNSTargetMode string

const (
	DNSTargetHostname DNSTargetMode = "hostname"
	DNSTargetZone     DNSTargetMode = "zone"
)

type DNSTargetInput struct {
	Hostname      string
	Zone          string
	Owner         string
	RRType        string
	RequireRRType bool
}

type DNSTarget struct {
	Mode      DNSTargetMode
	Input     string
	Target    string
	Zone      string
	Owner     string
	RRTypeRaw string
	RRType    uint16
}

func ResolveDNSTargetInput(input DNSTargetInput) (DNSTarget, error) {
	zone := strings.TrimSuffix(strings.TrimSpace(input.Zone), ".")
	host := strings.TrimSuffix(strings.TrimSpace(input.Hostname), ".")
	owner := strings.TrimSuffix(strings.TrimSpace(input.Owner), ".")
	rrtype := strings.ToUpper(strings.TrimSpace(input.RRType))

	if zone == "" && host == "" {
		return DNSTarget{}, ErrInputRequiredAny(InputRefHostname, InputRefZone)
	}

	mode := DNSTargetHostname
	target := host
	if zone != "" {
		mode = DNSTargetZone
		target = zone
	}

	if owner == "" {
		if host != "" {
			owner = host
		} else {
			owner = zone
		}
	}

	out := DNSTarget{
		Mode:      mode,
		Input:     target,
		Target:    target,
		Zone:      zone,
		Owner:     owner,
		RRTypeRaw: rrtype,
	}

	if input.RequireRRType {
		if rrtype == "" {
			return DNSTarget{}, ErrInputRequired(InputRefRRType)
		}
		qtype, ok := dns.StringToType[rrtype]
		if !ok {
			return DNSTarget{}, ErrUnsupportedValue(InputRefRRType, input.RRType)
		}
		out.RRType = qtype
	}

	return out, nil
}
