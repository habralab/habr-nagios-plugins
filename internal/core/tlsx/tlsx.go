package tlsx

import "fmt"

type Transport string

const (
	TransportTCP Transport = "tcp"
)

type STARTTLSProfile string

const (
	STARTTLSNone STARTTLSProfile = ""
	STARTTLSSMTP STARTTLSProfile = "smtp"
	STARTTLSIMAP STARTTLSProfile = "imap"
)

func ParseTransport(raw string) (Transport, error) {
	switch Transport(raw) {
	case "", TransportTCP:
		return TransportTCP, nil
	default:
		return "", fmt.Errorf("invalid --transport %q, expected tcp", raw)
	}
}

func ParseSTARTTLSProfile(raw string) (STARTTLSProfile, error) {
	switch STARTTLSProfile(raw) {
	case STARTTLSNone:
		return STARTTLSNone, nil
	case STARTTLSSMTP, STARTTLSIMAP:
		return STARTTLSProfile(raw), nil
	default:
		return "", fmt.Errorf("invalid --starttls %q, expected smtp or imap", raw)
	}
}
