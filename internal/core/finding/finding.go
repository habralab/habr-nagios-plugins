package finding

type Severity int

const (
	SeverityOK Severity = iota
	SeverityWarning
	SeverityCritical
)

type Problem struct {
	Severity Severity
	Code     string
	Message  string
	URL      string
	Ignored  bool
}

func SeverityName(sev Severity) string {
	switch sev {
	case SeverityCritical:
		return "CRITICAL"
	case SeverityWarning:
		return "WARNING"
	default:
		return "OK"
	}
}
