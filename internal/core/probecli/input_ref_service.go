package probecli

const (
	InputRefPort       InputRef = "port"
	InputRefWarnExpiry InputRef = "warn_expiry_days"
	InputRefTransport  InputRef = "transport"
	InputRefSTARTTLS   InputRef = "starttls"
	InputRefPolicyRoot InputRef = "policy_untrusted_root"
	InputRefPolicyDual InputRef = "policy_dual_stack"
	InputRefOCSPMode   InputRef = "ocsp_mode"
	InputRefTLSHSKTO   InputRef = "handshake_timeout"
)

func ServiceInputLabels() InputLabels {
	return InputLabels{
		InputRefPort:       "--port",
		InputRefWarnExpiry: "--warn-expiry-days",
		InputRefTransport:  "--transport",
		InputRefSTARTTLS:   "--starttls",
		InputRefPolicyRoot: "--policy-untrusted-root",
		InputRefPolicyDual: "--policy-dual-stack",
		InputRefOCSPMode:   "--ocsp-mode",
		InputRefTLSHSKTO:   "--handshake-timeout",
	}
}
