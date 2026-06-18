package ipfamily

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Policy string

const (
	PolicyAuto Policy = "auto"
	PolicyIPv4 Policy = "ipv4"
	PolicyIPv6 Policy = "ipv6"
	PolicyDual Policy = "dual"
)

type Capabilities struct {
	IPv4 bool
	IPv6 bool
}

type Availability string

const (
	AvailabilityAvailable       Availability = "available"
	AvailabilityHardUnavailable Availability = "hard_unavailable"
	AvailabilityUnknown         Availability = "unknown"
)

type FamilyAssessment struct {
	Availability Availability
	Reason       string
}

type Assessment struct {
	IPv4   FamilyAssessment
	IPv6   FamilyAssessment
	Cached bool
}

const defaultProbeTimeout = 1500 * time.Millisecond
const assessmentCacheTTL = 30 * time.Second

const (
	reasonProbeOK                   = "probe_ok"
	reasonProbeFailed               = "probe_failed"
	reasonProbeRequired             = "probe_required"
	reasonInterfacesUnavailable     = "interfaces_unavailable"
	reasonLinkLocalOnly             = "link_local_only"
	reasonNoUsableAddress           = "no_usable_address"
	reasonNoUpNonLoopbackInterface  = "no_up_non_loopback_interface"
	reasonNoRoute                   = "no_route"
	reasonNetworkUnreachable        = "network_unreachable"
	reasonFamilyNotSupported        = "family_not_supported"
	reasonAddressNotAvailable       = "address_not_available"
	reasonLocalTransportUnavailable = "local_transport_unavailable"
)

var (
	detectFamilyFn        = probeFamilyAssessment
	inspectLocalStateFn   = inspectLocalState
	assessmentTimeNowFn   = time.Now
	assessmentCacheMu     sync.Mutex
	assessmentCacheExpiry time.Time
	assessmentCacheValue  Assessment
)

func ParsePolicy(raw string) (Policy, error) {
	switch Policy(strings.TrimSpace(strings.ToLower(raw))) {
	case "", PolicyAuto:
		return PolicyAuto, nil
	case PolicyIPv4:
		return PolicyIPv4, nil
	case PolicyIPv6:
		return PolicyIPv6, nil
	case PolicyDual:
		return PolicyDual, nil
	default:
		return "", ErrInvalidPolicy(raw)
	}
}

func (p Policy) EffectiveCapabilities(detected Capabilities) Capabilities {
	switch p {
	case PolicyIPv4:
		return Capabilities{IPv4: true}
	case PolicyIPv6:
		return Capabilities{IPv6: true}
	case PolicyDual:
		return Capabilities{IPv4: true, IPv6: true}
	case PolicyAuto, "":
		return detected
	default:
		return detected
	}
}

func (p Policy) RequiresDetection() bool {
	return p == "" || p == PolicyAuto
}

func DetectCapabilities(ctx context.Context, timeout time.Duration) Capabilities {
	return DetectAssessment(ctx, timeout).Capabilities()
}

func DetectAssessment(ctx context.Context, timeout time.Duration) Assessment {
	timeout = normalizedTimeout(timeout)
	now := assessmentTimeNowFn()

	assessmentCacheMu.Lock()
	if !assessmentCacheExpiry.IsZero() && now.Before(assessmentCacheExpiry) {
		cached := assessmentCacheValue
		cached.Cached = true
		assessmentCacheMu.Unlock()
		return cached
	}
	assessmentCacheMu.Unlock()

	local := inspectLocalStateFn()
	out := Assessment{
		IPv4: local.IPv4,
		IPv6: local.IPv6,
	}
	if out.IPv4.Availability != AvailabilityHardUnavailable {
		out.IPv4 = detectFamilyFn(ctx, "tcp4", "198.41.0.4:53", timeout)
	}
	if out.IPv6.Availability != AvailabilityHardUnavailable {
		out.IPv6 = detectFamilyFn(ctx, "tcp6", "[2001:503:ba3e::2:30]:53", timeout)
	}

	assessmentCacheMu.Lock()
	assessmentCacheValue = out
	assessmentCacheExpiry = now.Add(assessmentCacheTTL)
	assessmentCacheMu.Unlock()
	return out
}

func (a Assessment) Capabilities() Capabilities {
	return Capabilities{
		IPv4: a.IPv4.Availability == AvailabilityAvailable,
		IPv6: a.IPv6.Availability == AvailabilityAvailable,
	}
}

func AllowIP(ip net.IP, caps Capabilities) bool {
	if ip == nil {
		return true
	}
	isIPv6 := ip.To4() == nil
	if caps.IPv4 == caps.IPv6 {
		return true
	}
	if isIPv6 {
		return caps.IPv6
	}
	return caps.IPv4
}

func FilterIPs(values []net.IP, caps Capabilities) []net.IP {
	if caps.IPv4 == caps.IPv6 {
		return append([]net.IP(nil), values...)
	}
	out := make([]net.IP, 0, len(values))
	for _, value := range values {
		if AllowIP(value, caps) {
			out = append(out, append(net.IP(nil), value...))
		}
	}
	return out
}

func normalizedTimeout(timeout time.Duration) time.Duration {
	switch {
	case timeout <= 0:
		return defaultProbeTimeout
	case timeout > defaultProbeTimeout:
		return defaultProbeTimeout
	default:
		return timeout
	}
}

func probeFamilyAssessment(ctx context.Context, network, endpoint string, timeout time.Duration) FamilyAssessment {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, network, endpoint)
	if err != nil {
		if LooksLikeLocalFamilyUnavailable(err) {
			return FamilyAssessment{
				Availability: AvailabilityHardUnavailable,
				Reason:       localFailureReason(err),
			}
		}
		return FamilyAssessment{
			Availability: AvailabilityUnknown,
			Reason:       reasonProbeFailed,
		}
	}
	_ = conn.Close()
	return FamilyAssessment{Availability: AvailabilityAvailable, Reason: reasonProbeOK}
}

type localState struct {
	IPv4 FamilyAssessment
	IPv6 FamilyAssessment
}

func inspectLocalState() localState {
	ifaces, err := net.Interfaces()
	if err != nil {
		return localState{
			IPv4: FamilyAssessment{Availability: AvailabilityUnknown, Reason: reasonInterfacesUnavailable},
			IPv6: FamilyAssessment{Availability: AvailabilityUnknown, Reason: reasonInterfacesUnavailable},
		}
	}

	var (
		hasUpNonLoopback bool
		hasIPv4Usable    bool
		hasIPv6Usable    bool
		hasIPv6LinkLocal bool
	)

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		hasUpNonLoopback = true
		addrs, addrErr := iface.Addrs()
		if addrErr != nil {
			continue
		}
		for _, addr := range addrs {
			ip := ipFromAddr(addr)
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				hasIPv4Usable = true
				continue
			}
			if isUsableIPv6(ip) {
				hasIPv6Usable = true
				continue
			}
			if ip.IsLinkLocalUnicast() {
				hasIPv6LinkLocal = true
			}
		}
	}

	return localState{
		IPv4: classifyLocalFamilyState(hasUpNonLoopback, hasIPv4Usable, false),
		IPv6: classifyLocalFamilyState(hasUpNonLoopback, hasIPv6Usable, hasIPv6LinkLocal),
	}
}

func classifyLocalFamilyState(hasUpNonLoopback, hasUsable, linkLocalOnly bool) FamilyAssessment {
	switch {
	case hasUsable:
		return FamilyAssessment{Availability: AvailabilityUnknown, Reason: reasonProbeRequired}
	case linkLocalOnly:
		return FamilyAssessment{Availability: AvailabilityHardUnavailable, Reason: reasonLinkLocalOnly}
	case hasUpNonLoopback:
		return FamilyAssessment{Availability: AvailabilityHardUnavailable, Reason: reasonNoUsableAddress}
	default:
		return FamilyAssessment{Availability: AvailabilityHardUnavailable, Reason: reasonNoUpNonLoopbackInterface}
	}
}

func ipFromAddr(addr net.Addr) net.IP {
	switch value := addr.(type) {
	case *net.IPAddr:
		return value.IP
	case *net.IPNet:
		return value.IP
	default:
		return nil
	}
}

func isUsableIPv6(ip net.IP) bool {
	return ip != nil && ip.To4() == nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

func LooksLikeLocalFamilyUnavailable(err error) bool {
	if err == nil {
		return false
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && isLocalFamilyErrno(opErr.Err) {
		return true
	}
	if isLocalFamilyErrno(err) {
		return true
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "no route to host") ||
		strings.Contains(text, "network is unreachable") ||
		strings.Contains(text, "address family not supported") ||
		strings.Contains(text, "can't assign requested address") ||
		strings.Contains(text, "cannot assign requested address")
}

func localFailureReason(err error) string {
	if err == nil {
		return ""
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "no route to host"):
		return reasonNoRoute
	case strings.Contains(text, "network is unreachable"):
		return reasonNetworkUnreachable
	case strings.Contains(text, "address family not supported"):
		return reasonFamilyNotSupported
	case strings.Contains(text, "can't assign requested address"),
		strings.Contains(text, "cannot assign requested address"):
		return reasonAddressNotAvailable
	default:
		return reasonLocalTransportUnavailable
	}
}

func isLocalFamilyErrno(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.EHOSTUNREACH, syscall.ENETUNREACH, syscall.EADDRNOTAVAIL, syscall.EAFNOSUPPORT:
			return true
		}
	}
	var sysErr *os.SyscallError
	if errors.As(err, &sysErr) {
		return isLocalFamilyErrno(sysErr.Err)
	}
	return false
}
