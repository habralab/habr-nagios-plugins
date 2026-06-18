package ipfamily

import (
	"context"
	"net"
	"testing"
	"time"
)

func resetAssessmentCache() {
	assessmentCacheMu.Lock()
	assessmentCacheExpiry = time.Time{}
	assessmentCacheValue = Assessment{}
	assessmentCacheMu.Unlock()
}

func TestParsePolicy(t *testing.T) {
	for _, tt := range []struct {
		raw  string
		want Policy
	}{
		{raw: "", want: PolicyAuto},
		{raw: "auto", want: PolicyAuto},
		{raw: "ipv4", want: PolicyIPv4},
		{raw: "ipv6", want: PolicyIPv6},
		{raw: "dual", want: PolicyDual},
	} {
		got, err := ParsePolicy(tt.raw)
		if err != nil {
			t.Fatalf("ParsePolicy(%q) error = %v", tt.raw, err)
		}
		if got != tt.want {
			t.Fatalf("ParsePolicy(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
	if _, err := ParsePolicy("weird"); err == nil {
		t.Fatal("ParsePolicy(weird) error = nil, want invalid policy")
	}
}

func TestPolicyEffectiveCapabilities(t *testing.T) {
	detected := Capabilities{IPv4: true, IPv6: false}
	if got := PolicyAuto.EffectiveCapabilities(detected); got != detected {
		t.Fatalf("PolicyAuto caps = %#v, want %#v", got, detected)
	}
	if got := PolicyIPv4.EffectiveCapabilities(detected); got != (Capabilities{IPv4: true}) {
		t.Fatalf("PolicyIPv4 caps = %#v", got)
	}
	if got := PolicyIPv6.EffectiveCapabilities(detected); got != (Capabilities{IPv6: true}) {
		t.Fatalf("PolicyIPv6 caps = %#v", got)
	}
	if got := PolicyDual.EffectiveCapabilities(detected); got != (Capabilities{IPv4: true, IPv6: true}) {
		t.Fatalf("PolicyDual caps = %#v", got)
	}
}

func TestFilterIPs(t *testing.T) {
	values := []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::10")}
	got := FilterIPs(values, Capabilities{IPv4: true, IPv6: false})
	if len(got) != 1 || got[0].String() != "192.0.2.10" {
		t.Fatalf("ipv4 filter = %#v", got)
	}
	got = FilterIPs(values, Capabilities{IPv4: false, IPv6: true})
	if len(got) != 1 || got[0].String() != "2001:db8::10" {
		t.Fatalf("ipv6 filter = %#v", got)
	}
}

func TestDetectCapabilitiesUsesProbeFunction(t *testing.T) {
	orig := detectFamilyFn
	origInspect := inspectLocalStateFn
	origNow := assessmentTimeNowFn
	defer func() {
		detectFamilyFn = orig
		inspectLocalStateFn = origInspect
		assessmentTimeNowFn = origNow
		resetAssessmentCache()
	}()
	resetAssessmentCache()
	inspectLocalStateFn = func() localState {
		return localState{
			IPv4: FamilyAssessment{Availability: AvailabilityUnknown, Reason: reasonProbeRequired},
			IPv6: FamilyAssessment{Availability: AvailabilityUnknown, Reason: reasonProbeRequired},
		}
	}
	assessmentTimeNowFn = func() time.Time { return time.Unix(100, 0) }
	detectFamilyFn = func(_ context.Context, network, endpoint string, timeout time.Duration) FamilyAssessment {
		if timeout > defaultProbeTimeout {
			t.Fatalf("timeout = %s, want clamped <= %s", timeout, defaultProbeTimeout)
		}
		switch network {
		case "tcp4":
			return FamilyAssessment{Availability: AvailabilityAvailable, Reason: reasonProbeOK}
		case "tcp6":
			return FamilyAssessment{Availability: AvailabilityHardUnavailable, Reason: reasonNoRoute}
		default:
			t.Fatalf("unexpected network %q endpoint %q", network, endpoint)
			return FamilyAssessment{}
		}
	}
	got := DetectCapabilities(context.Background(), 10*time.Second)
	if got != (Capabilities{IPv4: true}) {
		t.Fatalf("DetectCapabilities() = %#v, want ipv4-only", got)
	}
}

func TestDetectAssessmentSkipsProbeForHardLocalUnavailableFamily(t *testing.T) {
	orig := detectFamilyFn
	origInspect := inspectLocalStateFn
	origNow := assessmentTimeNowFn
	defer func() {
		detectFamilyFn = orig
		inspectLocalStateFn = origInspect
		assessmentTimeNowFn = origNow
		resetAssessmentCache()
	}()
	resetAssessmentCache()

	var probed []string
	inspectLocalStateFn = func() localState {
		return localState{
			IPv4: FamilyAssessment{Availability: AvailabilityUnknown, Reason: reasonProbeRequired},
			IPv6: FamilyAssessment{Availability: AvailabilityHardUnavailable, Reason: reasonLinkLocalOnly},
		}
	}
	assessmentTimeNowFn = func() time.Time { return time.Unix(100, 0) }
	detectFamilyFn = func(_ context.Context, network, _ string, _ time.Duration) FamilyAssessment {
		probed = append(probed, network)
		return FamilyAssessment{Availability: AvailabilityAvailable, Reason: reasonProbeOK}
	}

	got := DetectAssessment(context.Background(), time.Second)
	if len(probed) != 1 || probed[0] != "tcp4" {
		t.Fatalf("probed networks = %#v, want only tcp4", probed)
	}
	if got.IPv6.Availability != AvailabilityHardUnavailable || got.IPv6.Reason != reasonLinkLocalOnly {
		t.Fatalf("ipv6 assessment = %#v, want hard local unavailable", got.IPv6)
	}
}

func TestDetectAssessmentCachesResult(t *testing.T) {
	orig := detectFamilyFn
	origInspect := inspectLocalStateFn
	origNow := assessmentTimeNowFn
	defer func() {
		detectFamilyFn = orig
		inspectLocalStateFn = origInspect
		assessmentTimeNowFn = origNow
		resetAssessmentCache()
	}()
	resetAssessmentCache()

	now := time.Unix(100, 0)
	assessmentTimeNowFn = func() time.Time { return now }
	inspectLocalStateFn = func() localState {
		return localState{
			IPv4: FamilyAssessment{Availability: AvailabilityUnknown, Reason: reasonProbeRequired},
			IPv6: FamilyAssessment{Availability: AvailabilityUnknown, Reason: reasonProbeRequired},
		}
	}
	var calls int
	detectFamilyFn = func(_ context.Context, _ string, _ string, _ time.Duration) FamilyAssessment {
		calls++
		return FamilyAssessment{Availability: AvailabilityAvailable, Reason: reasonProbeOK}
	}

	first := DetectAssessment(context.Background(), time.Second)
	second := DetectAssessment(context.Background(), time.Second)
	if calls != 2 {
		t.Fatalf("probe calls = %d, want 2 (one per family, cached across assessments)", calls)
	}
	if first.Cached {
		t.Fatal("first assessment unexpectedly marked cached")
	}
	if !second.Cached {
		t.Fatal("second assessment should be marked cached")
	}
}

func TestClassifyLocalFamilyStateUsesLocalFactsOnly(t *testing.T) {
	got := classifyLocalFamilyState(true, true, false)
	if got.Availability != AvailabilityUnknown || got.Reason != reasonProbeRequired {
		t.Fatalf("got = %#v, want unknown/probe_required", got)
	}
	got = classifyLocalFamilyState(true, false, true)
	if got.Availability != AvailabilityHardUnavailable || got.Reason != reasonLinkLocalOnly {
		t.Fatalf("got = %#v, want hard_unavailable/link_local_only", got)
	}
	got = classifyLocalFamilyState(true, false, false)
	if got.Availability != AvailabilityHardUnavailable || got.Reason != reasonNoUsableAddress {
		t.Fatalf("got = %#v, want hard_unavailable/no_usable_address", got)
	}
	got = classifyLocalFamilyState(false, false, false)
	if got.Availability != AvailabilityHardUnavailable || got.Reason != reasonNoUpNonLoopbackInterface {
		t.Fatalf("got = %#v, want hard_unavailable/no_up_non_loopback_interface", got)
	}
}

func TestLocalFailureReasonClassifiesKnownErrors(t *testing.T) {
	for _, tt := range []struct {
		err  error
		want string
	}{
		{err: &net.OpError{Err: &net.AddrError{Err: "no route to host"}}, want: reasonNoRoute},
		{err: &net.OpError{Err: &net.AddrError{Err: "network is unreachable"}}, want: reasonNetworkUnreachable},
		{err: &net.OpError{Err: &net.AddrError{Err: "address family not supported"}}, want: reasonFamilyNotSupported},
		{err: &net.OpError{Err: &net.AddrError{Err: "cannot assign requested address"}}, want: reasonAddressNotAvailable},
	} {
		if got := localFailureReason(tt.err); got != tt.want {
			t.Fatalf("localFailureReason(%v) = %q, want %q", tt.err, got, tt.want)
		}
	}
}
