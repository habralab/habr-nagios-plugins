package sharedcache

import (
	"context"
	"time"
)

type BackendInspection struct {
	Descriptor    BackendDescriptor `json:"descriptor"`
	Code          string            `json:"code,omitempty"`
	Message       string            `json:"message,omitempty"`
	Reachable     bool              `json:"reachable,omitempty"`
	Authenticated bool              `json:"authenticated,omitempty"`
	ProtocolOK    bool              `json:"protocol_ok,omitempty"`
	ServerKind    string            `json:"server_kind,omitempty"`
	ServerRole    string            `json:"server_role,omitempty"`
	Endpoint      string            `json:"endpoint,omitempty"`
}

type InspectableBackend interface {
	Inspect(context.Context) BackendInspection
}

func InspectBackendFromDSN(ctx context.Context, raw string, timeout time.Duration) BackendInspection {
	backend, descriptor, err := NewBackendWithDescriptorFromDSN(raw, timeout)
	if err != nil {
		code := "backend_config_error"
		if descriptor.UnsupportedMode != "" {
			code = "backend_unsupported_mode"
		}
		if descriptor.Kind == "unknown" {
			code = "backend_unsupported_scheme"
		}
		return BackendInspection{
			Descriptor: descriptor,
			Code:       code,
			Message:    descriptor.Description,
		}
	}
	if inspectable, ok := backend.(InspectableBackend); ok {
		inspection := inspectable.Inspect(ctx)
		if inspection.Descriptor.Kind == "" {
			inspection.Descriptor = descriptor
		}
		return inspection
	}
	return BackendInspection{
		Descriptor: descriptor,
		Code:       "backend_internal_only",
		Message:    descriptor.Description,
	}
}
