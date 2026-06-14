package checkreport

import (
	"encoding/json"
	"strconv"
	"time"
)

type Status string

const (
	StatusOK       Status = "ok"
	StatusWarning  Status = "warning"
	StatusCritical Status = "critical"
	StatusUnknown  Status = "unknown"
)

type OutputMode string

const (
	OutputNagios OutputMode = "nagios"
	OutputJSON   OutputMode = "json"
)

type CheckState string

const (
	CheckPass     CheckState = "pass"
	CheckWarning  CheckState = "warning"
	CheckCritical CheckState = "critical"
	CheckUnknown  CheckState = "unknown"
	CheckIgnore   CheckState = "ignore"
	CheckNote     CheckState = "note"
)

type AggregationMode string

const (
	AggregationNone        AggregationMode = ""
	AggregationSuccessOnly AggregationMode = "success_only"
)

type Report struct {
	Probe              string       `json:"probe"`
	Target             string       `json:"target,omitempty"`
	PrimaryTarget      string       `json:"primary_target,omitempty"`
	Targets            []Target     `json:"targets,omitempty"`
	Status             Status       `json:"status"`
	Summary            string       `json:"summary"`
	Partial            bool         `json:"partial,omitempty"`
	CoverageNote       string       `json:"coverage_note,omitempty"`
	StartedAt          time.Time    `json:"started_at,omitempty"`
	DurationMS         int64        `json:"duration_ms,omitempty"`
	Stages             []Stage      `json:"stages,omitempty"`
	Findings           []Finding    `json:"findings,omitempty"`
	SuppressedFindings []Finding    `json:"suppressed_findings,omitempty"`
	Traces             []TraceEvent `json:"traces,omitempty"`
	Metrics            []Metric     `json:"metrics,omitempty"`
	Meta               []KV         `json:"meta,omitempty"`
}

type Target struct {
	Role  string `json:"role"`
	Value string `json:"value"`
}

type Stage struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Status     Status   `json:"status"`
	Target     string   `json:"target,omitempty"`
	DurationMS int64    `json:"duration_ms,omitempty"`
	Checks     []Check  `json:"checks,omitempty"`
	Notes      []string `json:"notes,omitempty"`
}

type Check struct {
	ID              string          `json:"id"`
	State           CheckState      `json:"state"`
	Subject         string          `json:"subject,omitempty"`
	Message         string          `json:"message"`
	Evidence        []Evidence      `json:"evidence,omitempty"`
	Meta            []KV            `json:"meta,omitempty"`
	MinVerbosity    int             `json:"min_verbosity,omitempty"`
	AggregationKey  string          `json:"aggregation_key,omitempty"`
	AggregationMode AggregationMode `json:"aggregation_mode,omitempty"`
}

type Evidence struct {
	Kind       string `json:"kind"`
	Summary    string `json:"summary"`
	Attributes []KV   `json:"attributes,omitempty"`
}

type Finding struct {
	Code       string `json:"code"`
	Severity   Status `json:"severity"`
	Target     string `json:"target,omitempty"`
	Message    string `json:"message"`
	Suppressed bool   `json:"suppressed,omitempty"`
}

type TraceEvent struct {
	Kind       string     `json:"kind"`
	StageID    string     `json:"stage_id,omitempty"`
	State      CheckState `json:"state,omitempty"`
	Target     string     `json:"target,omitempty"`
	Message    string     `json:"message"`
	Attributes []KV       `json:"attributes,omitempty"`
	MinVerbosity int      `json:"min_verbosity,omitempty"`
}

type Metric struct {
	Name   string   `json:"name"`
	Type   string   `json:"type,omitempty"`
	Scope  string   `json:"scope,omitempty"`
	Unit   string   `json:"unit,omitempty"`
	Value  string   `json:"value,omitempty"`
	Number *float64 `json:"number,omitempty"`
}

type KV struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func (r Report) ExitCode() int {
	switch r.Status {
	case StatusCritical:
		return 2
	case StatusWarning:
		return 1
	case StatusUnknown:
		return 3
	default:
		return 0
	}
}

func (r Report) NagiosLabel() string {
	switch r.Status {
	case StatusCritical:
		return "CRITICAL"
	case StatusWarning:
		return "WARNING"
	case StatusUnknown:
		return "UNKNOWN"
	default:
		return "OK"
	}
}

func (r Report) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

func (r Report) EffectiveTarget() string {
	if r.PrimaryTarget != "" {
		return r.PrimaryTarget
	}
	return r.Target
}

func (m Metric) DisplayValue() string {
	if m.Value != "" {
		return m.Value
	}
	if m.Number == nil {
		return ""
	}
	return strconv.FormatFloat(*m.Number, 'f', -1, 64)
}
