package dnschain

import (
	"github.com/habralab/habr-nagios-plugins/internal/core/checkreport"
)

func (r *Result) ExitCode() int {
	return r.Report.ExitCode()
}

func (r *Result) Summary() string {
	return checkreport.DefaultResultSummary(&r.Report)
}

func (r *Result) Detail() string {
	return checkreport.DefaultResultDetail(&r.Report, r.Config.Verbosity)
}

func (r *Result) JSON() ([]byte, error) {
	return checkreport.DefaultResultJSON(&r.Report)
}
