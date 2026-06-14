package checkreport

func PartitionSuppressedFindings(findings []Finding, ignoreSet map[string]bool) ([]Finding, []Finding) {
	if len(findings) == 0 {
		return nil, nil
	}
	if len(ignoreSet) == 0 {
		out := append([]Finding(nil), findings...)
		return out, nil
	}

	active := make([]Finding, 0, len(findings))
	suppressed := make([]Finding, 0)
	for _, finding := range findings {
		if ignoreSet[finding.Code] {
			finding.Suppressed = true
			suppressed = append(suppressed, finding)
			continue
		}
		active = append(active, finding)
	}
	return active, suppressed
}
