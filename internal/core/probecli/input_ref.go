package probecli

type InputRef string

type InputLabels map[InputRef]string

func DefaultInputLabels() InputLabels {
	out := InputLabels{}
	mergeInputLabels(out, CommonInputLabels())
	mergeInputLabels(out, DNSInputLabels())
	mergeInputLabels(out, ServiceInputLabels())
	mergeInputLabels(out, WebInputLabels())
	return out
}

func mergeInputLabels(dst, src InputLabels) {
	for key, value := range src {
		dst[key] = value
	}
}
