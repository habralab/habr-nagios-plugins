package probecli

import (
	"strconv"
	"time"
)

func DecodeTimeoutInput(inputs *Inputs, key string, ref InputRef) (time.Duration, error) {
	return ParseTimeout(inputs.String(key), DefaultInputLabels().label(ref))
}

func DecodeCSVInput(inputs *Inputs, key string) []string {
	return SplitCSV(inputs.String(key))
}

func DecodeEnumInput[T any](inputs *Inputs, key string, ref InputRef, allowed []string, parse func(string) (T, error)) (T, error) {
	raw := inputs.String(key)
	value, err := parse(raw)
	if err != nil {
		var zero T
		return zero, ErrInvalidEnum(ref, raw, allowed...)
	}
	return value, nil
}

func ValidateMinInt(value int, ref InputRef, min int) error {
	if value < min {
		return ErrInputConstraint(ref, "must be >= "+strconv.Itoa(min))
	}
	return nil
}
