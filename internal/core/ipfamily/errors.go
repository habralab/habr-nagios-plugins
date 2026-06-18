package ipfamily

import "fmt"

type InvalidPolicyError struct {
	Value string
}

func (e InvalidPolicyError) Error() string {
	return fmt.Sprintf("invalid ip family policy %q", e.Value)
}

func ErrInvalidPolicy(value string) error {
	return InvalidPolicyError{Value: value}
}
