package probecli

import (
	"errors"
	"fmt"
	"strings"
)

type RequiredInputError struct {
	Field InputRef
}

func (e *RequiredInputError) Error() string {
	return FormatInputError(e, DefaultInputLabels())
}

type RequiredAnyInputError struct {
	Fields []InputRef
}

func (e *RequiredAnyInputError) Error() string {
	return FormatInputError(e, DefaultInputLabels())
}

type InvalidEnumInputError struct {
	Field   InputRef
	Value   string
	Allowed []string
}

func (e *InvalidEnumInputError) Error() string {
	return FormatInputError(e, DefaultInputLabels())
}

type UnsupportedValueInputError struct {
	Field InputRef
	Value string
}

func (e *UnsupportedValueInputError) Error() string {
	return FormatInputError(e, DefaultInputLabels())
}

type InputConstraintError struct {
	Field  InputRef
	Detail string
}

func (e *InputConstraintError) Error() string {
	return FormatInputError(e, DefaultInputLabels())
}

type InvalidInputError struct {
	Field  InputRef
	Detail error
}

func (e *InvalidInputError) Error() string {
	return FormatInputError(e, DefaultInputLabels())
}

func (e *InvalidInputError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Detail
}

func FormatInputError(err error, labels InputLabels) string {
	var required *RequiredInputError
	if errors.As(err, &required) {
		return fmt.Sprintf("%s is required", labels.label(required.Field))
	}

	var requiredAny *RequiredAnyInputError
	if errors.As(err, &requiredAny) {
		items := make([]string, 0, len(requiredAny.Fields))
		for _, field := range requiredAny.Fields {
			items = append(items, labels.label(field))
		}
		return fmt.Sprintf("either %s is required", joinInputAlternatives(items))
	}

	var invalidEnum *InvalidEnumInputError
	if errors.As(err, &invalidEnum) {
		return fmt.Sprintf("invalid %s %q: want %s", labels.label(invalidEnum.Field), invalidEnum.Value, strings.Join(invalidEnum.Allowed, "|"))
	}

	var unsupported *UnsupportedValueInputError
	if errors.As(err, &unsupported) {
		return fmt.Sprintf("unsupported %s %q", labels.label(unsupported.Field), unsupported.Value)
	}

	var constraint *InputConstraintError
	if errors.As(err, &constraint) {
		return fmt.Sprintf("%s %s", labels.label(constraint.Field), strings.TrimSpace(constraint.Detail))
	}

	var invalid *InvalidInputError
	if errors.As(err, &invalid) {
		return fmt.Sprintf("invalid %s: %s", labels.label(invalid.Field), invalid.Detail)
	}

	return err.Error()
}

func ErrInputRequired(ref InputRef) error {
	return &RequiredInputError{Field: ref}
}

func ErrInputRequiredAny(refs ...InputRef) error {
	return &RequiredAnyInputError{Fields: append([]InputRef(nil), refs...)}
}

func ErrInvalidEnum(ref InputRef, value string, allowed ...string) error {
	return &InvalidEnumInputError{Field: ref, Value: value, Allowed: append([]string(nil), allowed...)}
}

func ErrUnsupportedValue(ref InputRef, value string) error {
	return &UnsupportedValueInputError{Field: ref, Value: value}
}

func ErrInputConstraint(ref InputRef, detail string) error {
	return &InputConstraintError{Field: ref, Detail: strings.TrimSpace(detail)}
}

func ErrInvalidInput(ref InputRef, err error) error {
	return &InvalidInputError{Field: ref, Detail: err}
}

func joinInputAlternatives(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	case 2:
		return items[0] + " or " + items[1]
	default:
		return strings.Join(items[:len(items)-1], ", ") + " or " + items[len(items)-1]
	}
}

func (l InputLabels) label(ref InputRef) string {
	if label, ok := l[ref]; ok && strings.TrimSpace(label) != "" {
		return label
	}
	return string(ref)
}
