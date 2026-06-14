package verbosity

import (
	"fmt"
	"strconv"
	"strings"
)

func NormalizeArgs(args []string) ([]string, int, error) {
	out := make([]string, 0, len(args))
	level := 0

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-v":
			level++
		case arg == "-vv":
			level += 2
		case arg == "-vvv":
			level += 3
		case arg == "--verbose":
			if i+1 < len(args) && isInteger(args[i+1]) {
				n, _ := strconv.Atoi(args[i+1])
				level += n
				i++
				continue
			}
			level++
		case strings.HasPrefix(arg, "--verbose="):
			raw := strings.TrimPrefix(arg, "--verbose=")
			n, err := strconv.Atoi(raw)
			if err != nil {
				return nil, 0, fmt.Errorf("invalid --verbose value %q", raw)
			}
			level += n
		default:
			out = append(out, arg)
		}
	}

	return out, level, nil
}

func Clamp(level int) int {
	if level < 0 {
		return 0
	}
	if level > 3 {
		return 3
	}
	return level
}

func isInteger(s string) bool {
	if s == "" {
		return false
	}
	_, err := strconv.Atoi(s)
	return err == nil
}
