package probecli

const (
	InputRefTimeout      InputRef = "timeout"
	InputRefOutput       InputRef = "output"
	InputRefIgnoreError  InputRef = "ignore_errors"
	InputRefCacheBackend InputRef = "cache_backend"
)

func CommonInputLabels() InputLabels {
	return InputLabels{
		InputRefTimeout:      "--timeout",
		InputRefOutput:       "--output",
		InputRefIgnoreError:  "--ignore-errors",
		InputRefCacheBackend: "--cache-backend",
	}
}
