package apptest

import (
	"bytes"
	"io"
	"os"
	"testing"
)

func RunWithCapturedStdout(t *testing.T, run func() int) (int, string) {
	t.Helper()

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	defer r.Close()
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	exitCode := run()
	w.Close()

	var out bytes.Buffer
	if _, err := io.Copy(&out, r); err != nil {
		t.Fatalf("io.Copy() error = %v", err)
	}
	return exitCode, out.String()
}
