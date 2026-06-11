package buildinfo

import "testing"

func TestStringWithCommit(t *testing.T) {
	oldVersion := Version
	oldCommit := Commit
	t.Cleanup(func() {
		Version = oldVersion
		Commit = oldCommit
	})

	Version = "v0.1.0"
	Commit = "abc123def456"

	if got, want := String("check_example"), "check_example v0.1.0 (abc123def456)"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

func TestStringWithoutCommitFallsBackToVersionOnly(t *testing.T) {
	oldVersion := Version
	oldCommit := Commit
	t.Cleanup(func() {
		Version = oldVersion
		Commit = oldCommit
	})

	Version = "dev"
	Commit = "unknown"

	if got, want := String("check_example"), "check_example dev"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}
