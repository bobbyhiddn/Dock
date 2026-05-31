package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Version is injected at build time via ldflags:
//
//	go build -ldflags "-X main.Version=v0.1.0.0 -X main.BuildTime=2024-01-01T00:00:00Z" .
//
// For local non-release builds (no ldflags), the default "dev" remains unless
// git is available in the environment, in which case git-describe is used.
//
// Version scheme: vMAJOR.MINOR.PATCH.VOLATILE (e.g. v0.1.0.0)
//
//	volatile > 0  → test/interim build
//	volatile == 0 → stable release
//
// Never hardcode the version for releases — it comes from git tags via ldflags.
var Version = "dev"

// BuildTime is injected at build time via ldflags.
var BuildTime = "unknown"

func init() {
	// Only attempt git-describe for local "dev" builds.
	// Deployed releases always have Version injected via ldflags (never "dev").
	if Version == "dev" {
		if desc, err := gitDescribeVersion(); err == nil && desc != "" {
			Version = desc
		}
	}
}

// gitDescribeVersion runs `git describe --tags --always --dirty` and returns
// the result. Returns an error if git is not available or not in a repo.
func gitDescribeVersion() (string, error) {
	out, err := exec.Command("git", "describe", "--tags", "--always", "--dirty").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// printVersion prints the version string to stdout and exits 0.
// Called by the --version flag or version subcommand.
func printVersion() {
	fmt.Printf("hermit-dock %s (built %s)\n", Version, BuildTime)
	os.Exit(0)
}
