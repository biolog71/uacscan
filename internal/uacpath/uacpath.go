// Package uacpath locates the UAC repository that uacscan reads artifacts from
// and compares itself against.
//
// It is kept out of the test files so there is exactly one place that knows how
// to find UAC, and so the lookup contains no developer-specific paths.
package uacpath

import (
	"os"
	"path/filepath"
)

// Find returns the UAC repository root, or "" if it cannot be located.
//
// UAC_ROOT wins if set. Otherwise it looks for a sibling checkout, which is the
// usual layout when both live under the same parent directory.
func Find() string {
	if r := os.Getenv("UAC_ROOT"); r != "" {
		if isUAC(r) {
			return r
		}
		return ""
	}
	for _, rel := range []string{"../uac", "../../uac", "../../../uac", "../../../../uac"} {
		if abs, err := filepath.Abs(rel); err == nil && isUAC(abs) {
			return abs
		}
	}
	return ""
}

// Artifacts returns the artifacts directory, or "" if UAC cannot be found.
func Artifacts() string {
	if r := Find(); r != "" {
		return filepath.Join(r, "artifacts")
	}
	return ""
}

// Config returns the shipped uac.conf, or "" if UAC cannot be found.
func Config() string {
	if r := Find(); r != "" {
		return filepath.Join(r, "config", "uac.conf")
	}
	return ""
}

// isUAC checks for the marker files that make a directory recognisably UAC,
// rather than trusting the name alone.
func isUAC(dir string) bool {
	for _, marker := range []string{"uac", "artifacts", "config/uac.conf"} {
		if _, err := os.Stat(filepath.Join(dir, marker)); err != nil {
			return false
		}
	}
	return true
}
