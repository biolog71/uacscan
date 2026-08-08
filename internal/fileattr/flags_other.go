//go:build !linux

package fileattr

import "errors"

// GetFlags is unavailable off Linux: file attribute flags are an ext-family
// concept and the artifact that uses them declares supported_os: [linux].
func GetFlags(path string) (uint32, error) {
	return 0, errors.New("file attribute flags are not available on this platform")
}
