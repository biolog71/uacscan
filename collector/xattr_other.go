//go:build !linux

package collector

import "errors"

// errNoXattr reports that this platform has no equivalent of the attribute
// being asked for.
var errNoXattr = errors.New("extended attribute not available on this platform")

// getxattr is a stub off Linux.
//
// The only caller is the getcap artifact, and file capabilities are a Linux
// concept -- the artifact itself is declared supported_os: [linux], so with
// supported_os honoured this is never reached. It returns an error rather than
// an empty result so that a future caller cannot mistake "unsupported" for
// "no attribute set".
func getxattr(path, attr string) ([]byte, error) {
	return nil, errNoXattr
}
