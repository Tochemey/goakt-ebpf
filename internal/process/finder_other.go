//go:build !linux

package process

import "errors"

// FindByExe is not supported on non-Linux platforms.
func FindByExe(exePath string) (ID, error) {
	return 0, errors.New("FindByExe requires Linux")
}
