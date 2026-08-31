//go:build !darwin && !linux

package tun

import "errors"

// Create is unavailable on platforms without a native TUN implementation.
func Create() (Device, error) {
	return nil, errors.New("native TUN is supported only on macOS and Linux")
}
