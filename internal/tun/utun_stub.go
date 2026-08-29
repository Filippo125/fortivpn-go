//go:build !darwin

package tun

import "errors"

// Create is intentionally unavailable outside macOS in this milestone.
func Create() (Device, error) {
	return nil, errors.New("native utun is supported only on macOS")
}
