//go:build !linux

package auth

import "os/exec"

func newBrowserCommand(name string, args ...string) (*exec.Cmd, error) {
	return exec.Command(name, args...), nil
}
