//go:build linux

package auth

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

var (
	currentEUID = os.Geteuid
	lookupUser  = user.LookupId
)

// newBrowserCommand drops root privileges for the browser opener when the VPN
// client itself was launched through sudo. The VPN process remains privileged
// so it can create the TUN interface and install routes.
func newBrowserCommand(name string, args ...string) (*exec.Cmd, error) {
	cmd := exec.Command(name, args...)
	if currentEUID() != 0 {
		return cmd, nil
	}

	rawUID, rawGID := os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID")
	if rawUID == "" || rawGID == "" || rawUID == "0" {
		return cmd, nil
	}
	uid, err := strconv.ParseUint(rawUID, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid SUDO_UID %q: %w", rawUID, err)
	}
	gid, err := strconv.ParseUint(rawGID, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid SUDO_GID %q: %w", rawGID, err)
	}
	desktopUser, err := lookupUser(rawUID)
	if err != nil {
		return nil, fmt.Errorf("look up sudo desktop user %s: %w", rawUID, err)
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
		Uid: uint32(uid),
		Gid: uint32(gid),
	}}
	cmd.Env = os.Environ()
	cmd.Env = setEnvironment(cmd.Env, "HOME", desktopUser.HomeDir)
	cmd.Env = setEnvironment(cmd.Env, "USER", desktopUser.Username)
	cmd.Env = setEnvironment(cmd.Env, "LOGNAME", desktopUser.Username)

	runtimeDir := filepath.Join("/run/user", rawUID)
	if info, statErr := os.Stat(runtimeDir); statErr == nil && info.IsDir() {
		cmd.Env = setEnvironment(cmd.Env, "XDG_RUNTIME_DIR", runtimeDir)
		bus := filepath.Join(runtimeDir, "bus")
		if _, statErr := os.Stat(bus); statErr == nil {
			cmd.Env = setEnvironment(cmd.Env, "DBUS_SESSION_BUS_ADDRESS", "unix:path="+bus)
		}
	}
	return cmd, nil
}

func setEnvironment(environment []string, key, value string) []string {
	prefix := key + "="
	for index, entry := range environment {
		if len(entry) >= len(prefix) && entry[:len(prefix)] == prefix {
			environment[index] = prefix + value
			return environment
		}
	}
	return append(environment, prefix+value)
}
