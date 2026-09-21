//go:build linux

package auth

import (
	"os/user"
	"strings"
	"testing"
)

func TestBrowserCommandDropsSudoPrivileges(t *testing.T) {
	originalEUID, originalLookup := currentEUID, lookupUser
	t.Cleanup(func() {
		currentEUID = originalEUID
		lookupUser = originalLookup
	})
	currentEUID = func() int { return 0 }
	lookupUser = func(uid string) (*user.User, error) {
		return &user.User{Uid: uid, Gid: "100", Username: "alice", HomeDir: "/home/alice"}, nil
	}
	t.Setenv("SUDO_UID", "1000")
	t.Setenv("SUDO_GID", "100")

	cmd, err := newBrowserCommand("xdg-open", "https://vpn.example.test/")
	if err != nil {
		t.Fatal(err)
	}
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Credential == nil {
		t.Fatal("browser command has no credentials")
	}
	if got := cmd.SysProcAttr.Credential.Uid; got != 1000 {
		t.Fatalf("browser UID = %d, want 1000", got)
	}
	if got := cmd.SysProcAttr.Credential.Gid; got != 100 {
		t.Fatalf("browser GID = %d, want 100", got)
	}
	for _, expected := range []string{"HOME=/home/alice", "USER=alice", "LOGNAME=alice"} {
		if !containsEnvironment(cmd.Env, expected) {
			t.Errorf("browser environment does not contain %q", expected)
		}
	}
}

func TestBrowserCommandKeepsCurrentUserWithoutSudo(t *testing.T) {
	originalEUID := currentEUID
	t.Cleanup(func() { currentEUID = originalEUID })
	currentEUID = func() int { return 1000 }

	cmd, err := newBrowserCommand("xdg-open", "https://vpn.example.test/")
	if err != nil {
		t.Fatal(err)
	}
	if cmd.SysProcAttr != nil {
		t.Fatalf("unexpected browser credentials: %#v", cmd.SysProcAttr)
	}
}

func containsEnvironment(environment []string, expected string) bool {
	for _, entry := range environment {
		if strings.EqualFold(entry, expected) {
			return true
		}
	}
	return false
}
