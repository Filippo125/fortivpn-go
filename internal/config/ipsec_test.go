package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadIPsecCredentialsPermissionsAndRedaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	data := []byte(`{"gateway":"192.0.2.1","username":"alice","password":"secret-value","psk":"shared-key"}`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIPsecCredentials(path); err == nil {
		t.Fatal("accepted public credentials")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	credentials, err := LoadIPsecCredentials(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%v %#v", credentials.Password, credentials.PSK); strings.Contains(got, "secret-value") || strings.Contains(got, "shared-key") {
		t.Fatalf("formatted credentials exposed a secret: %s", got)
	}
	if err := os.WriteFile(path, []byte(`{"secret-value":"hidden"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIPsecCredentials(path); err == nil || strings.Contains(err.Error(), "secret-value") {
		t.Fatalf("error = %v", err)
	}
}

func TestLoadIPsecCredentialsRejectsInvalidGateway(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(path, []byte(`{"gateway":"vpn.example.test","username":"alice","password":"secret","psk":"shared"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIPsecCredentials(path); err == nil || !strings.Contains(err.Error(), "literal gateway IP") {
		t.Fatalf("error = %v", err)
	}
}
