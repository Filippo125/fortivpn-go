package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConnectDispatchesConfiguredIPsecInstance(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".config", "fortivpn", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	config := `
instances:
  - name: office
    protocol: ipsec
    gateway: 192.0.2.10
    remote_id: 192.0.2.10
    username: alice
    password: secret
    psk: shared-key
    saml: false
    ip_mode: ipv4
    timeout: 1ms
    socket: /tmp/fortivpn-missing.vici
`
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("FORTIVPN_CONFIG", "")
	var out bytes.Buffer
	err := run([]string{"connect", "office"}, &out)
	if err == nil {
		t.Fatal("connection unexpectedly succeeded")
	}
	for _, unexpected := range []string{"unknown command", "remote identity is missing", "requires a gateway", "requires a PSK", "provide --saml", "Usage:"} {
		if strings.Contains(err.Error(), unexpected) {
			t.Fatalf("configured IPsec instance was not dispatched: %v", err)
		}
	}
}

func TestConnectDefaultsExistingInstancesToSSLVPN(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fortivpn.yaml")
	config := `
instances:
  - name: legacy
    gateway: 127.0.0.1
    port: 1
    username: alice
    password: secret
    timeout: 1ms
`
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := run([]string{"connect", "legacy", "--config", path}, &out)
	if err == nil {
		t.Fatal("connection unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), "protocol") || strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("legacy instance was not dispatched to SSL-VPN: %v", err)
	}
}

func TestWithoutOptionRemovesBothConfigForms(t *testing.T) {
	got, err := withoutOption([]string{"--debug", "--config", "one", "--config=two"}, "config")
	if err != nil || len(got) != 1 || got[0] != "--debug" {
		t.Fatalf("withoutOption() = %#v, %v", got, err)
	}
}
