package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	appconfig "github.com/Filippo125/fortivpn-go/internal/config"
)

func TestConfigAddInstanceWritesAllExplicitOptions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fortivpn.yaml")
	body := "groups:\n  company: {}\ninstances:\n  - name: existing\n    group: company\n    gateway: old.example.test\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err := run([]string{
		"config", "add-instance",
		"--config", path,
		"--instance", "company/production",
		"--gateway", "vpn.example.test",
		"--protocol", "ipsec",
		"--port", "8443",
		"--realm", "employees",
		"--username", "alice",
		"--psk", "shared-key",
		"--remote-id", "gateway.example.test",
		"--transport", "tcp",
		"--tcp-port", "4500",
		"--socket", "/private/runtime/charon.vici",
		"--saml=false",
		"--ip-mode", "dual",
		"--browser", "default",
		"--timeout", "3m",
		"--insecure",
	}, &output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "company/production") {
		t.Fatalf("output = %q", output.String())
	}
	cfg, err := appconfig.Load(path, "company/production")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Gateway != "vpn.example.test" || cfg.Protocol != "ipsec" || cfg.Port != 8443 || cfg.Realm != "employees" || cfg.Username != "alice" || cfg.PSK != "shared-key" || cfg.RemoteID != "gateway.example.test" || cfg.Transport != "tcp" || cfg.TCPPort != 4500 || cfg.Socket != "/private/runtime/charon.vici" || cfg.SAML || cfg.IPMode != "dual" || cfg.Browser != "default" || !cfg.Insecure {
		t.Fatalf("config = %#v", cfg)
	}
}
