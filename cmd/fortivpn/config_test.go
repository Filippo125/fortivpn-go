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
		"--instance", `company\production`,
		"--gateway", "vpn.example.test",
		"--port", "8443",
		"--realm", "employees",
		"--username", "alice",
		"--saml=false",
		"--ip-mode", "dual",
		"--browser", "default",
		"--timeout", "3m",
		"--insecure",
	}, &output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `company\production`) {
		t.Fatalf("output = %q", output.String())
	}
	cfg, err := appconfig.Load(path, `company\production`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Gateway != "vpn.example.test" || cfg.Port != 8443 || cfg.Realm != "employees" || cfg.Username != "alice" || cfg.SAML || cfg.IPMode != "dual" || cfg.Browser != "default" || !cfg.Insecure {
		t.Fatalf("config = %#v", cfg)
	}
}
