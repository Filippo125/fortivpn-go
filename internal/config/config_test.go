package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadYAMLResolvesGlobalGroupAndInstanceOverrides(t *testing.T) {
	path := writeStructuredConfig(t, "fortivpn.yaml", `
globals:
  insecure: true
  ip_mode: ipv4
  timeout: 5m
  browser: default
  username: global-user
groups:
  employees:
    insecure: false
    username: group-user
    saml: true
instances:
  - name: office
    group: employees
    gateway: vpn.example.test
    port: 8443
    realm: staff
    ip_mode: dual
    saml: false
`)
	cfg, err := Load(path, "employees/office")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Gateway != "vpn.example.test" || cfg.Port != 8443 || cfg.Realm != "staff" {
		t.Fatalf("instance settings = %#v", cfg)
	}
	if cfg.Insecure || cfg.SAML || cfg.Username != "group-user" || cfg.IPMode != "dual" || cfg.Browser != "default" || cfg.Timeout != 5*time.Minute {
		t.Fatalf("resolved settings = %#v", cfg)
	}
}

func TestLoadYAMLResolvesIPsecPSK(t *testing.T) {
	path := writeStructuredConfig(t, "fortivpn.yaml", `
globals:
  psk: global-key
groups:
  employees:
    psk: group-key
instances:
  - name: office
    group: employees
    gateway: 192.0.2.10
`)
	cfg, err := Load(path, "employees/office")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PSK != "group-key" {
		t.Fatalf("resolved PSK = %q", cfg.PSK)
	}
}

func TestLoadYAMLResolvesIPsecConnectionSettings(t *testing.T) {
	path := writeStructuredConfig(t, "fortivpn.yaml", `
globals:
  protocol: ipsec
  transport: tcp
  tcp_port: 4500
instances:
  - name: office
    gateway: vpn.example.test
    remote_id: gateway.example.test
    socket: /private/runtime/charon.vici
`)
	cfg, err := Load(path, "office")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Protocol != "ipsec" || cfg.RemoteID != "gateway.example.test" || cfg.Transport != "tcp" || cfg.TCPPort != 4500 || cfg.Socket != "/private/runtime/charon.vici" {
		t.Fatalf("IPsec settings = %#v", cfg)
	}
}

func TestLoadRejectsInvalidConnectionSettings(t *testing.T) {
	path := writeStructuredConfig(t, "fortivpn.yaml", `
instances:
  - name: office
    gateway: vpn.example.test
    protocol: wireguard
`)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "protocol") {
		t.Fatalf("protocol error = %v", err)
	}
}

func TestLoadStructuredChecksPermissionsForPSK(t *testing.T) {
	path := writeStructuredConfig(t, "fortivpn.yaml", `
globals:
  psk: shared-key
instances:
  - name: office
    gateway: 192.0.2.10
`)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("permissions error = %v", err)
	}
}

func TestLoadJSONSelectsNamedInstance(t *testing.T) {
	path := writeStructuredConfig(t, "fortivpn.json", `{
  "globals": {"ip_mode": "auto"},
  "instances": [
    {"name": "one", "gateway": "one.example.test"},
    {"name": "two", "gateway": "two.example.test", "insecure": true}
  ]
}`)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "--instance") {
		t.Fatalf("multiple instances error = %v", err)
	}
	cfg, err := Load(path, "two")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Gateway != "two.example.test" || !cfg.Insecure || cfg.IPMode != "auto" {
		t.Fatalf("config = %#v", cfg)
	}
}

func TestLoadStructuredRejectsUnknownFieldsAndGroups(t *testing.T) {
	unknownField := writeStructuredConfig(t, "unknown.yaml", `
instances:
  - name: office
    gateway: vpn.example.test
    typo: value
`)
	if _, err := Load(unknownField); err == nil || !strings.Contains(err.Error(), "field typo") {
		t.Fatalf("unknown field error = %v", err)
	}

	unknownGroup := writeStructuredConfig(t, "group.json", `{
  "instances": [{"name": "office", "group": "missing", "gateway": "vpn.example.test"}]
}`)
	if _, err := Load(unknownGroup); err == nil || !strings.Contains(err.Error(), "unknown group") {
		t.Fatalf("unknown group error = %v", err)
	}
}

func TestLoadStructuredChecksPermissionsForEveryPassword(t *testing.T) {
	path := writeStructuredConfig(t, "fortivpn.yaml", `
groups:
  secret:
    password: hidden
instances:
  - name: public
    gateway: vpn.example.test
`)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("permissions error = %v", err)
	}
}

func TestLoadRejectsINI(t *testing.T) {
	path := writeStructuredConfig(t, "fortivpn.conf", "gateway = vpn.example.test")
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "unsupported config format") {
		t.Fatalf("INI error = %v", err)
	}
}

func TestInstanceSelectorsUseGroupAndAllowRepeatedNames(t *testing.T) {
	path := writeStructuredConfig(t, "fortivpn.yaml", `
groups:
  production: {}
  staging: {}
instances:
  - name: main
    group: staging
    gateway: staging.example.test
  - name: local
    gateway: localhost
  - name: main
    group: production
    gateway: production.example.test
`)
	selectors, err := InstanceSelectors(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"local", "production/main", "staging/main"}
	if len(selectors) != len(want) {
		t.Fatalf("selectors = %#v, want %#v", selectors, want)
	}
	for i := range want {
		if selectors[i] != want[i] {
			t.Fatalf("selectors = %#v, want %#v", selectors, want)
		}
	}
	cfg, err := Load(path, "production/main")
	if err != nil || cfg.Gateway != "production.example.test" {
		t.Fatalf("config = %#v, error = %v", cfg, err)
	}
}

func TestAddInstanceUpdatesYAMLAtomically(t *testing.T) {
	path := writeStructuredConfig(t, "fortivpn.yaml", `
globals:
  timeout: 5m
groups:
  company:
    saml: true
instances:
  - name: existing
    group: company
    gateway: old.example.test
`)
	insecure := false
	port := 8443
	if err := AddInstance(path, Instance{
		Name:    "production",
		Group:   "company",
		Gateway: "vpn.example.test",
		Port:    &port,
		GroupSettings: GroupSettings{
			Globals: Globals{Insecure: &insecure},
		},
	}); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path, "company/production")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Gateway != "vpn.example.test" || cfg.Port != 8443 || cfg.Insecure || !cfg.SAML || cfg.Timeout != 5*time.Minute {
		t.Fatalf("added config = %#v", cfg)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "timeout: 5m") {
		t.Fatalf("duration was not preserved as a string:\n%s", data)
	}
}

func TestAddInstanceCanAddFirstInstance(t *testing.T) {
	path := writeStructuredConfig(t, "fortivpn.yaml", `
groups:
  company: {}
instances: []
`)
	if err := AddInstance(path, Instance{Name: "first", Group: "company", Gateway: "vpn.example.test"}); err != nil {
		t.Fatal(err)
	}
	if cfg, err := Load(path, "company/first"); err != nil || cfg.Gateway != "vpn.example.test" {
		t.Fatalf("config = %#v, error = %v", cfg, err)
	}
}

func TestAddInstanceRejectsDuplicateAndUnknownGroup(t *testing.T) {
	path := writeStructuredConfig(t, "fortivpn.json", `{
  "groups": {"company": {}},
  "instances": [{"name": "production", "group": "company", "gateway": "old.example.test"}]
}`)
	duplicate := Instance{Name: "production", Group: "company", Gateway: "new.example.test"}
	if err := AddInstance(path, duplicate); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate error = %v", err)
	}
	unknown := Instance{Name: "test", Group: "missing", Gateway: "test.example.test"}
	if err := AddInstance(path, unknown); err == nil || !strings.Contains(err.Error(), "unknown group") {
		t.Fatalf("unknown group error = %v", err)
	}
}

func TestAddInstanceUpdatesJSON(t *testing.T) {
	path := writeStructuredConfig(t, "fortivpn.json", `{
  "instances": [{"name": "existing", "gateway": "old.example.test"}]
}`)
	timeout := Duration(2 * time.Minute)
	if err := AddInstance(path, Instance{
		Name:          "new",
		Gateway:       "new.example.test",
		GroupSettings: GroupSettings{Globals: Globals{Timeout: &timeout}},
	}); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path, "new")
	if err != nil || cfg.Gateway != "new.example.test" || cfg.Timeout != 2*time.Minute {
		t.Fatalf("config = %#v, error = %v", cfg, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"timeout": "2m0s"`) {
		t.Fatalf("JSON duration was not preserved as a string:\n%s", data)
	}
}

func TestAddInstanceWithPasswordRestrictsPermissions(t *testing.T) {
	path := writeStructuredConfig(t, "fortivpn.yaml", `instances:
  - name: existing
    gateway: old.example.test
`)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	password := "secret"
	if err := AddInstance(path, Instance{Name: "new", Gateway: "new.example.test", GroupSettings: GroupSettings{Globals: Globals{Password: &password}}}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("permissions = %o, want 600", got)
	}
}

func writeStructuredConfig(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(strings.TrimSpace(body)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
