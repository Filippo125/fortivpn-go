package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Filippo125/fortivpn-go/internal/network"
)

func TestIPsecDoesNotAcceptSSLVPNOptions(t *testing.T) {
	var out bytes.Buffer
	err := run([]string{"ipsec", "connect", "--insecure"}, &out)
	if err == nil {
		t.Fatal("accepted SSL-VPN certificate bypass")
	}
}

func TestIPsecReadsCredentialsFromSelectedConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fortivpn.yaml")
	config := `
globals:
  username: global-user
  password: global-password
  psk: global-psk
  timeout: 1ms
groups:
  employees:
    username: alice
instances:
  - name: office
    group: employees
    gateway: 192.0.2.10
    saml: false
`
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := run([]string{"ipsec", "connect", "--config", path, "--instance", "employees/office", "--remote-id", "192.0.2.10", "--route", "198.51.100.0/24", "--socket", filepath.Join(t.TempDir(), "missing.vici")}, &out)
	if err == nil {
		t.Fatal("connection unexpectedly succeeded")
	}
	for _, unexpected := range []string{"requires a gateway", "provide --saml", "requires a PSK", "missing or invalid", "Usage:"} {
		if strings.Contains(err.Error(), unexpected) {
			t.Fatalf("configuration was not applied: %v", err)
		}
	}
}

func TestIPsecRejectsSAMLConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fortivpn.yaml")
	config := "instances:\n  - name: office\n    gateway: 192.0.2.10\n    saml: true\n"
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := run([]string{"ipsec", "connect", "--config", path}, &out)
	if err == nil || !strings.Contains(err.Error(), "does not support SAML") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseIPsecModeMapsAutoToIPv4(t *testing.T) {
	mode, err := parseIPsecMode("auto")
	if err != nil || mode != network.IPModeIPv4 {
		t.Fatalf("parseIPsecMode(auto) = %q, %v", mode, err)
	}
	if _, err := parseIPsecMode("ipv6"); err == nil {
		t.Fatal("accepted unsupported IPv6-only IPsec mode")
	}
}

func TestResolveIPsecGatewayAcceptsLiteral(t *testing.T) {
	address, err := resolveIPsecGateway(context.Background(), "192.0.2.10")
	if err != nil || address.String() != "192.0.2.10" {
		t.Fatalf("resolveIPsecGateway() = %s, %v", address, err)
	}
}
