package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Filippo125/fortivpn-go/internal/network"
)

func TestInspectAcceptsGatewayBeforeOptions(t *testing.T) {
	var output bytes.Buffer
	err := run([]string{"inspect", "vpn.example.test", "--username", "alice", "--password", "secret", "--timeout", "1ms"}, &output)
	if err == nil || strings.Contains(err.Error(), "inspect requires") || strings.Contains(err.Error(), "provide --saml") {
		t.Fatalf("error = %v; flags after gateway were not parsed", err)
	}
}

func TestInspectAcceptsGatewayAfterOptions(t *testing.T) {
	var output bytes.Buffer
	err := run([]string{"inspect", "--username", "alice", "--password", "secret", "--timeout", "1ms", "vpn.example.test"}, &output)
	if err == nil || strings.Contains(err.Error(), "inspect requires") || strings.Contains(err.Error(), "provide --saml") {
		t.Fatalf("error = %v; gateway after flags was not parsed", err)
	}
}

func TestInspectReadsGatewayAndUsernameFromConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fortivpn.yaml")
	config := "globals:\n  username: alice\n  timeout: 1ms\ninstances:\n  - name: main\n    gateway: vpn.example.test\n"
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err := run([]string{"inspect", "--config", path, "--password", "secret"}, &output)
	if err == nil || strings.Contains(err.Error(), "requires a gateway") || strings.Contains(err.Error(), "provide --saml") {
		t.Fatalf("error = %v; configuration defaults were not used", err)
	}
}

func TestInspectSelectsStructuredConfigInstance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fortivpn.yaml")
	config := `
globals:
  timeout: 1ms
groups:
  employees:
    username: alice
instances:
  - name: primary
    group: employees
    gateway: vpn.example.test
  - name: secondary
    gateway: other.example.test
`
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err := run([]string{"inspect", "--config", path, "--instance", "employees/primary", "--password", "secret"}, &output)
	if err == nil || strings.Contains(err.Error(), "--instance") || strings.Contains(err.Error(), "requires a gateway") || strings.Contains(err.Error(), "provide --saml") {
		t.Fatalf("error = %v; selected instance defaults were not used", err)
	}
}

func TestConfigPathAcceptsEqualsSyntaxAndRequiresValue(t *testing.T) {
	path, err := configPath([]string{"--config=one.conf", "--config", "two.conf"})
	if err != nil || path != "two.conf" {
		t.Fatalf("configPath() = %q, %v", path, err)
	}
	if _, err := configPath([]string{"--config"}); err == nil {
		t.Fatal("missing config path was accepted")
	}
}

func TestTunConfigSupportsDualStack(t *testing.T) {
	config, err := tunConfig("10.20.4.12/32", "10.20.4.1", "2001:db8::12/128", 1400)
	if err != nil {
		t.Fatal(err)
	}
	if config.IPv4 == nil || config.IPv6 == nil || config.MTU != 1400 {
		t.Fatalf("config = %#v", config)
	}
}

func TestReadPasswordReadsOneLine(t *testing.T) {
	password, err := readPassword(strings.NewReader("first\nsecond\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := password, "first"; got != want {
		t.Fatalf("password = %q, want %q", got, want)
	}
}

func TestParseIPMode(t *testing.T) {
	mode, err := parseIPMode("dual-stack")
	if err != nil || mode != network.IPModeDualStack {
		t.Fatalf("parseIPMode() = %q, %v", mode, err)
	}
	if _, err := parseIPMode("ipx"); err == nil {
		t.Fatal("invalid mode was accepted")
	}
}

func TestPasswordForAuthenticationUsesExplicitPassword(t *testing.T) {
	password, err := passwordForAuthentication(false, "alice", "secret", false, nil, nil)
	if err != nil || password != "secret" {
		t.Fatalf("passwordForAuthentication() = %q, %v", password, err)
	}
}

func TestPasswordForAuthenticationRejectsSAMLPasswordInput(t *testing.T) {
	if _, err := passwordForAuthentication(true, "", "", true, nil, nil); err == nil {
		t.Fatal("SAML accepted --password-stdin")
	}
}

func TestReadMaskedPasswordShowsStarsAndHandlesBackspace(t *testing.T) {
	var prompt bytes.Buffer
	password, err := readMaskedPassword(strings.NewReader("abc\x7fd\r"), &prompt)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := password, "abd"; got != want {
		t.Fatalf("password = %q, want %q", got, want)
	}
	if got, want := prompt.String(), "***\b \b*"; got != want {
		t.Fatalf("mask = %q, want %q", got, want)
	}
}

func TestReadMaskedPasswordCancelsOnControlC(t *testing.T) {
	_, err := readMaskedPassword(strings.NewReader("\x03"), io.Discard)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}
