package main

import (
	"bytes"
	"context"
	"errors"
	"io"
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

func TestTunnelMethods(t *testing.T) {
	config := &network.Config{TunnelMethods: []network.TunnelMethod{"websocket", "tun"}}
	if !hasTunnelMethod(config, "tun") {
		t.Fatal("TUN transport was not found")
	}
	if got, want := tunnelMethods(config), "websocket, tun"; got != want {
		t.Fatalf("tunnel methods = %q, want %q", got, want)
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
