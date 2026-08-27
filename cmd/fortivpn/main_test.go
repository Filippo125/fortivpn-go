package main

import (
	"bytes"
	"strings"
	"testing"
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
