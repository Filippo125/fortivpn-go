package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompleteInstancesPrintsCanonicalSelectors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fortivpn.yaml")
	body := `
groups:
  company: {}
instances:
  - name: secondary
    gateway: secondary.example.test
  - name: production
    group: company
    gateway: vpn.example.test
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run([]string{"__complete-instances", "--config", path}, &output); err != nil {
		t.Fatal(err)
	}
	if got, want := output.String(), "company\\production\nsecondary\n"; got != want {
		t.Fatalf("completion output = %q, want %q", got, want)
	}
}

func TestCompletionSupportsCommonShells(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		t.Run(shell, func(t *testing.T) {
			var output bytes.Buffer
			if err := run([]string{"completion", shell}, &output); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output.String(), "instance") || !strings.Contains(output.String(), "__complete-instances") {
				t.Fatalf("completion script for %s is incomplete", shell)
			}
		})
	}
}
