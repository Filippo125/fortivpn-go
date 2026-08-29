package auth

import "testing"

func TestSAMLCallbackAddressUsesFortiGateFixedPort(t *testing.T) {
	if got, want := samlCallbackAddress, "127.0.0.1:8020"; got != want {
		t.Fatalf("SAML callback address = %q, want %q", got, want)
	}
}
