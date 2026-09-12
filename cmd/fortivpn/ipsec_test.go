package main

import (
	"bytes"
	"testing"
)

func TestIPsecDoesNotAcceptSSLVPNOptions(t *testing.T) {
	var out bytes.Buffer
	err := run([]string{"ipsec", "connect", "--insecure"}, &out)
	if err == nil {
		t.Fatal("accepted SSL-VPN certificate bypass")
	}
}
