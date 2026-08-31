//go:build linux

package tun

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/Filippo125/fortivpn-go/internal/network"
)

func TestLinuxAddressArgs(t *testing.T) {
	config := network.IPConfig{
		Address: netip.MustParsePrefix("10.20.4.12/32"),
		Gateway: netip.MustParseAddr("10.20.4.1"),
	}
	want := []string{"-4", "address", "add", "10.20.4.12/32", "peer", "10.20.4.1", "dev", "tun0"}
	if got := linuxAddressArgs(config, "tun0", false); !reflect.DeepEqual(got, want) {
		t.Fatalf("linuxAddressArgs() = %q, want %q", got, want)
	}
}

func TestLinuxAddressArgsIPv6WithoutPeer(t *testing.T) {
	config := network.IPConfig{Address: netip.MustParsePrefix("2001:db8::12/128")}
	want := []string{"-6", "address", "add", "2001:db8::12/128", "dev", "tun0"}
	if got := linuxAddressArgs(config, "tun0", true); !reflect.DeepEqual(got, want) {
		t.Fatalf("linuxAddressArgs() = %q, want %q", got, want)
	}
}
