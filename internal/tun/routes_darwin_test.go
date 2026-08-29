//go:build darwin

package tun

import (
	"net/netip"
	"testing"

	"github.com/filippoferrazini/fortivpn-go/internal/network"
)

func TestNewRouteSpecPreservesFamilyAndPrefix(t *testing.T) {
	route := network.Route{Destination: netip.MustParsePrefix("2001:db8:10::/48")}
	spec, err := newRouteSpec("utun7", route)
	if err != nil {
		t.Fatal(err)
	}
	if !spec.ipv6 || spec.destination != "2001:db8:10::/48" || spec.device != "utun7" {
		t.Fatalf("route spec = %#v", spec)
	}
}
