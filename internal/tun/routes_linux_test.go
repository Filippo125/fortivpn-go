//go:build linux

package tun

import (
	"net/netip"
	"testing"

	"github.com/Filippo125/fortivpn-go/internal/network"
)

func TestNewLinuxRouteSpecPreservesFamilyAndPrefix(t *testing.T) {
	route := network.Route{Destination: netip.MustParsePrefix("2001:db8:10::/48")}
	spec, err := newLinuxRouteSpec("tun7", route)
	if err != nil {
		t.Fatal(err)
	}
	if !spec.ipv6 || spec.destination != "2001:db8:10::/48" || spec.device != "tun7" {
		t.Fatalf("route spec = %#v", spec)
	}
}
