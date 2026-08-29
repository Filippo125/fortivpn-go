package network

import (
	"net/netip"
	"testing"
)

func TestForIPModeFiltersIPv4Configuration(t *testing.T) {
	config := &Config{
		IPv4:    &IPConfig{Address: netip.MustParsePrefix("10.20.1.2/32")},
		IPv6:    &IPConfig{Address: netip.MustParsePrefix("2001:db8::2/128")},
		DNS:     []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2606:4700:4700::1111")},
		Routes4: []Route{{Destination: netip.MustParsePrefix("10.20.0.0/16")}},
		Routes6: []Route{{Destination: netip.MustParsePrefix("2001:db8:20::/48")}},
	}
	selected, err := config.ForIPMode(IPModeIPv4)
	if err != nil {
		t.Fatal(err)
	}
	if selected.IPv4 == nil || selected.IPv6 != nil || len(selected.Routes6) != 0 || len(selected.DNS) != 1 || !selected.DNS[0].Is4() {
		t.Fatalf("IPv4 selection = %#v", selected)
	}
}

func TestForIPModeDualRequiresBothFamilies(t *testing.T) {
	_, err := (&Config{IPv4: &IPConfig{Address: netip.MustParsePrefix("10.20.1.2/32")}}).ForIPMode(IPModeDualStack)
	if err == nil {
		t.Fatal("dual stack selection succeeded without IPv6")
	}
}
