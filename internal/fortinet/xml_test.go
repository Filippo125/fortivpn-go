package fortinet

import "testing"

func TestParseNetworkConfigDualStack(t *testing.T) {
	xml := []byte(`<sslvpn mtu="1420"><assigned-addr ipv4="10.20.4.12/32" ipv6="2001:db8:1234::12/128" gateway4="10.20.4.1" gateway6="2001:db8:1234::1"/><dns ip="10.20.0.53" domain="corp.example"/><dns ip="2001:db8::53"/><split-dns domains="private.example, apps.example" dnsserver1="10.20.0.54"/><split-tunnel-info><addr ip="10.40.0.0" mask="255.255.0.0"/><addr ip="2001:db8:4000::" prefix="48"/></split-tunnel-info><tunnel-method value="websocket"/><tunnel-method>tun</tunnel-method></sslvpn>`)
	config, err := ParseNetworkConfig(xml)
	if err != nil {
		t.Fatal(err)
	}
	if config.IPv4 == nil || config.IPv4.Address.String() != "10.20.4.12/32" {
		t.Fatalf("IPv4 = %#v", config.IPv4)
	}
	if config.IPv6 == nil || config.IPv6.Address.String() != "2001:db8:1234::12/128" {
		t.Fatalf("IPv6 = %#v", config.IPv6)
	}
	if len(config.DNS) != 3 || len(config.Domains) != 3 || len(config.Routes4) != 1 || len(config.Routes6) != 1 {
		t.Fatalf("config = %#v", config)
	}
	if config.MTU != 1420 || len(config.TunnelMethods) != 2 {
		t.Fatalf("metadata = %#v", config)
	}
}

func TestParseNetworkConfigIPv6Only(t *testing.T) {
	config, err := ParseNetworkConfig([]byte(`<sslvpn><assigned-addr ipv6="2001:db8:3::8" prefix-len="120"/></sslvpn>`))
	if err != nil {
		t.Fatal(err)
	}
	if config.IPv4 != nil || config.IPv6 == nil || config.IPv6.Address.String() != "2001:db8:3::8/120" {
		t.Fatalf("config = %#v", config)
	}
}

func TestParseNetworkConfigEmptySplitTunnelMeansDefaultRoute(t *testing.T) {
	config, err := ParseNetworkConfig([]byte(`<sslvpn><ipv4><split-tunnel-info/></ipv4><ipv6><split-tunnel-info/></ipv6></sslvpn>`))
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Routes4) != 1 || config.Routes4[0].Destination.String() != "0.0.0.0/0" {
		t.Fatalf("IPv4 routes = %#v", config.Routes4)
	}
	if len(config.Routes6) != 1 || config.Routes6[0].Destination.String() != "::/0" {
		t.Fatalf("IPv6 routes = %#v", config.Routes6)
	}
}

func TestParseNetworkConfigDoesNotInferRouteForNegatedEmptySplitTunnel(t *testing.T) {
	config, err := ParseNetworkConfig([]byte(`<sslvpn><ipv6><split-tunnel-info negate="1"/></ipv6></sslvpn>`))
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Routes6) != 0 {
		t.Fatalf("IPv6 routes = %#v", config.Routes6)
	}
}
