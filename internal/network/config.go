// Package network contains the family-neutral VPN network model.
package network

import (
	"errors"
	"fmt"
	"net/netip"
)

type IPMode string

const (
	IPModeAuto      IPMode = "auto"
	IPModeIPv4      IPMode = "ipv4"
	IPModeIPv6      IPMode = "ipv6"
	IPModeDualStack IPMode = "dual"
)

type IPConfig struct {
	Address netip.Prefix
	Gateway netip.Addr
}

type Route struct {
	Destination netip.Prefix
	Gateway     netip.Addr
}

func (r Route) String() string {
	if r.Gateway.IsValid() {
		return fmt.Sprintf("%s via %s", r.Destination, r.Gateway)
	}
	return r.Destination.String()
}

type TunnelMethod string

type Config struct {
	IPv4 *IPConfig
	IPv6 *IPConfig

	DNS     []netip.Addr
	Domains []string

	Routes4 []Route
	Routes6 []Route

	MTU           int
	TunnelMethods []TunnelMethod
}

func (c *Config) Empty() bool {
	return c.IPv4 == nil && c.IPv6 == nil && len(c.DNS) == 0 && len(c.Domains) == 0 &&
		len(c.Routes4) == 0 && len(c.Routes6) == 0 && c.MTU == 0 && len(c.TunnelMethods) == 0
}

// ForIPMode returns a copy of c restricted to the requested address family.
// Auto preserves all configuration supplied by the gateway, while DualStack
// rejects an allocation that does not contain both address families.
func (c *Config) ForIPMode(mode IPMode) (*Config, error) {
	if c == nil {
		return nil, errors.New("network configuration is nil")
	}
	selected := *c
	switch mode {
	case IPModeAuto:
		return &selected, nil
	case IPModeIPv4:
		if c.IPv4 == nil {
			return nil, errors.New("gateway did not assign an IPv4 address")
		}
		selected.IPv6 = nil
		selected.Routes6 = nil
		selected.DNS = filterAddrs(c.DNS, false)
		return &selected, nil
	case IPModeIPv6:
		if c.IPv6 == nil {
			return nil, errors.New("gateway did not assign an IPv6 address")
		}
		selected.IPv4 = nil
		selected.Routes4 = nil
		selected.DNS = filterAddrs(c.DNS, true)
		return &selected, nil
	case IPModeDualStack:
		if c.IPv4 == nil || c.IPv6 == nil {
			return nil, errors.New("gateway did not assign both IPv4 and IPv6 addresses")
		}
		return &selected, nil
	default:
		return nil, fmt.Errorf("unsupported IP mode %q", mode)
	}
}

func filterAddrs(addrs []netip.Addr, ipv6 bool) []netip.Addr {
	selected := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		if addr.IsValid() && addr.Is6() == ipv6 {
			selected = append(selected, addr)
		}
	}
	return selected
}
