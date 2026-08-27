// Package network contains the family-neutral VPN network model.
package network

import (
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
