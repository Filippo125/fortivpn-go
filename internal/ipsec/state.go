package ipsec

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/Filippo125/fortivpn-go/internal/network"
	"github.com/Filippo125/fortivpn-go/internal/session"
	"github.com/strongswan/govici/vici"
)

func text(m *vici.Message, key string) string   { v, _ := m.Get(key).(string); return v }
func list(m *vici.Message, key string) []string { v, _ := m.Get(key).([]string); return v }

func (b *Backend) info(name string, messages []*vici.Message) (session.Info, error) {
	for _, message := range messages {
		sa, ok := message.Get(name).(*vici.Message)
		if !ok || text(sa, "state") != "ESTABLISHED" {
			continue
		}
		expectedHost := b.options.Gateway.String()
		if b.relay != nil {
			expectedHost = "127.0.0.1"
		}
		if text(sa, "remote-id") != b.options.RemoteID || text(sa, "remote-host") != expectedHost {
			return session.Info{}, errors.New("negotiated IPsec peer differs from the requested gateway")
		}
		cfg := &network.Config{}
		for _, raw := range list(sa, "local-vips") {
			addr, err := netip.ParseAddr(raw)
			if err != nil || addr.IsUnspecified() || addr.IsMulticast() {
				return session.Info{}, errors.New("invalid IPsec virtual address")
			}
			ip := &network.IPConfig{Address: netip.PrefixFrom(addr, addr.BitLen())}
			if addr.Is4() {
				if cfg.IPv4 != nil {
					return session.Info{}, errors.New("multiple IPv4 virtual addresses are unsupported")
				}
				cfg.IPv4 = ip
			} else {
				if cfg.IPv6 != nil {
					return session.Info{}, errors.New("multiple IPv6 virtual addresses are unsupported")
				}
				cfg.IPv6 = ip
			}
		}
		if cfg.IPv4 == nil || (b.options.IPMode == network.IPModeDualStack && cfg.IPv6 == nil) {
			return session.Info{}, errors.New("gateway did not install the requested IPsec address families")
		}
		if b.options.IPMode == network.IPModeIPv4 && cfg.IPv6 != nil {
			return session.Info{}, errors.New("unexpected IPv6 allocation")
		}
		children, ok := sa.Get("child-sas").(*vici.Message)
		if !ok {
			return session.Info{}, errors.New("no installed IPsec child SAs")
		}
		for i, requested := range b.options.Routes {
			found := false
			for _, key := range children.Keys() {
				child, ok := children.Get(key).(*vici.Message)
				if !ok || text(child, "name") != childName(name, i) {
					continue
				}
				state := text(child, "state")
				if state != "INSTALLED" && state != "REKEYING" && state != "REKEYED" {
					continue
				}
				if text(child, "mode") != "TUNNEL" || text(child, "protocol") != "ESP" || text(child, "encap") != "yes" {
					return session.Info{}, errors.New("IPsec child is not an ESP tunnel using NAT-T")
				}
				vip := cfg.IPv4
				if requested.Addr().Is6() {
					vip = cfg.IPv6
				}
				locals := list(child, "local-ts")
				if len(locals) != 1 || vip == nil || locals[0] != vip.Address.String() {
					return session.Info{}, errors.New("IPsec local selector does not match the assigned address")
				}
				remotes := list(child, "remote-ts")
				if len(remotes) == 0 {
					return session.Info{}, errors.New("missing IPsec remote selectors")
				}
				for _, raw := range remotes {
					p, err := netip.ParsePrefix(raw)
					if err != nil || p != p.Masked() || p.Bits() < requested.Bits() || !requested.Contains(p.Addr()) {
						return session.Info{}, errors.New("IPsec remote selector exceeds the requested split route")
					}
					route := network.Route{Destination: p}
					if p.Addr().Is4() {
						cfg.Routes4 = appendRoute(cfg.Routes4, route)
					} else {
						cfg.Routes6 = appendRoute(cfg.Routes6, route)
					}
				}
				found = true
				break
			}
			if !found {
				return session.Info{}, fmt.Errorf("IPsec child %d is not installed", i)
			}
		}
		return session.Info{Gateway: b.options.Gateway.String(), Config: cfg}, nil
	}
	return session.Info{}, errors.New("no established IPsec session")
}
func appendRoute(routes []network.Route, r network.Route) []network.Route {
	for _, v := range routes {
		if v == r {
			return routes
		}
	}
	return append(routes, r)
}
