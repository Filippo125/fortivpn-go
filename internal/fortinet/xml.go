package fortinet

import (
	"bytes"
	"encoding/xml"
	"io"
	"net/netip"
	"strconv"
	"strings"

	"github.com/filippoferrazini/fortivpn-go/internal/network"
)

// ParseNetworkConfig accepts the XML variants emitted by FortiGate releases.
// Unknown elements are deliberately ignored so a new gateway field cannot make
// an otherwise valid connection fail.
func ParseNetworkConfig(data []byte) (*network.Config, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	config := &network.Config{}
	var stack []xmlFrame
	for {
		token, err := decoder.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		switch element := token.(type) {
		case xml.StartElement:
			name := strings.ToLower(element.Name.Local)
			attrs := attributes(element.Attr)
			family := familyOf(stack)
			if name == "ipv4" {
				family = 4
			} else if name == "ipv6" {
				family = 6
			}
			stack = append(stack, xmlFrame{name: name, attrs: attrs, family: family})
			if parseElement(config, name, attrs, frameNames(stack)) {
				markRoute(stack)
			}
		case xml.CharData:
			if len(stack) > 0 {
				parseText(config, stack[len(stack)-1].name, string(element))
			}
		case xml.EndElement:
			if len(stack) > 0 {
				frame := stack[len(stack)-1]
				if frame.name == "split-tunnel-info" && frame.routeCount == 0 && frame.attrs["negate"] != "1" {
					addDefaultRoute(config, frame.family)
				}
				stack = stack[:len(stack)-1]
			}
		}
	}
	return config, nil
}

type xmlFrame struct {
	name       string
	attrs      map[string]string
	family     int
	routeCount int
}

func familyOf(stack []xmlFrame) int {
	if len(stack) == 0 {
		return 0
	}
	return stack[len(stack)-1].family
}

func frameNames(stack []xmlFrame) []string {
	names := make([]string, len(stack))
	for index, frame := range stack {
		names[index] = frame.name
	}
	return names
}

func markRoute(stack []xmlFrame) {
	for index := len(stack) - 2; index >= 0; index-- {
		if stack[index].name == "split-tunnel-info" {
			stack[index].routeCount++
			return
		}
	}
}

func addDefaultRoute(config *network.Config, family int) {
	if family == 4 {
		config.Routes4 = appendUniqueRoute(config.Routes4, network.Route{Destination: netip.PrefixFrom(netip.IPv4Unspecified(), 0)})
	}
	if family == 6 {
		config.Routes6 = appendUniqueRoute(config.Routes6, network.Route{Destination: netip.PrefixFrom(netip.IPv6Unspecified(), 0)})
	}
}

func attributes(attrs []xml.Attr) map[string]string {
	result := make(map[string]string, len(attrs))
	for _, attr := range attrs {
		result[strings.ToLower(attr.Name.Local)] = strings.TrimSpace(attr.Value)
	}
	return result
}

func parseElement(config *network.Config, name string, attrs map[string]string, stack []string) bool {
	if name == "assigned-addr" || name == "assigned_addr" || name == "ip" {
		parseIPConfig(config, attrs, "ipv4", false)
		parseIPConfig(config, attrs, "ipv6", true)
		parseIPConfig(config, attrs, "ip", false)
		parseIPConfig(config, attrs, "addr", false)
	}
	if name == "dns" || name == "dns-server" || name == "dns_server" {
		for _, key := range []string{"ip", "ipv4", "ipv6", "addr", "address"} {
			if addr, err := netip.ParseAddr(attrs[key]); err == nil {
				config.DNS = appendUniqueAddr(config.DNS, addr)
			}
		}
		for _, key := range []string{"domain", "suffix", "search"} {
			if value := attrs[key]; value != "" {
				config.Domains = appendUniqueString(config.Domains, value)
			}
		}
	}
	if name == "split-dns" || name == "split_dns" {
		for _, domain := range strings.Split(attrs["domains"], ",") {
			if domain = strings.TrimSpace(domain); domain != "" {
				config.Domains = appendUniqueString(config.Domains, domain)
			}
		}
		for index := 1; index <= 9; index++ {
			if addr, err := netip.ParseAddr(attrs["dnsserver"+strconv.Itoa(index)]); err == nil {
				config.DNS = appendUniqueAddr(config.DNS, addr)
			}
		}
	}
	if name == "addr" || name == "route" || name == "routev4" || name == "routev6" {
		return parseRoute(config, attrs)
	}
	if name == "mtu" {
		if value, err := strconv.Atoi(attrs["value"]); err == nil && value > 0 {
			config.MTU = value
		}
	}
	if raw := attrs["mtu"]; raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value > 0 {
			config.MTU = value
		}
	}
	if strings.Contains(name, "tunnel") {
		for _, key := range []string{"value", "method", "methods", "type", "protocol"} {
			for _, method := range strings.FieldsFunc(attrs[key], func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
				config.TunnelMethods = appendUniqueMethod(config.TunnelMethods, network.TunnelMethod(method))
			}
		}
	}
	return false
}

func parseText(config *network.Config, name, raw string) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return
	}
	if name == "mtu" {
		if mtu, err := strconv.Atoi(value); err == nil && mtu > 0 {
			config.MTU = mtu
		}
	}
	if name == "tunnel-method" || name == "tunnelmethod" || name == "method" {
		config.TunnelMethods = appendUniqueMethod(config.TunnelMethods, network.TunnelMethod(value))
	}
}

func parseIPConfig(config *network.Config, attrs map[string]string, key string, forceV6 bool) {
	raw := attrs[key]
	if raw == "" {
		return
	}
	prefix, err := parsePrefix(raw, attrs["mask"], first(attrs, "prefix", "prefix-len", "prefixlen"))
	if err != nil {
		return
	}
	gateway := parseGateway(attrs, prefix.Addr().Is6())
	ip := &network.IPConfig{Address: prefix, Gateway: gateway}
	if forceV6 || prefix.Addr().Is6() {
		config.IPv6 = ip
	} else {
		config.IPv4 = ip
	}
}

func parseRoute(config *network.Config, attrs map[string]string) bool {
	raw := first(attrs, "ip", "dest", "destination", "network", "addr", "ipv4", "ipv6")
	if raw == "" {
		return false
	}
	prefix, err := parsePrefix(raw, first(attrs, "mask", "netmask"), first(attrs, "prefix", "prefix-len", "prefixlen"))
	if err != nil {
		return false
	}
	route := network.Route{Destination: prefix.Masked(), Gateway: parseGateway(attrs, prefix.Addr().Is6())}
	if prefix.Addr().Is6() {
		config.Routes6 = appendUniqueRoute(config.Routes6, route)
	} else {
		config.Routes4 = appendUniqueRoute(config.Routes4, route)
	}
	return true
}

func parsePrefix(raw, mask, prefixLength string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		return prefix, nil
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Prefix{}, err
	}
	bits := 32
	if addr.Is6() {
		bits = 128
	}
	if mask != "" {
		maskAddr, maskErr := netip.ParseAddr(mask)
		if maskErr == nil && maskAddr.BitLen() == bits {
			bits = maskBits(maskAddr)
		} else if value, valueErr := strconv.Atoi(mask); valueErr == nil {
			bits = value
		}
	} else if prefixLength != "" {
		if value, valueErr := strconv.Atoi(prefixLength); valueErr == nil {
			bits = value
		}
	}
	return netip.PrefixFrom(addr, bits), nil
}

func maskBits(mask netip.Addr) int {
	bytes := mask.AsSlice()
	bits := 0
	for _, value := range bytes {
		for bit := byte(0x80); bit != 0 && value&bit != 0; bit >>= 1 {
			bits++
		}
	}
	return bits
}

func parseGateway(attrs map[string]string, ipv6 bool) netip.Addr {
	keys := []string{"gateway", "gw"}
	if ipv6 {
		keys = append([]string{"gateway6", "gw6", "ipv6-gateway"}, keys...)
	} else {
		keys = append([]string{"gateway4", "gw4", "ipv4-gateway"}, keys...)
	}
	for _, key := range keys {
		if addr, err := netip.ParseAddr(attrs[key]); err == nil && addr.Is6() == ipv6 {
			return addr
		}
	}
	return netip.Addr{}
}

func first(values map[string]string, keys ...string) string {
	for _, key := range keys {
		if values[key] != "" {
			return values[key]
		}
	}
	return ""
}

func appendUniqueAddr(values []netip.Addr, value netip.Addr) []netip.Addr {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func appendUniqueMethod(values []network.TunnelMethod, value network.TunnelMethod) []network.TunnelMethod {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func appendUniqueRoute(values []network.Route, value network.Route) []network.Route {
	for _, existing := range values {
		if existing.Destination == value.Destination && existing.Gateway == value.Gateway {
			return values
		}
	}
	return append(values, value)
}
