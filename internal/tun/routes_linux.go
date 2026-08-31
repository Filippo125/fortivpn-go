//go:build linux

package tun

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/Filippo125/fortivpn-go/internal/network"
)

// ConfigureRoutes installs the supplied split-tunnel routes through device.
// The returned cleanup function removes only the routes that this call added.
func ConfigureRoutes(ctx context.Context, device string, routes4, routes6 []network.Route) (func() error, error) {
	installed := make([]linuxRouteSpec, 0, len(routes4)+len(routes6))
	for _, route := range append(append([]network.Route{}, routes4...), routes6...) {
		spec, err := newLinuxRouteSpec(device, route)
		if err != nil {
			return nil, err
		}
		if containsLinuxRoute(installed, spec) {
			continue
		}
		if err := runLinuxRoute(ctx, "add", spec); err != nil {
			_ = removeLinuxRoutes(context.Background(), installed)
			return nil, err
		}
		installed = append(installed, spec)
	}
	return func() error { return removeLinuxRoutes(context.Background(), installed) }, nil
}

type linuxRouteSpec struct {
	destination string
	ipv6        bool
	device      string
}

func newLinuxRouteSpec(device string, route network.Route) (linuxRouteSpec, error) {
	if device == "" {
		return linuxRouteSpec{}, fmt.Errorf("route requires a TUN interface")
	}
	if !route.Destination.IsValid() {
		return linuxRouteSpec{}, fmt.Errorf("route requires a valid destination")
	}
	address := route.Destination.Addr()
	if !address.Is4() && !address.Is6() {
		return linuxRouteSpec{}, fmt.Errorf("unsupported route destination %s", route.Destination)
	}
	return linuxRouteSpec{destination: route.Destination.String(), ipv6: address.Is6(), device: device}, nil
}

func containsLinuxRoute(routes []linuxRouteSpec, want linuxRouteSpec) bool {
	for _, route := range routes {
		if route == want {
			return true
		}
	}
	return false
}

func removeLinuxRoutes(ctx context.Context, routes []linuxRouteSpec) error {
	var failures []string
	for index := len(routes) - 1; index >= 0; index-- {
		if err := runLinuxRoute(ctx, "delete", routes[index]); err != nil {
			failures = append(failures, err.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("remove VPN routes: %s", strings.Join(failures, "; "))
	}
	return nil
}

func runLinuxRoute(ctx context.Context, action string, route linuxRouteSpec) error {
	args := []string{"-4", "route", action, route.destination, "dev", route.device}
	if route.ipv6 {
		args[0] = "-6"
	}
	command := exec.CommandContext(ctx, "ip", args...)
	output, err := command.CombinedOutput()
	if err == nil {
		return nil
	}
	message := strings.TrimSpace(string(output))
	if message == "" {
		return fmt.Errorf("%s route %s via %s: %w", action, route.destination, route.device, err)
	}
	return fmt.Errorf("%s route %s via %s: %w: %s", action, route.destination, route.device, err, message)
}
