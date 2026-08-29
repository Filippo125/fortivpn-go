//go:build darwin

package tun

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/filippoferrazini/fortivpn-go/internal/network"
)

// ConfigureRoutes installs the supplied split-tunnel routes through device.
// The returned cleanup function removes only the routes that this call added.
func ConfigureRoutes(ctx context.Context, device string, routes4, routes6 []network.Route) (func() error, error) {
	installed := make([]routeSpec, 0, len(routes4)+len(routes6))
	for _, route := range append(append([]network.Route{}, routes4...), routes6...) {
		spec, err := newRouteSpec(device, route)
		if err != nil {
			return nil, err
		}
		if containsRoute(installed, spec) {
			continue
		}
		if err := runRoute(ctx, "add", spec); err != nil {
			_ = removeRoutes(context.Background(), installed)
			return nil, err
		}
		installed = append(installed, spec)
	}
	return func() error { return removeRoutes(context.Background(), installed) }, nil
}

type routeSpec struct {
	destination string
	ipv6        bool
	device      string
}

func newRouteSpec(device string, route network.Route) (routeSpec, error) {
	if device == "" {
		return routeSpec{}, fmt.Errorf("route requires a TUN interface")
	}
	if !route.Destination.IsValid() {
		return routeSpec{}, fmt.Errorf("route requires a valid destination")
	}
	address := route.Destination.Addr()
	if !address.Is4() && !address.Is6() {
		return routeSpec{}, fmt.Errorf("unsupported route destination %s", route.Destination)
	}
	return routeSpec{destination: route.Destination.String(), ipv6: address.Is6(), device: device}, nil
}

func containsRoute(routes []routeSpec, want routeSpec) bool {
	for _, route := range routes {
		if route == want {
			return true
		}
	}
	return false
}

func removeRoutes(ctx context.Context, routes []routeSpec) error {
	var failures []string
	for index := len(routes) - 1; index >= 0; index-- {
		if err := runRoute(ctx, "delete", routes[index]); err != nil {
			failures = append(failures, err.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("remove VPN routes: %s", strings.Join(failures, "; "))
	}
	return nil
}

func runRoute(ctx context.Context, action string, route routeSpec) error {
	args := []string{"-n", action}
	if route.ipv6 {
		args = append(args, "-inet6")
	}
	args = append(args, "-net", route.destination, "-interface", route.device)
	command := exec.CommandContext(ctx, "/sbin/route", args...)
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
