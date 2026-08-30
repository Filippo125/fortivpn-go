//go:build !darwin

package tun

import (
	"context"
	"errors"

	"github.com/Filippo125/fortivpn-go/internal/network"
)

// ConfigureRoutes is unavailable where the native macOS utun implementation
// is unavailable.
func ConfigureRoutes(context.Context, string, []network.Route, []network.Route) (func() error, error) {
	return nil, errors.New("VPN route configuration is supported only on macOS")
}
