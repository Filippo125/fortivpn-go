//go:build !darwin && !linux

package tun

import (
	"context"
	"errors"

	"github.com/Filippo125/fortivpn-go/internal/network"
)

// ConfigureRoutes is unavailable where no native TUN implementation exists.
func ConfigureRoutes(context.Context, string, []network.Route, []network.Route) (func() error, error) {
	return nil, errors.New("VPN route configuration is supported only on macOS and Linux")
}
