// Package tun provides operating-system TUN devices for the packet engine.
package tun

import (
	"context"
	"errors"

	"github.com/filippoferrazini/fortivpn-go/internal/network"
)

// Device is a session-owned packet device. Read and Write use bare IP packets;
// platform-specific link framing is deliberately hidden by the implementation.
type Device interface {
	Name() string
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}

// Config describes interface addresses only. Routes and DNS remain separate so
// their lifecycle can be managed precisely by later milestones.
type Config struct {
	IPv4 *network.IPConfig
	IPv6 *network.IPConfig
	MTU  int
}

type Configurer interface {
	Configure(context.Context, Config) error
}

func IPVersion(packet []byte) int {
	if len(packet) == 0 {
		return 0
	}
	return int(packet[0] >> 4)
}

func ValidateConfig(config Config) error {
	if config.MTU < 0 || config.MTU > 65535 {
		return errors.New("MTU must be between 0 and 65535")
	}
	if config.IPv4 != nil && (!config.IPv4.Address.IsValid() || !config.IPv4.Address.Addr().Is4()) {
		return errors.New("IPv4 configuration requires an IPv4 prefix")
	}
	if config.IPv6 != nil && (!config.IPv6.Address.IsValid() || !config.IPv6.Address.Addr().Is6()) {
		return errors.New("IPv6 configuration requires an IPv6 prefix")
	}
	return nil
}
