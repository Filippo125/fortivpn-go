package sslvpn

import (
	"strings"
	"sync"

	"github.com/Filippo125/fortivpn-go/internal/network"
	"github.com/Filippo125/fortivpn-go/internal/tun"
)

// routeCleanupDevice removes session routes while the TUN interface still
// exists. PacketEngine closes its Device to release blocked reads, so a normal
// deferred cleanup would otherwise run too late on Linux.
type routeCleanupDevice struct {
	tun.Device
	cleanup        func() error
	onCleanupError func(error)
	once           sync.Once
	closeErr       error
}

func (d *routeCleanupDevice) Close() error {
	d.once.Do(func() {
		if d.cleanup != nil {
			if err := d.cleanup(); err != nil && d.onCleanupError != nil {
				d.onCleanupError(err)
			}
		}
		d.closeErr = d.Device.Close()
	})
	return d.closeErr
}

func hasTunnelMethod(config *network.Config, method network.TunnelMethod) bool {
	for _, candidate := range config.TunnelMethods {
		if candidate == method {
			return true
		}
	}
	return false
}

func tunnelMethods(config *network.Config) string {
	values := make([]string, 0, len(config.TunnelMethods))
	for _, method := range config.TunnelMethods {
		values = append(values, string(method))
	}
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ", ")
}
