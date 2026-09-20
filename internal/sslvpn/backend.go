// Package sslvpn owns FortiGate SSL-VPN authentication, allocation, transport,
// and local network state. None of its authentication options apply to IPsec.
package sslvpn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/Filippo125/fortivpn-go/internal/auth"
	"github.com/Filippo125/fortivpn-go/internal/fortinet"
	"github.com/Filippo125/fortivpn-go/internal/network"
	"github.com/Filippo125/fortivpn-go/internal/session"
	"github.com/Filippo125/fortivpn-go/internal/tun"
	"github.com/Filippo125/fortivpn-go/internal/tunnel"
)

// Options are SSL-VPN-specific; Authenticator intentionally remains outside the
// protocol-neutral session contract. Callbacks run synchronously during setup.
type Options struct {
	Client          fortinet.ClientOptions
	Authenticator   auth.Authenticator
	IPMode          network.IPMode
	DebugWriter     io.Writer
	OnAuthenticated func()
	OnCleanupError  func(error)
}

type Backend struct {
	gateway         string
	allocate        func(context.Context) (*network.Config, error)
	openTunnel      func(context.Context, fortinet.Tunnel2Options) (tunnel.Tunnel, error)
	createDevice    func() (tun.Device, error)
	configureRoutes func(context.Context, string, []network.Route, []network.Route) (func() error, error)
	onCleanupError  func(error)
}

var _ session.Backend = (*Backend)(nil)

func New(options Options) (*Backend, error) {
	if options.Authenticator == nil {
		return nil, errors.New("SSL-VPN requires an authenticator")
	}
	client, err := fortinet.NewClient(options.Client)
	if err != nil {
		return nil, err
	}
	if options.DebugWriter != nil {
		client.SetDebugWriter(options.DebugWriter)
	}
	mode := options.IPMode
	if mode == "" {
		mode = network.IPModeAuto
	}
	return &Backend{
		gateway: client.Gateway(),
		allocate: func(ctx context.Context) (*network.Config, error) {
			result, err := options.Authenticator.Authenticate(ctx, client)
			if result != nil {
				defer result.Clear()
			}
			if err != nil {
				return nil, err
			}
			if options.OnAuthenticated != nil {
				options.OnAuthenticated()
			}
			return client.NetworkConfigForIPMode(ctx, mode)
		},
		openTunnel: func(ctx context.Context, options fortinet.Tunnel2Options) (tunnel.Tunnel, error) {
			return client.OpenTunnel2(ctx, options)
		},
		createDevice:    tun.Create,
		configureRoutes: tun.ConfigureRoutes,
		onCleanupError:  options.OnCleanupError,
	}, nil
}

func (b *Backend) Gateway() string { return b.gateway }

// Inspect authenticates and reads allocation without installing local state.
func (b *Backend) Inspect(ctx context.Context) (*network.Config, error) { return b.allocate(ctx) }

// Probe checks only the SSL-VPN transport handshake, without a packet engine.
func (b *Backend) Probe(ctx context.Context) error {
	config, err := b.allocate(ctx)
	if err != nil {
		return err
	}
	transport, err := b.openTunnel(ctx, fortinet.Tunnel2Options{DNS: config.DNS})
	if err != nil {
		return err
	}
	defer transport.Close()
	return nil
}

func (b *Backend) Connect(ctx context.Context) (_ session.Session, err error) {
	config, err := b.allocate(ctx)
	if err != nil {
		return nil, err
	}
	if !hasTunnelMethod(config, network.TunnelMethod("tun")) {
		return nil, fmt.Errorf("gateway does not offer the TUN transport (offers: %s)", tunnelMethods(config))
	}
	transport, err := b.openTunnel(ctx, fortinet.Tunnel2Options{DNS: config.DNS})
	if err != nil {
		return nil, err
	}
	s := &connection{info: session.Info{Gateway: b.gateway, Config: config}, transport: transport}
	defer func() {
		if err != nil {
			_ = s.Close()
		}
	}()
	device, err := b.createDevice()
	if err != nil {
		return nil, err
	}
	managed := &routeCleanupDevice{Device: device, onCleanupError: b.onCleanupError}
	s.device = managed
	configurer, ok := device.(tun.Configurer)
	if !ok {
		return nil, errors.New("native TUN implementation cannot configure the interface")
	}
	if err = configurer.Configure(ctx, tun.Config{IPv4: config.IPv4, IPv6: config.IPv6, MTU: config.MTU}); err != nil {
		return nil, err
	}
	managed.cleanup, err = b.configureRoutes(ctx, device.Name(), config.Routes4, config.Routes6)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	s.info.Interface = device.Name()
	return s, nil
}

type connection struct {
	info      session.Info
	transport tunnel.Tunnel
	device    *routeCleanupDevice
	once      sync.Once
	closeErr  error
}

func (s *connection) Info() session.Info { return s.info }
func (s *connection) Run(ctx context.Context) error {
	defer s.Close()
	// PacketEngine owns closure while running. The transport wrapper funnels
	// those calls through the session's single teardown owner.
	return (tunnel.PacketEngine{Device: s.device, Tunnel: &sessionTransport{Tunnel: s.transport, close: s.Close}}).Run(ctx)
}
func (s *connection) Close() error {
	s.once.Do(func() {
		s.closeErr = s.transport.Close()
		if s.device != nil {
			s.closeErr = errors.Join(s.closeErr, s.device.Close())
		}
	})
	return s.closeErr
}

type sessionTransport struct {
	tunnel.Tunnel
	close func() error
}

func (t *sessionTransport) Close() error { return t.close() }
