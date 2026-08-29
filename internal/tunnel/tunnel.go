// Package tunnel contains the session-scoped VPN packet engine.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/filippoferrazini/fortivpn-go/internal/tun"
)

const defaultPacketBufferSize = 65535

var ErrUnsupportedPacket = errors.New("packet is neither IPv4 nor IPv6")

// Tunnel is a session-owned transport for unmodified IP packets. Concrete
// implementations encapsulate packets using a FortiGate tunnel protocol; the
// packet engine deliberately does not care whether the transport is TLS, DTLS,
// or WebSocket.
type Tunnel interface {
	Connect(context.Context) error
	ReadPacket(context.Context, []byte) (int, error)
	WritePacket(context.Context, []byte) error
	Close() error
}

// PacketEngine copies raw IPv4 and IPv6 packets between one operating-system
// device and one FortiGate transport. It owns both ends for the duration of
// Run, so cancellation always tears down the whole session rather than leaving
// a goroutine blocked in a device read.
type PacketEngine struct {
	Device     tun.Device
	Tunnel     Tunnel
	BufferSize int
}

func (e PacketEngine) Run(ctx context.Context) error {
	if e.Device == nil {
		return errors.New("packet engine requires a TUN device")
	}
	if e.Tunnel == nil {
		return errors.New("packet engine requires a tunnel")
	}
	if e.BufferSize < 0 {
		return errors.New("packet buffer size cannot be negative")
	}

	bufferSize := e.BufferSize
	if bufferSize == 0 {
		bufferSize = defaultPacketBufferSize
	}
	if bufferSize < 1 {
		return errors.New("packet buffer size must be positive")
	}

	if err := e.Tunnel.Connect(ctx); err != nil {
		return fmt.Errorf("connect FortiGate tunnel: %w", err)
	}

	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, 2)
	var closeOnce sync.Once
	closeAll := func() {
		closeOnce.Do(func() {
			_ = e.Tunnel.Close()
			_ = e.Device.Close()
		})
	}
	defer closeAll()

	go func() { results <- copyDeviceToTunnel(childCtx, e.Device, e.Tunnel, bufferSize) }()
	go func() { results <- copyTunnelToDevice(childCtx, e.Tunnel, e.Device, bufferSize) }()

	select {
	case <-ctx.Done():
		closeAll()
		return nil
	case err := <-results:
		closeAll()
		if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
}

func copyDeviceToTunnel(ctx context.Context, device tun.Device, transport Tunnel, bufferSize int) error {
	packet := make([]byte, bufferSize)
	for {
		n, err := device.Read(packet)
		if err != nil {
			return fmt.Errorf("read %s: %w", device.Name(), err)
		}
		if err := validatePacket(packet[:n]); err != nil {
			return fmt.Errorf("read %s: %w", device.Name(), err)
		}
		if err := transport.WritePacket(ctx, packet[:n]); err != nil {
			return fmt.Errorf("write FortiGate tunnel: %w", err)
		}
	}
}

func copyTunnelToDevice(ctx context.Context, transport Tunnel, device tun.Device, bufferSize int) error {
	packet := make([]byte, bufferSize)
	for {
		n, err := transport.ReadPacket(ctx, packet)
		if err != nil {
			return fmt.Errorf("read FortiGate tunnel: %w", err)
		}
		if err := validatePacket(packet[:n]); err != nil {
			return fmt.Errorf("read FortiGate tunnel: %w", err)
		}
		written, err := device.Write(packet[:n])
		if err != nil {
			return fmt.Errorf("write %s: %w", device.Name(), err)
		}
		if written != n {
			return fmt.Errorf("write %s: %w", device.Name(), io.ErrShortWrite)
		}
	}
}

func validatePacket(packet []byte) error {
	switch tun.IPVersion(packet) {
	case 4, 6:
		return nil
	default:
		return ErrUnsupportedPacket
	}
}
