package tunnel

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

func TestPacketEngineForwardsIPv4AndIPv6(t *testing.T) {
	device := newMemoryDevice([][]byte{{0x45, 0, 0, 0}, {0x60, 0, 0, 0}})
	transport := &memoryTunnel{incoming: [][]byte{{0x60, 0, 0, 0}, {0x45, 0, 0, 0}}}
	engine := PacketEngine{Device: device, Tunnel: transport}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := engine.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if !transport.connected {
		t.Fatal("tunnel was not connected")
	}
	if got, want := transport.written, [][]byte{{0x45, 0, 0, 0}, {0x60, 0, 0, 0}}; !samePackets(got, want) {
		t.Fatalf("packets written to tunnel = %x, want %x", got, want)
	}
	if got, want := device.writtenPackets(), [][]byte{{0x60, 0, 0, 0}, {0x45, 0, 0, 0}}; !samePackets(got, want) {
		t.Fatalf("packets written to device = %x, want %x", got, want)
	}
}

func TestPacketEngineRejectsNonIPPacket(t *testing.T) {
	device := newMemoryDevice([][]byte{{0x10, 0, 0, 0}})
	transport := &memoryTunnel{}
	err := (PacketEngine{Device: device, Tunnel: transport}).Run(context.Background())
	if !errors.Is(err, ErrUnsupportedPacket) {
		t.Fatalf("Run() error = %v, want unsupported packet", err)
	}
}

type memoryDevice struct {
	mu      sync.Mutex
	packets [][]byte
	written [][]byte
	closed  chan struct{}
	once    sync.Once
}

func newMemoryDevice(packets [][]byte) *memoryDevice {
	return &memoryDevice{packets: clonePackets(packets), closed: make(chan struct{})}
}

func (d *memoryDevice) Name() string { return "memory0" }

func (d *memoryDevice) Read(dst []byte) (int, error) {
	d.mu.Lock()
	if len(d.packets) != 0 {
		packet := d.packets[0]
		d.packets = d.packets[1:]
		d.mu.Unlock()
		return copy(dst, packet), nil
	}
	d.mu.Unlock()
	<-d.closed
	return 0, io.EOF
}

func (d *memoryDevice) Write(packet []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.written = append(d.written, append([]byte(nil), packet...))
	return len(packet), nil
}

func (d *memoryDevice) Close() error {
	d.once.Do(func() { close(d.closed) })
	return nil
}

func (d *memoryDevice) writtenPackets() [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return clonePackets(d.written)
}

type memoryTunnel struct {
	mu        sync.Mutex
	incoming  [][]byte
	written   [][]byte
	connected bool
	closed    chan struct{}
	once      sync.Once
}

func (t *memoryTunnel) Connect(context.Context) error {
	t.mu.Lock()
	t.connected = true
	if t.closed == nil {
		t.closed = make(chan struct{})
	}
	t.mu.Unlock()
	return nil
}

func (t *memoryTunnel) ReadPacket(_ context.Context, dst []byte) (int, error) {
	t.mu.Lock()
	if len(t.incoming) != 0 {
		packet := t.incoming[0]
		t.incoming = t.incoming[1:]
		t.mu.Unlock()
		return copy(dst, packet), nil
	}
	closed := t.closed
	t.mu.Unlock()
	<-closed
	return 0, io.EOF
}

func (t *memoryTunnel) WritePacket(_ context.Context, packet []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.written = append(t.written, append([]byte(nil), packet...))
	return nil
}

func (t *memoryTunnel) Close() error {
	t.mu.Lock()
	if t.closed == nil {
		t.closed = make(chan struct{})
	}
	closed := t.closed
	t.mu.Unlock()
	t.once.Do(func() { close(closed) })
	return nil
}

func clonePackets(packets [][]byte) [][]byte {
	cloned := make([][]byte, len(packets))
	for i, packet := range packets {
		cloned[i] = append([]byte(nil), packet...)
	}
	return cloned
}

func samePackets(got, want [][]byte) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if string(got[i]) != string(want[i]) {
			return false
		}
	}
	return true
}
