package sslvpn

import (
	"reflect"
	"testing"

	"github.com/Filippo125/fortivpn-go/internal/network"
	"github.com/Filippo125/fortivpn-go/internal/tun"
)

func TestTunnelMethods(t *testing.T) {
	config := &network.Config{TunnelMethods: []network.TunnelMethod{"websocket", "tun"}}
	if !hasTunnelMethod(config, "tun") {
		t.Fatal("TUN transport was not found")
	}
	if got, want := tunnelMethods(config), "websocket, tun"; got != want {
		t.Fatalf("tunnel methods = %q, want %q", got, want)
	}
}

func TestRouteCleanupDeviceCleansRoutesBeforeClosingDevice(t *testing.T) {
	var steps []string
	device := &recordingDevice{close: func() error {
		steps = append(steps, "close")
		return nil
	}}
	managed := &routeCleanupDevice{
		Device: device,
		cleanup: func() error {
			steps = append(steps, "cleanup")
			return nil
		},
	}
	if err := managed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := managed.Close(); err != nil {
		t.Fatal(err)
	}
	if want := []string{"cleanup", "close"}; !reflect.DeepEqual(steps, want) {
		t.Fatalf("close steps = %q, want %q", steps, want)
	}
}

type recordingDevice struct {
	close func() error
}

func (d *recordingDevice) Name() string              { return "test0" }
func (d *recordingDevice) Read([]byte) (int, error)  { return 0, nil }
func (d *recordingDevice) Write([]byte) (int, error) { return 0, nil }
func (d *recordingDevice) Close() error              { return d.close() }

var _ tun.Device = (*recordingDevice)(nil)
