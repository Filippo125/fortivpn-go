package sslvpn

import (
	"context"
	"errors"
	"io"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/Filippo125/fortivpn-go/internal/auth"
	"github.com/Filippo125/fortivpn-go/internal/fortinet"
	"github.com/Filippo125/fortivpn-go/internal/network"
	"github.com/Filippo125/fortivpn-go/internal/tun"
	"github.com/Filippo125/fortivpn-go/internal/tunnel"
)

type testTransport struct {
	done       chan struct{}
	once       sync.Once
	closes     int
	connectErr error
}

func (t *testTransport) Connect(context.Context) error                   { return t.connectErr }
func (t *testTransport) ReadPacket(context.Context, []byte) (int, error) { <-t.done; return 0, io.EOF }
func (t *testTransport) WritePacket(context.Context, []byte) error       { return nil }
func (t *testTransport) Close() error                                    { t.closes++; t.once.Do(func() { close(t.done) }); return nil }

type testDevice struct {
	done         chan struct{}
	once         sync.Once
	steps        *[]string
	configureErr error
}

func (d *testDevice) Name() string                                { return "test0" }
func (d *testDevice) Read([]byte) (int, error)                    { <-d.done; return 0, io.EOF }
func (d *testDevice) Write(p []byte) (int, error)                 { return len(p), nil }
func (d *testDevice) Configure(context.Context, tun.Config) error { return d.configureErr }
func (d *testDevice) Close() error {
	*d.steps = append(*d.steps, "device")
	d.once.Do(func() { close(d.done) })
	return nil
}

func fixture() (*Backend, *testTransport, *testDevice, *[]string) {
	steps := []string{}
	transport := &testTransport{done: make(chan struct{})}
	device := &testDevice{done: make(chan struct{}), steps: &steps}
	b := &Backend{
		gateway: "vpn.example.test",
		allocate: func(context.Context) (*network.Config, error) {
			return &network.Config{TunnelMethods: []network.TunnelMethod{"tun"}}, nil
		},
		openTunnel:   func(context.Context, fortinet.Tunnel2Options) (tunnel.Tunnel, error) { return transport, nil },
		createDevice: func() (tun.Device, error) { return device, nil },
		configureRoutes: func(context.Context, string, []network.Route, []network.Route) (func() error, error) {
			return func() error { steps = append(steps, "routes"); return nil }, nil
		},
	}
	return b, transport, device, &steps
}

func TestConnectUnwindsFailedSetup(t *testing.T) {
	failure := errors.New("setup failed")
	for _, stage := range []string{"allocation", "method", "transport", "device", "configure", "routes", "canceled"} {
		t.Run(stage, func(t *testing.T) {
			b, transport, device, steps := fixture()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			wantCloses := 1
			var wantSteps []string
			switch stage {
			case "allocation":
				b.allocate = func(context.Context) (*network.Config, error) { return nil, failure }
				wantCloses = 0
			case "method":
				b.allocate = func(context.Context) (*network.Config, error) { return &network.Config{}, nil }
				wantCloses = 0
			case "transport":
				b.openTunnel = func(context.Context, fortinet.Tunnel2Options) (tunnel.Tunnel, error) { return nil, failure }
				wantCloses = 0
			case "device":
				b.createDevice = func() (tun.Device, error) { return nil, failure }
			case "configure":
				device.configureErr = failure
				wantSteps = []string{"device"}
			case "routes":
				b.configureRoutes = func(context.Context, string, []network.Route, []network.Route) (func() error, error) {
					return nil, failure
				}
				wantSteps = []string{"device"}
			case "canceled":
				original := b.configureRoutes
				b.configureRoutes = func(ctx context.Context, name string, r4, r6 []network.Route) (func() error, error) {
					cancel()
					return original(ctx, name, r4, r6)
				}
				wantSteps = []string{"routes", "device"}
			}
			active, err := b.Connect(ctx)
			if err == nil || active != nil {
				t.Fatalf("Connect = %v, %v", active, err)
			}
			if stage != "method" && stage != "canceled" && !errors.Is(err, failure) {
				t.Fatalf("error = %v", err)
			}
			if stage == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatalf("error = %v", err)
			}
			if transport.closes != wantCloses {
				t.Fatalf("transport closes = %d, want %d", transport.closes, wantCloses)
			}
			if len(*steps) != len(wantSteps) || (len(wantSteps) > 0 && !reflect.DeepEqual(*steps, wantSteps)) {
				t.Fatalf("cleanup = %v, want %v", *steps, wantSteps)
			}
		})
	}
}

func TestSessionLifecycle(t *testing.T) {
	for _, stop := range []string{"close-before-run", "cancel", "peer-loss", "engine-error", "close-during-run"} {
		t.Run(stop, func(t *testing.T) {
			b, transport, _, steps := fixture()
			setupCtx, setupCancel := context.WithCancel(context.Background())
			active, err := b.Connect(setupCtx)
			if err != nil {
				t.Fatal(err)
			}
			defer active.Close()
			setupCancel() // A setup deadline must not terminate the established session.
			if info := active.Info(); info.Gateway != b.gateway || info.Interface != "test0" || info.Config == nil {
				t.Fatalf("info = %+v", info)
			}
			if transport.closes != 0 {
				t.Fatal("setup cancellation closed the session")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			failure := errors.New("transport connect failed")
			switch stop {
			case "close-before-run":
				_ = active.Close()
			case "cancel":
				cancel()
			case "peer-loss":
				transport.once.Do(func() { close(transport.done) })
			case "engine-error":
				transport.connectErr = failure
			}
			if stop != "close-before-run" {
				done := make(chan error, 1)
				go func() { done <- active.Run(ctx) }()
				if stop == "close-during-run" {
					_ = active.Close()
				}
				select {
				case err := <-done:
					if stop == "engine-error" {
						if !errors.Is(err, failure) {
							t.Fatalf("error = %v", err)
						}
					} else if err != nil {
						t.Fatal(err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("session did not stop")
				}
			}
			if err := active.Close(); err != nil {
				t.Fatal(err)
			}
			if transport.closes != 1 {
				t.Fatalf("transport closed %d times", transport.closes)
			}
			if !reflect.DeepEqual(*steps, []string{"routes", "device"}) {
				t.Fatalf("cleanup = %v", *steps)
			}
		})
	}
}

func TestInspectAndProbeDoNotCreateLocalState(t *testing.T) {
	for _, probe := range []bool{false, true} {
		b, transport, _, steps := fixture()
		b.createDevice = func() (tun.Device, error) { t.Fatal("unexpected TUN creation"); return nil, nil }
		if probe {
			if err := b.Probe(context.Background()); err != nil {
				t.Fatal(err)
			}
		} else {
			if _, err := b.Inspect(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		want := 0
		if probe {
			want = 1
		}
		if transport.closes != want || len(*steps) != 0 {
			t.Fatalf("closes=%d cleanup=%v", transport.closes, *steps)
		}
	}
}

type failingAuthenticator struct {
	result *auth.AuthResult
	err    error
}

func (a failingAuthenticator) Authenticate(context.Context, *fortinet.Client) (*auth.AuthResult, error) {
	return a.result, a.err
}
func TestAuthenticationFailureClearsResult(t *testing.T) {
	failure := errors.New("authentication rejected")
	result := &auth.AuthResult{SessionID: auth.Secret("secret")}
	b, err := New(Options{Client: fortinet.ClientOptions{Gateway: "vpn.example.test"}, Authenticator: failingAuthenticator{result, failure}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Connect(context.Background()); !errors.Is(err, failure) {
		t.Fatalf("error = %v", err)
	}
	if result.SessionID != "" {
		t.Fatal("authentication result was retained")
	}
}
