package ipsec

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Filippo125/fortivpn-go/internal/network"
	"github.com/strongswan/govici/vici"
)

func options() Options {
	return Options{Gateway: netip.MustParseAddr("192.0.2.1"), RemoteID: "192.0.2.1", Username: "alice", Password: Secret("test-password"), PSK: Secret("test-psk"), IPMode: network.IPModeIPv4}
}
func msg(values map[string]any) *vici.Message {
	m, err := vici.MarshalMessage(values)
	if err != nil {
		panic(err)
	}
	return m
}
func state(name string) *vici.Message {
	return msg(map[string]any{name: map[string]any{
		"state": "ESTABLISHED", "remote-id": "192.0.2.1", "remote-host": "192.0.2.1", "local-vips": []string{"10.250.0.10"},
		"child-sas": map[string]any{"child-1": map[string]any{"name": childName(name, 0), "state": "INSTALLED", "mode": "TUNNEL", "protocol": "ESP", "encap": "yes", "local-ts": []string{"10.250.0.10/32"}, "remote-ts": []string{"10.1.0.0/24"}}},
	}})
}

type fakeControl struct {
	calls    []string
	args     []map[string]any
	name     string
	fail     string
	failure  error
	canceled bool
	mutate   func(*vici.Message)
}

func (f *fakeControl) call(ctx context.Context, cmd string, args map[string]any) (*vici.Message, error) {
	f.calls = append(f.calls, cmd)
	f.args = append(f.args, args)
	if cmd == "stats" {
		return msg(map[string]any{"plugins": []string{"eap-mschapv2", "eap-identity", "vici", "kernel-netlink"}}), nil
	}
	if cmd == "load-conn" {
		for key := range args {
			f.name = key
		}
	}
	if cmd == f.fail {
		return nil, f.failure
	}
	if strings.HasPrefix(cmd, "unload") || cmd == "terminate" {
		if ctx.Err() != nil {
			f.canceled = true
		}
	}
	return msg(map[string]any{"success": "yes"}), nil
}
func (f *fakeControl) list(context.Context, string) ([]*vici.Message, error) {
	m := state(f.name)
	if f.mutate != nil {
		f.mutate(m)
	}
	return []*vici.Message{m}, nil
}

func TestValidateRejectsUnsafeAndUnsupportedOptions(t *testing.T) {
	cases := map[string]func(*Options){
		"unknown-transport": func(o *Options) { o.Transport = "https" },
		"tcp-port-with-udp": func(o *Options) { o.TCPPort = 443 },
		"wildcard":          func(o *Options) { o.RemoteID = "%any" },
		"missing-id":        func(o *Options) { o.RemoteID = "" },
		"ipv6-only":         func(o *Options) { o.IPMode = network.IPModeIPv6 },
		"secret-newline":    func(o *Options) { o.Password = "hidden\nsecret" },
		"relative-socket":   func(o *Options) { o.SocketPath = "local.vici" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			o := options()
			mutate(&o)
			if err := o.Validate(); err == nil {
				t.Fatal("accepted invalid configuration")
			}
		})
	}
}

func TestConfigProposesBroadSelectorsForNegotiatedRoutes(t *testing.T) {
	o := options()
	o.IPMode = network.IPModeDualStack
	b, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	connection := b.config("test")["test"].(map[string]any)
	children := connection["children"].(map[string]any)
	if len(children) != 2 {
		t.Fatalf("children = %#v", children)
	}
	want := []string{"0.0.0.0/0", "::/0"}
	for i, selector := range want {
		child := children[childName("test", i)].(map[string]any)
		got := child["remote_ts"].([]string)
		if !reflect.DeepEqual(got, []string{selector}) {
			t.Fatalf("child %d remote_ts = %#v", i, got)
		}
	}
}

func TestAcceptsNegotiatedDualStackRoutes(t *testing.T) {
	o := options()
	o.IPMode = network.IPModeDualStack
	b, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	m := state("test")
	sa := m.Get("test").(*vici.Message)
	_ = sa.Set("local-vips", []string{"10.250.0.10", "2001:db8:200::10"})
	children := sa.Get("child-sas").(*vici.Message)
	_ = children.Set("child-2", map[string]any{
		"name":      childName("test", 1),
		"state":     "INSTALLED",
		"mode":      "TUNNEL",
		"protocol":  "ESP",
		"encap":     "yes",
		"local-ts":  []string{"2001:db8:200::10/128"},
		"remote-ts": []string{"::/0"},
	})
	info, err := b.info("test", []*vici.Message{m})
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Config.Routes4) != 1 || len(info.Config.Routes6) != 1 || info.Config.Routes6[0].Destination.String() != "::/0" {
		t.Fatalf("negotiated routes = IPv4 %v, IPv6 %v", info.Config.Routes4, info.Config.Routes6)
	}
}
func TestConnectAndCloseOwnOnlyNamedResources(t *testing.T) {
	b, _ := New(options())
	f := &fakeControl{}
	b.control = f
	s, err := b.Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s.Info().Config.IPv4.Address.String() != "10.250.0.10/32" || s.Info().Config.Routes4[0].Destination.String() != "10.1.0.0/24" {
		t.Fatal(s.Info())
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	want := []string{"stats", "get-conns", "get-shared", "load-shared", "load-shared", "load-conn", "initiate", "terminate", "unload-conn", "unload-shared", "unload-shared"}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("calls = %v", f.calls)
	}
	for i, cmd := range f.calls {
		switch cmd {
		case "terminate":
			if f.args[i]["ike"] != f.name {
				t.Fatal("wrong SA terminated")
			}
		case "unload-conn":
			if f.args[i]["name"] != f.name {
				t.Fatal("wrong config unloaded")
			}
		case "unload-shared":
			if !strings.HasPrefix(f.args[i]["id"].(string), f.name+"-") {
				t.Fatal("wrong credential unloaded")
			}
		}
	}
}
func TestSetupFailureCleansWithIndependentContextAndRedactsErrors(t *testing.T) {
	for _, stage := range []string{"load-shared", "load-conn", "initiate"} {
		t.Run(stage, func(t *testing.T) {
			b, _ := New(options())
			failure := fmt.Errorf("rejected %s %s: %w", string(b.options.Password), string(b.options.PSK), context.Canceled)
			f := &fakeControl{fail: stage, failure: failure}
			b.control = f
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			s, err := b.Connect(ctx)
			if err == nil || s != nil || !errors.Is(err, context.Canceled) {
				t.Fatalf("Connect = %v, %v", s, err)
			}
			if strings.Contains(err.Error(), string(b.options.Password)) || strings.Contains(err.Error(), string(b.options.PSK)) {
				t.Fatal("error exposed credentials")
			}
			if f.canceled {
				t.Fatal("cleanup reused canceled context")
			}
			if f.calls[len(f.calls)-1] != "unload-shared" {
				t.Fatalf("cleanup calls = %v", f.calls)
			}
		})
	}
}
func TestAcceptsNegotiatedDefaultRoute(t *testing.T) {
	b, _ := New(options())
	f := &fakeControl{mutate: func(m *vici.Message) {
		sa := m.Get(m.Keys()[0]).(*vici.Message)
		children := sa.Get("child-sas").(*vici.Message)
		child := children.Get("child-1").(*vici.Message)
		_ = child.Set("remote-ts", []string{"0.0.0.0/0"})
	}}
	b.control = f
	s, err := b.Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Info().Config.Routes4; len(got) != 1 || got[0].Destination.String() != "0.0.0.0/0" {
		t.Fatalf("routes = %v", got)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsUnsafeNegotiatedRoutes(t *testing.T) {
	cases := map[string]struct {
		transport string
		routes    []string
	}{
		"gateway":      {routes: []string{"192.0.2.0/24"}},
		"tcp-loopback": {transport: "tcp", routes: []string{"127.0.0.0/8"}},
		"wrong-family": {routes: []string{"2001:db8::/64"}},
	}
	for testName, test := range cases {
		t.Run(testName, func(t *testing.T) {
			o := options()
			o.Transport = test.transport
			b, err := New(o)
			if err != nil {
				t.Fatal(err)
			}
			m := state("test")
			sa := m.Get("test").(*vici.Message)
			child := sa.Get("child-sas").(*vici.Message).Get("child-1").(*vici.Message)
			_ = child.Set("remote-ts", test.routes)
			if _, err := b.info("test", []*vici.Message{m}); err == nil {
				t.Fatal("accepted unsafe negotiated route")
			}
		})
	}
}
func TestRejectsMissingIPv6AndIncorrectIdentity(t *testing.T) {
	for _, variant := range []string{"ipv6", "identity", "local-selector", "encapsulation"} {
		t.Run(variant, func(t *testing.T) {
			b, _ := New(options())
			m := state("test")
			sa := m.Get("test").(*vici.Message)
			child := sa.Get("child-sas").(*vici.Message).Get("child-1").(*vici.Message)
			switch variant {
			case "ipv6":
				b.options.IPMode = network.IPModeDualStack
			case "identity":
				_ = sa.Set("remote-id", "unexpected")
			case "local-selector":
				_ = child.Set("local-ts", []string{"0.0.0.0/0"})
			case "encapsulation":
				_ = child.Set("encap", "no")
			}
			if _, err := b.info("test", []*vici.Message{m}); err == nil {
				t.Fatal("accepted mismatched negotiated configuration")
			}
		})
	}
}
func TestRunCancellationCleans(t *testing.T) {
	b, _ := New(options())
	f := &fakeControl{}
	b.control = f
	s, err := b.Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if f.calls[len(f.calls)-1] != "unload-shared" {
		t.Fatal(f.calls)
	}
}

// Models the interval where a socket deadline has elapsed but the context
// timer has not yet closed Done or published Err.
type delayedDeadlineContext struct{ context.Context }

func (delayedDeadlineContext) Deadline() (time.Time, bool) {
	return time.Now().Add(-time.Second), true
}

func TestRunElapsedDeadlineBeforeContextNotification(t *testing.T) {
	b, _ := New(options())
	f := &fakeControl{}
	b.control = f
	s, err := b.Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Without the elapsed-deadline check the incomplete SA reaches the loss
	// threshold, instead of treating the caller's duration as a normal stop.
	f.mutate = func(m *vici.Message) { *m = *msg(map[string]any{}) }
	if err := s.Run(delayedDeadlineContext{context.Background()}); err != nil {
		t.Fatal(err)
	}
	if f.calls[len(f.calls)-1] != "unload-shared" {
		t.Fatal("deadline did not clean up credentials")
	}
}
func TestSecretsFormatting(t *testing.T) {
	s := Secret("do-not-print")
	for _, v := range []string{fmt.Sprint(s), fmt.Sprintf("%#v", s), fmt.Sprintf("%+v", options())} {
		if strings.Contains(v, "do-not-print") || strings.Contains(v, "test-password") || strings.Contains(v, "test-psk") {
			t.Fatal("formatting exposed secret")
		}
	}
}

type blockedControl struct {
	fakeControl
	plugin   string
	occupied bool
}

func (f *blockedControl) call(ctx context.Context, cmd string, args map[string]any) (*vici.Message, error) {
	if cmd == "stats" {
		return msg(map[string]any{"plugins": []string{"eap-mschapv2", "eap-identity", f.plugin}}), nil
	}
	if cmd == "get-conns" && f.occupied {
		return msg(map[string]any{"conns": []string{"existing-vpn"}}), nil
	}
	return f.fakeControl.call(ctx, cmd, args)
}
func TestPreflightRejectsDNSWritersAndOccupiedDaemon(t *testing.T) {
	for _, plugin := range []string{"resolve", "osx-attr", "updown", "occupied"} {
		t.Run(plugin, func(t *testing.T) {
			b, _ := New(options())
			f := &blockedControl{plugin: plugin, occupied: plugin == "occupied"}
			b.control = f
			if _, err := b.Connect(context.Background()); err == nil {
				t.Fatal("unsafe daemon accepted")
			}
			for _, cmd := range f.calls {
				if strings.HasPrefix(cmd, "load") || strings.HasPrefix(cmd, "unload") || cmd == "terminate" {
					t.Fatal("preflight mutated daemon")
				}
			}
		})
	}
}

func TestTCPRejectsKernelESPBeforeLoadingCredentials(t *testing.T) {
	o := options()
	o.Transport = "tcp"
	b, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeControl{}
	b.control = f
	if _, err = b.Connect(context.Background()); err == nil || !strings.Contains(err.Error(), "kernel-libipsec") {
		t.Fatal("accepted kernel ESP for TCP", err)
	}
	if !reflect.DeepEqual(f.calls, []string{"stats"}) {
		t.Fatal("modified daemon before TCP preflight", f.calls)
	}
	if b.options.TCPPort != 4500 {
		t.Fatal("incorrect default TCP port")
	}
}
