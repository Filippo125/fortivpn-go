// Package ipsec implements an experimental IKEv2 PSK/EAP backend using a
// dedicated strongSwan daemon. Charon owns the data plane, addresses and routes.
// The daemon must disable DNS-writing plugins (resolve/osx-attr) and updown.
package ipsec

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Filippo125/fortivpn-go/internal/ipsec/tcptransport"
	"github.com/Filippo125/fortivpn-go/internal/network"
	"github.com/Filippo125/fortivpn-go/internal/session"
	"github.com/strongswan/govici/vici"
)

type Secret string

func (Secret) String() string   { return "<redacted>" }
func (Secret) GoString() string { return "<redacted>" }

type Options struct {
	Transport  string
	TCPPort    uint16
	SocketPath string
	Gateway    netip.Addr
	RemoteID   string
	Username   string
	Password   Secret
	PSK        Secret
	IPMode     network.IPMode
	Routes     []netip.Prefix
}

// Validate restricts this prototype to the verified profile. Traffic selectors
// are explicit: broad gateway-provided default routes are never requested.
func (o Options) Validate() error {
	if o.Transport != "" && o.Transport != "udp" && o.Transport != "tcp" {
		return errors.New("IPsec transport must be udp or tcp")
	}
	if o.Transport != "tcp" && o.TCPPort != 0 {
		return errors.New("TCP port requires TCP transport")
	}
	if !o.Gateway.IsValid() || !o.Gateway.Is4() || o.Gateway.IsUnspecified() || o.Gateway.IsMulticast() {
		return errors.New("IPsec requires an IPv4 gateway address")
	}
	if o.SocketPath != "" && !filepath.IsAbs(o.SocketPath) {
		return errors.New("VICI socket path must be absolute")
	}
	for name, value := range map[string]string{"remote identity": o.RemoteID, "username": o.Username, "password": string(o.Password), "PSK": string(o.PSK)} {
		if value == "" || len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("IPsec %s is missing or invalid", name)
		}
	}
	// %any and wildcard identities would disable the intended peer identity check.
	if strings.ContainsAny(o.RemoteID, "%*") {
		return errors.New("IPsec remote identity must be explicit")
	}
	if o.IPMode != network.IPModeIPv4 && o.IPMode != network.IPModeDualStack {
		return errors.New("IPsec prototype supports ip-mode ipv4 or dual")
	}
	if len(o.Routes) == 0 || len(o.Routes) > 32 {
		return errors.New("IPsec requires 1 to 32 explicit split routes")
	}
	seen := map[netip.Prefix]bool{}
	v4, v6 := false, false
	for _, p := range o.Routes {
		if !p.IsValid() || p != p.Masked() || p.Bits() == 0 || p.Addr().Is4In6() || p.Addr().IsMulticast() || p.Contains(o.Gateway) {
			return errors.New("IPsec routes must be canonical split prefixes excluding the gateway")
		}
		if o.Transport == "tcp" && p.Contains(netip.MustParseAddr("127.0.0.1")) {
			return errors.New("TCP split routes must exclude the loopback relay")
		}
		if seen[p] {
			return errors.New("duplicate IPsec split route")
		}
		seen[p] = true
		if p.Addr().Is4() {
			v4 = true
		} else {
			v6 = true
		}
	}
	if !v4 || (o.IPMode == network.IPModeIPv4 && v6) || (o.IPMode == network.IPModeDualStack && !v6) {
		return errors.New("IPsec split routes must match the requested address families")
	}
	return nil
}

type control interface {
	call(context.Context, string, map[string]any) (*vici.Message, error)
	list(context.Context, string) ([]*vici.Message, error)
}

type socketControl struct{ path string }

func (c socketControl) dial(ctx context.Context) (*vici.Session, error) {
	return vici.NewSession(vici.WithSocketPath(c.path), vici.WithDialContext(func(_ context.Context, n, a string) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, n, a) }))
}
func (c socketControl) call(ctx context.Context, cmd string, args map[string]any) (*vici.Message, error) {
	m, err := vici.MarshalMessage(args)
	if err != nil {
		return nil, err
	}
	s, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	return s.Call(ctx, cmd, m)
}
func (c socketControl) list(ctx context.Context, name string) ([]*vici.Message, error) {
	s, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	m, _ := vici.MarshalMessage(map[string]any{"ike": name})
	var out []*vici.Message
	for event, err := range s.CallStreaming(ctx, "list-sas", "list-sa", m) {
		if err != nil {
			return nil, err
		}
		out = append(out, event)
	}
	return out, nil
}

type Backend struct {
	options Options
	control control
	relay   *tcptransport.Relay
}

var _ session.Backend = (*Backend)(nil)

func New(o Options) (*Backend, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	if o.Transport == "" {
		o.Transport = "udp"
	}
	if o.Transport == "tcp" && o.TCPPort == 0 {
		o.TCPPort = 4500
	}
	if o.SocketPath == "" {
		o.SocketPath = "/var/run/charon.vici"
	}
	o.Routes = append([]netip.Prefix(nil), o.Routes...)
	return &Backend{options: o, control: socketControl{path: o.SocketPath}}, nil
}

func (b *Backend) Connect(ctx context.Context) (_ session.Session, err error) {
	if err := b.preflight(ctx); err != nil {
		return nil, b.safe(err)
	}
	if b.options.Transport == "tcp" {
		relay, e := tcptransport.Dial(ctx, netip.AddrPortFrom(b.options.Gateway, b.options.TCPPort), 4500)
		if e != nil {
			return nil, e
		}
		copyBackend := *b
		copyBackend.relay = relay
		b = &copyBackend
		defer func() {
			if err != nil {
				relay.Close()
			}
		}()
	}
	var token [12]byte
	if _, err = rand.Read(token[:]); err != nil {
		return nil, err
	}
	name := "fortivpn-" + hex.EncodeToString(token[:])
	s := &connection{backend: b, name: name, done: make(chan struct{})}
	defer func() {
		if err != nil {
			err = errors.Join(b.safe(err), s.Close())
		}
	}()
	// Record attempted writes as well, so uncertain command outcomes are cleaned.
	for _, key := range []struct{ suffix, kind, owner, data string }{{"-ike", "IKE", b.options.RemoteID, string(b.options.PSK)}, {"-eap", "EAP", b.options.Username, string(b.options.Password)}} {
		id := name + key.suffix
		s.keys = append(s.keys, id)
		if _, err = b.control.call(ctx, "load-shared", map[string]any{"id": id, "type": key.kind, "owners": []string{key.owner}, "data": key.data}); err != nil {
			return nil, fmt.Errorf("load IPsec credential: %w", err)
		}
	}
	s.loaded = true
	if _, err = b.control.call(ctx, "load-conn", b.config(name)); err != nil {
		return nil, fmt.Errorf("load IPsec connection: %w", err)
	}
	for i := range b.options.Routes {
		s.initiated = true
		if _, err = b.control.call(ctx, "initiate", map[string]any{"ike": name, "child": childName(name, i), "timeout": "30000"}); err != nil {
			return nil, fmt.Errorf("negotiate IPsec child %d: %w", i, err)
		}
	}
	var messages []*vici.Message
	messages, err = b.control.list(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("read negotiated IPsec state: %w", err)
	}
	s.info, err = b.info(name, messages)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return s, nil
}

// preflight keeps the prototype on a dedicated daemon and rejects plugins
// that could change DNS or execute external network scripts during setup.
func (b *Backend) preflight(ctx context.Context) error {
	stats, err := b.control.call(ctx, "stats", nil)
	if err != nil {
		return fmt.Errorf("inspect strongSwan daemon: %w", err)
	}
	plugins := list(stats, "plugins")
	if len(plugins) == 0 {
		return errors.New("strongSwan did not report its loaded plugins")
	}
	found := map[string]bool{}
	for _, plugin := range plugins {
		found[plugin] = true
		switch plugin {
		case "resolve", "osx-attr", "updown":
			return fmt.Errorf("dedicated IPsec daemon must disable plugin %s", plugin)
		}
	}
	if b.options.Transport == "tcp" && (!found["kernel-libipsec"] || found["kernel-pfkey"]) {
		return errors.New("TCP requires dedicated strongSwan kernel-libipsec userspace ESP (kernel-pfkey disabled)")
	}
	if !found["eap-mschapv2"] || !found["eap-identity"] {
		return errors.New("strongSwan requires eap-mschapv2 and eap-identity plugins")
	}
	for _, pair := range [][2]string{{"get-conns", "conns"}, {"get-shared", "keys"}} {
		m, err := b.control.call(ctx, pair[0], nil)
		if err != nil {
			return fmt.Errorf("inspect dedicated IPsec daemon: %w", err)
		}
		if len(list(m, pair[1])) != 0 {
			return errors.New("IPsec prototype requires a dedicated daemon with no loaded connections or shared credentials")
		}
	}
	return nil
}

func childName(name string, i int) string { return fmt.Sprintf("%s-%d", name, i) }
func (b *Backend) config(name string) map[string]any {
	children := map[string]any{}
	for i, p := range b.options.Routes {
		children[childName(name, i)] = map[string]any{"local_ts": []string{"dynamic"}, "remote_ts": []string{p.String()}, "esp_proposals": []string{"aes256-sha256-modp2048"}, "start_action": "none", "dpd_action": "clear", "close_action": "none", "rekey_time": "3000s", "life_time": "3600s"}
	}
	vips := []string{"0.0.0.0"}
	if b.options.IPMode == network.IPModeDualStack {
		vips = append(vips, "::")
	}
	cfg := map[string]any{
		"version": "2", "remote_addrs": []string{b.options.Gateway.String()}, "proposals": []string{"aes256-sha256-modp2048"}, "vips": vips, "encap": "yes", "mobike": "no", "dpd_delay": "10s", "rekey_time": "14400s", "reauth_time": "0s",
		"local":  map[string]any{"auth": "eap-mschapv2", "id": b.options.Username, "eap_id": b.options.Username},
		"remote": map[string]any{"auth": "psk", "id": b.options.RemoteID}, "children": children,
	}
	if b.relay != nil {
		cfg["remote_addrs"] = []string{"127.0.0.1"}
		cfg["local_addrs"] = []string{"127.0.0.1"}
		cfg["local_port"] = "4500"
		cfg["remote_port"] = fmt.Sprint(b.relay.LocalAddr().Port())
	}
	return map[string]any{name: cfg}
}

type connection struct {
	backend           *Backend
	name              string
	keys              []string
	loaded, initiated bool
	info              session.Info
	once              sync.Once
	done              chan struct{}
	closeErr          error
}

func (s *connection) Info() session.Info { return s.info }
func (s *connection) Run(ctx context.Context) (err error) {
	defer func() { err = errors.Join(err, s.Close()) }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var transportDone <-chan struct{}
	if s.backend.relay != nil {
		transportDone = s.backend.relay.Done()
	}
	failures := 0
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-transportDone:
			select {
			case <-s.done:
				return nil
			default:
			}
			if ctx.Err() != nil {
				return nil
			}
			if err := s.backend.relay.Err(); err != nil {
				return fmt.Errorf("IPsec TCP transport closed: %w", err)
			}
			return errors.New("IPsec TCP transport closed")
		case <-s.done:
			return nil
		case <-ticker.C:
			poll, cancel := context.WithTimeout(ctx, 3*time.Second)
			messages, e := s.backend.control.list(poll, s.name)
			cancel()
			if ctx.Err() != nil {
				return nil
			}
			// Socket deadlines can fire before the context timer publishes Err.
			// An elapsed caller deadline still means normal disconnection.
			if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
				return nil
			}
			select {
			case <-s.done:
				return nil
			default:
			}
			if e != nil {
				return s.backend.safe(fmt.Errorf("monitor IPsec: %w", e))
			}
			if _, e = s.backend.info(s.name, messages); e != nil {
				failures++
				if failures >= 3 {
					return fmt.Errorf("IPsec session lost: %w", e)
				}
			} else {
				failures = 0
			}
		}
	}
}
func (s *connection) Close() error {
	s.once.Do(func() {
		if s.backend.relay != nil {
			defer s.backend.relay.Close()
		}
		close(s.done)
		// Cleanup has its own deadline, even if setup/Run was canceled. A fresh VICI
		// connection per command avoids reusing a stream interrupted mid-response.
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		var errs []error
		if s.initiated {
			r, e := s.backend.control.call(ctx, "terminate", map[string]any{"ike": s.name, "force": "yes", "timeout": "5000"})
			// strongSwan reports no matches as a command failure after auth rejection.
			if e != nil && (r == nil || r.Get("matches") != "0") {
				errs = append(errs, fmt.Errorf("terminate IPsec: %w", e))
			}
		}
		if s.loaded {
			if _, e := s.backend.control.call(ctx, "unload-conn", map[string]any{"name": s.name}); e != nil {
				errs = append(errs, fmt.Errorf("unload IPsec connection: %w", e))
			}
		}
		for i := len(s.keys) - 1; i >= 0; i-- {
			if _, e := s.backend.control.call(ctx, "unload-shared", map[string]any{"id": s.keys[i]}); e != nil {
				errs = append(errs, fmt.Errorf("unload IPsec credential: %w", e))
			}
		}
		s.closeErr = s.backend.safe(errors.Join(errs...))
	})
	return s.closeErr
}

type redactedError struct {
	cause error
	text  string
}

func (e redactedError) Error() string { return e.text }
func (e redactedError) Unwrap() error { return e.cause }
func (b *Backend) safe(err error) error {
	if err == nil {
		return nil
	}
	text := err.Error()
	for _, v := range []string{string(b.options.Password), string(b.options.PSK)} {
		if v != "" {
			text = strings.ReplaceAll(text, v, "<redacted>")
		}
	}
	return redactedError{cause: err, text: text}
}
