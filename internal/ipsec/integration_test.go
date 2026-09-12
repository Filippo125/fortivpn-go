package ipsec

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Filippo125/fortivpn-go/internal/network"
	"github.com/strongswan/govici/vici"
)

// This test is opt-in and must run in the dedicated NET_ADMIN container from
// tests/integration/ipsec. No secrets are embedded in source or test output.
func TestGatewayIntegration(t *testing.T) {
	path := os.Getenv("FORTIVPN_IPSEC_CREDENTIALS")
	if path == "" {
		t.Skip("set FORTIVPN_IPSEC_CREDENTIALS in the isolated lab container")
	}
	route4 := requiredLabValue(t, "FORTIVPN_IPSEC_ROUTE4")
	host4 := requiredLabValue(t, "FORTIVPN_IPSEC_HOST4")
	route6 := requiredLabValue(t, "FORTIVPN_IPSEC_ROUTE6")
	host6 := requiredLabValue(t, "FORTIVPN_IPSEC_HOST6")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var creds struct{ Gateway, Username, Password, PSK string }
	if err = json.Unmarshal(data, &creds); err != nil {
		t.Fatal("invalid credentials JSON")
	}
	base := Options{Transport: os.Getenv("FORTIVPN_IPSEC_TRANSPORT"), Gateway: netip.MustParseAddr(creds.Gateway), RemoteID: creds.Gateway, Username: creds.Username, Password: Secret(creds.Password), PSK: Secret(creds.PSK), IPMode: network.IPModeIPv4, Routes: []netip.Prefix{netip.MustParsePrefix(route4)}}
	ctl := socketControl{path: "/var/run/charon.vici"}
	allocatedAddresses := make(map[string]struct{})
	assertEmpty := func(t *testing.T) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, pair := range [][2]string{{"get-conns", "conns"}, {"get-shared", "keys"}} {
			m, e := ctl.call(ctx, pair[0], nil)
			if e != nil {
				t.Fatal(e)
			}
			if len(list(m, pair[1])) != 0 {
				t.Fatalf("daemon retained %s", pair[1])
			}
		}
		sas, e := ctl.list(ctx, "")
		if e != nil {
			t.Fatal(e)
		}
		if len(sas) != 0 {
			t.Fatal("daemon retained SAs")
		}
		output, e := exec.Command("ip", "-j", "address", "show").Output()
		if e != nil {
			t.Fatal(e)
		}
		for address := range allocatedAddresses {
			if strings.Contains(string(output), address) {
				t.Fatal("virtual address remains after cleanup")
			}
		}
		output, e = exec.Command("ip", "route", "show", "table", "all").Output()
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(string(output), route4) {
			t.Fatal("IPv4 split route remains after cleanup")
		}
		output, e = exec.Command("ip", "-6", "route", "show", "table", "all").Output()
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(string(output), route6) {
			t.Fatal("IPv6 split route remains after cleanup")
		}
	}
	assertEmpty(t)
	for _, scenario := range []string{"ipv4", "dual", "wrong-password", "wrong-psk", "wrong-identity", "setup-cancel", "peer-loss"} {
		t.Run(scenario, func(t *testing.T) {
			o := base
			o.Routes = append([]netip.Prefix(nil), base.Routes...)
			switch scenario {
			case "dual":
				o.IPMode = network.IPModeDualStack
				o.Routes = append(o.Routes, netip.MustParsePrefix(route6))
			case "wrong-password":
				o.Password = "intentionally-incorrect-password"
			case "wrong-psk":
				o.PSK = "intentionally-incorrect-psk"
			case "wrong-identity":
				o.RemoteID = "192.0.2.222"
			}
			b, e := New(o)
			if e != nil {
				t.Fatal(e)
			}
			duration := 30 * time.Second
			if scenario == "setup-cancel" {
				duration = 150 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), duration)
			active, e := b.Connect(ctx)
			cancel()
			if scenario != "ipv4" && scenario != "dual" && scenario != "peer-loss" {
				if e == nil {
					_ = active.Close()
					t.Fatal("invalid authentication or canceled setup succeeded")
				}
				for _, secret := range []string{creds.Password, creds.PSK, string(o.Password), string(o.PSK)} {
					if strings.Contains(e.Error(), secret) {
						t.Fatal("diagnostic exposed a secret")
					}
				}
				t.Logf("expected failure: %v", e)
				assertEmpty(t)
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			defer active.Close()
			if active.Info().Config.IPv4 != nil {
				allocatedAddresses[active.Info().Config.IPv4.Address.Addr().String()] = struct{}{}
			}
			if active.Info().Config.IPv6 != nil {
				allocatedAddresses[active.Info().Config.IPv6.Address.Addr().String()] = struct{}{}
			}
			t.Logf("assigned IPv4=%v IPv6=%v; routes4=%v routes6=%v", active.Info().Config.IPv4, active.Info().Config.IPv6, active.Info().Config.Routes4, active.Info().Config.Routes6)
			runCtx, stop := context.WithCancel(context.Background())
			defer stop()
			done := make(chan error, 1)
			go func() { done <- active.Run(runCtx) }()
			probe := func(host string) {
				t.Helper()
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				if o.Transport == "tcp" {
					route, e := exec.CommandContext(ctx, "ip", "-j", "route", "get", host).Output()
					var entries []struct{ Dev string }
					if e != nil || json.Unmarshal(route, &entries) != nil || len(entries) != 1 || entries[0].Dev != "ipsec0" {
						t.Fatalf("TCP test route must use userspace ESP interface: %s (%v)", route, e)
					}
				}
				args := []string{"-c", "2", "-W", "2", host}
				if strings.Contains(host, ":") {
					args = append([]string{"-6"}, args...)
				}
				out, e := exec.CommandContext(ctx, "ping", args...).CombinedOutput()
				if e != nil {
					t.Fatalf("ping %s failed: %v: %s", host, e, out)
				}
				c, e := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(host, "22"))
				if e != nil {
					t.Fatalf("TCP %s: %v", host, e)
				}
				_ = c.Close()
				t.Logf("ICMP and TCP/22 passed: %s", host)
			}
			probe(host4)
			if scenario == "dual" {
				probe(host6)
			}
			conn := active.(*connection)
			if scenario == "peer-loss" {
				ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
				_, e = ctl.call(ctx, "terminate", map[string]any{"ike": conn.name, "force": "yes", "timeout": "5000"})
				cancel()
				if e != nil {
					t.Fatal(e)
				}
				select {
				case e = <-done:
					if e == nil {
						t.Fatal("peer loss was not reported")
					}
					t.Logf("peer loss detected: %v", e)
				case <-time.After(10 * time.Second):
					t.Fatal("peer loss was not detected")
				}
				assertEmpty(t)
				return
			}
			// Confirm SA replacement, not merely acceptance of the rekey request.
			snapshotID := func(child string) string {
				t.Helper()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				events, err := ctl.list(ctx, conn.name)
				if err != nil {
					t.Fatal(err)
				}
				for _, event := range events {
					sa, ok := event.Get(conn.name).(*vici.Message)
					if !ok || text(sa, "state") != "ESTABLISHED" {
						continue
					}
					if child == "" {
						return text(sa, "uniqueid")
					}
					children, ok := sa.Get("child-sas").(*vici.Message)
					if !ok {
						continue
					}
					for _, key := range children.Keys() {
						c, ok := children.Get(key).(*vici.Message)
						if ok && text(c, "name") == child && text(c, "state") == "INSTALLED" {
							return text(c, "uniqueid")
						}
					}
				}
				return ""
			}
			targets := []string{childName(conn.name, 0), ""}
			if scenario == "dual" {
				targets = append([]string{childName(conn.name, 1)}, targets...)
			}
			for _, child := range targets {
				before := snapshotID(child)
				if before == "" {
					t.Fatal("missing SA before rekey")
				}
				args := map[string]any{"ike": conn.name}
				if child != "" {
					args["child"] = child
				}
				ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
				_, e = ctl.call(ctx, "rekey", args)
				cancel()
				if e != nil {
					t.Fatal(e)
				}
				changed := false
				deadline := time.Now().Add(8 * time.Second)
				for time.Now().Before(deadline) {
					current := snapshotID(child)
					if current != "" && current != before {
						changed = true
						break
					}
					time.Sleep(100 * time.Millisecond)
				}
				if !changed {
					t.Fatal("rekey did not replace the SA")
				}
				t.Logf("SA replacement confirmed (child=%q)", child)
				probe(host4)
				if scenario == "dual" {
					probe(host6)
				}
			}

			stop()
			select {
			case e = <-done:
				if e != nil {
					t.Fatal(e)
				}
			case <-time.After(20 * time.Second):
				t.Fatal("disconnect did not finish")
			}
			assertEmpty(t)
		})
	}
}

func requiredLabValue(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required for the opt-in integration test", name)
	}
	return value
}
