package fortinet

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestOpenTunnel2SendsAuthenticatedModernTunnelRequest(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got, want := request.URL.Path, "/remote/sslvpn-tunnel2"; got != want {
			t.Errorf("path = %q, want %q", got, want)
		}
		if got, want := request.URL.Query().Get("uuid"), "ABCDEF"; got != want {
			t.Errorf("uuid = %q, want %q", got, want)
		}
		if got, want := request.URL.Query().Get("dns0"), "1.1.1.1"; got != want {
			t.Errorf("dns0 = %q, want %q", got, want)
		}
		if got, want := request.URL.Query().Get("dns1"), "2001:4860:4860::8888"; got != want {
			t.Errorf("dns1 = %q, want %q", got, want)
		}
		if got, want := request.Host, "sslvpn"; got != want {
			t.Errorf("Host = %q, want %q", got, want)
		}
		if got, want := request.Header.Get("User-Agent"), tunnelUserAgent; got != want {
			t.Errorf("User-Agent = %q, want %q", got, want)
		}
		if request.Header.Get("FSV_HOSTNAME") == "" {
			t.Error("FSV_HOSTNAME was not sent")
		}
		if _, err := request.Cookie("SVPNCOOKIE"); err != nil {
			t.Error("SVPNCOOKIE was not sent")
		}
		hijacker, ok := writer.(http.Hijacker)
		if !ok {
			t.Fatal("test server does not support connection hijacking")
		}
		connection, _, err := hijacker.Hijack()
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		// Successful tunnel2 endpoints leave the TLS stream open and wait for AD
		// packet frames. They do not exchange a control hello on this channel.
		time.Sleep(2 * tunnelInitialResponseWait)
	}))
	defer server.Close()

	client, err := NewClient(ClientOptions{Gateway: server.URL, Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	client.http.Jar.SetCookies(client.baseURL, []*http.Cookie{{Name: "SVPNCOOKIE", Value: "session", Path: "/remote", Secure: true}})
	tunnel, err := client.OpenTunnel2(context.Background(), Tunnel2Options{
		UUID: "ABCDEF",
		DNS:  []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2001:4860:4860::8888")},
	})
	if err != nil {
		t.Fatalf("OpenTunnel2() error = %v", err)
	}
	if err := tunnel.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestTunnel2FramesIPv4AndIPv6Packets(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	tunnel := &Tunnel2{conn: client, reader: bufio.NewReader(client)}

	incoming := []byte{0x60, 0, 0, 0}
	readResult := make(chan error, 1)
	go func() {
		_, err := server.Write(makeDataFrame(incoming, etherTypeIPv6))
		readResult <- err
	}()
	buffer := make([]byte, 64)
	n, err := tunnel.ReadPacket(context.Background(), buffer)
	if err != nil {
		t.Fatalf("ReadPacket() error = %v", err)
	}
	if got, want := buffer[:n], incoming; string(got) != string(want) {
		t.Fatalf("ReadPacket() = %x, want %x", got, want)
	}
	if err := <-readResult; err != nil {
		t.Fatal(err)
	}

	outgoing := []byte{0x45, 0, 0, 0}
	writeResult := make(chan []byte, 1)
	go func() {
		frame := make([]byte, tunnelHeaderLength+len(outgoing))
		_, err := io.ReadFull(server, frame)
		if err != nil {
			t.Error(err)
			return
		}
		writeResult <- frame
	}()
	if err := tunnel.WritePacket(context.Background(), outgoing); err != nil {
		t.Fatalf("WritePacket() error = %v", err)
	}
	frame := <-writeResult
	if got, want := binary.BigEndian.Uint16(frame[:2]), uint16(len(frame)); got != want {
		t.Fatalf("frame length = %d, want %d", got, want)
	}
	if got, want := string(frame[2:4]), tunnelMagicData; got != want {
		t.Fatalf("frame magic = %q, want %q", got, want)
	}
	if got, want := binary.BigEndian.Uint16(frame[8:10]), uint16(etherTypeIPv4); got != want {
		t.Fatalf("frame EtherType = 0x%04x, want 0x%04x", got, want)
	}
	if got, want := frame[tunnelHeaderLength:], outgoing; string(got) != string(want) {
		t.Fatalf("frame payload = %x, want %x", got, want)
	}
}

func TestOpenTunnel2RequiresSessionCookie(t *testing.T) {
	client, err := NewClient(ClientOptions{Gateway: "vpn.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.OpenTunnel2(context.Background(), Tunnel2Options{}); err == nil {
		t.Fatal("OpenTunnel2() succeeded without a session cookie")
	}
}

func TestOpenTunnel2ReturnsRedactedHTTPStatus(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	client, err := NewClient(ClientOptions{Gateway: server.URL, Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	client.http.Jar.SetCookies(client.baseURL, []*http.Cookie{{Name: "SVPNCOOKIE", Value: "not-for-errors", Path: "/remote", Secure: true}})
	_, err = client.OpenTunnel2(context.Background(), Tunnel2Options{UUID: "ABC"})
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusForbidden {
		t.Fatalf("OpenTunnel2() error = %v, want 403 HTTPStatusError", err)
	}
	if got := err.Error(); got == "" || containsSecret(got, "not-for-errors") {
		t.Fatalf("tunnel error exposes a cookie value: %q", got)
	}
}

func containsSecret(value, secret string) bool {
	return len(secret) > 0 && len(value) >= len(secret) && stringContains(value, secret)
}

func stringContains(value, fragment string) bool {
	for index := 0; index+len(fragment) <= len(value); index++ {
		if value[index:index+len(fragment)] == fragment {
			return true
		}
	}
	return false
}
