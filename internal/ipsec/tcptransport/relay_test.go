package tcptransport

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return w.Buffer.Write(p)
}
func TestFraming(t *testing.T) {
	for _, n := range []int{1, 32, 1400, MaxPayload} {
		p := bytes.Repeat([]byte{0x42}, n)
		var w shortWriter
		if err := WriteFrame(&w, p); err != nil {
			t.Fatal(err)
		}
		if int(binary.BigEndian.Uint16(w.Bytes())) != n+2 {
			t.Fatal("length excludes header")
		}
		// RFC empty frames may be interspersed with data.
		r := io.MultiReader(bytes.NewReader([]byte{0, 2}), &w)
		got, err := ReadFrame(r)
		if err != nil || !bytes.Equal(got, p) {
			t.Fatalf("round trip: %v", err)
		}
	}
	for _, p := range [][]byte{{0, 0}, {0, 1}, {0, 5, 1}} {
		if _, err := ReadFrame(bytes.NewReader(p)); err == nil {
			t.Fatal("accepted malformed record")
		}
	}
	if err := WriteFrame(io.Discard, make([]byte, MaxPayload+1)); err == nil {
		t.Fatal("accepted oversized payload")
	}
}
func TestRelayEncryptedDatagramsAndEOF(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	daemon, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	relay, err := Dial(ctx, netip.MustParseAddrPort(listener.Addr().String()), uint16(daemon.LocalAddr().(*net.UDPAddr).Port))
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	peer.SetDeadline(time.Now().Add(3 * time.Second))
	magic := make([]byte, 6)
	if _, err := io.ReadFull(peer, magic); err != nil || string(magic) != "IKETCP" {
		t.Fatal("missing stream prefix", err)
	}
	for _, p := range [][]byte{{0, 0, 0, 0, 1, 2, 3, 4}, {0x12, 0x34, 0x56, 0x78, 1, 2, 3, 4}} {
		if _, err := daemon.WriteToUDPAddrPort(p, relay.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		got, err := ReadFrame(peer)
		if err != nil || !bytes.Equal(got, p) {
			t.Fatal("outbound", err)
		}
		if err := WriteFrame(peer, p); err != nil {
			t.Fatal(err)
		}
		daemon.SetReadDeadline(time.Now().Add(3 * time.Second))
		b := make([]byte, 100)
		n, _, err := daemon.ReadFromUDP(b)
		if err != nil || !bytes.Equal(b[:n], p) {
			t.Fatal("inbound", err)
		}
	}
	peer.Close()
	select {
	case <-relay.Done():
		if relay.Err() == nil {
			t.Fatal("lost failure")
		}
	case <-time.After(time.Second):
		t.Fatal("EOF did not close relay")
	}
	relay.Close() // Close must be idempotent, including after a read failure.
}
