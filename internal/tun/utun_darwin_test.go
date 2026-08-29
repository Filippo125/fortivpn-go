//go:build darwin

package tun

import (
	"encoding/binary"
	"testing"
)

func TestFramePacket(t *testing.T) {
	packet := []byte{0x60, 0, 0, 0}
	frame, err := framePacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint32(frame[:4]); got != afInet6 {
		t.Fatalf("family = %d, want %d", got, afInet6)
	}
	if string(frame[4:]) != string(packet) {
		t.Fatalf("packet payload changed: %x", frame)
	}
}

func TestIPVersion(t *testing.T) {
	if IPVersion([]byte{0x45}) != 4 || IPVersion([]byte{0x60}) != 6 || IPVersion(nil) != 0 {
		t.Fatal("unexpected IP version detection")
	}
}
