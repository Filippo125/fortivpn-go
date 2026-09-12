// Package tcptransport carries encrypted IKE/ESP datagrams over RFC 9329 TCP.
// The local endpoint is exclusively loopback; authentication remains in IKE.
package tcptransport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

const MaxPayload = 65533

// ReadFrame handles short reads, coalesced messages and RFC empty records.
func ReadFrame(r io.Reader) ([]byte, error) {
	for {
		var h [2]byte
		if _, err := io.ReadFull(r, h[:]); err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(h[:]))
		if n < 2 {
			return nil, errors.New("invalid IPsec TCP record length")
		}
		if n == 2 {
			continue
		}
		p := make([]byte, n-2)
		_, err := io.ReadFull(r, p)
		return p, err
	}
}

func WriteFrame(w io.Writer, p []byte) error {
	if len(p) == 0 || len(p) > MaxPayload {
		return errors.New("invalid IPsec TCP payload size")
	}
	b := make([]byte, len(p)+2)
	binary.BigEndian.PutUint16(b, uint16(len(b)))
	copy(b[2:], p)
	return writeAll(w, b)
}
func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

// Relay owns one TCP connection and one connected loopback UDP socket. Only
// packets from the configured daemon port are accepted by the UDP socket.
// It never reconnects, changes gateway, or falls back to external UDP.
type Relay struct {
	tcp  net.Conn
	udp  *net.UDPConn
	done chan struct{}
	once sync.Once
	mu   sync.Mutex
	err  error
	wg   sync.WaitGroup
}

func Dial(ctx context.Context, gateway netip.AddrPort, daemonPort uint16) (*Relay, error) {
	if !gateway.IsValid() || !gateway.Addr().Is4() || gateway.Port() == 0 || daemonPort == 0 {
		return nil, errors.New("invalid TCP relay endpoint")
	}
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp4", gateway.String())
	if err != nil {
		return nil, fmt.Errorf("connect IPsec TCP: %w", err)
	}
	// Context applies to establishment only, not the returned session lifetime.
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	c.SetWriteDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { c.Close() })
	err = writeAll(c, []byte("IKETCP"))
	stopped := stop()
	if err != nil || !stopped || ctx.Err() != nil {
		c.Close()
		if err == nil {
			err = ctx.Err()
		}
		if err == nil {
			err = context.Canceled
		}
		return nil, err
	}
	c.SetWriteDeadline(time.Time{})
	u, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(daemonPort)})
	if err != nil {
		c.Close()
		return nil, err
	}
	r := &Relay{tcp: c, udp: u, done: make(chan struct{})}
	r.wg.Add(2)
	go r.outbound()
	go r.inbound()
	return r, nil
}
func (r *Relay) LocalAddr() netip.AddrPort { return r.udp.LocalAddr().(*net.UDPAddr).AddrPort() }
func (r *Relay) Done() <-chan struct{}     { return r.done }
func (r *Relay) Err() error                { r.mu.Lock(); defer r.mu.Unlock(); return r.err }
func (r *Relay) fail(err error) {
	r.once.Do(func() {
		r.mu.Lock()
		r.err = err
		r.mu.Unlock()
		close(r.done)
		r.tcp.Close()
		r.udp.Close()
	})
}
func (r *Relay) Close() error { r.fail(nil); r.wg.Wait(); return nil }
func (r *Relay) outbound() {
	defer r.wg.Done()
	b := make([]byte, 65536)
	for {
		n, err := r.udp.Read(b)
		if err != nil {
			r.fail(err)
			return
		}
		// UDP NAT keepalives are not needed on the TCP transport.
		if n == 1 && b[0] == 0xff {
			continue
		}
		r.tcp.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err = WriteFrame(r.tcp, b[:n]); err != nil {
			r.fail(err)
			return
		}
	}
}
func (r *Relay) inbound() {
	defer r.wg.Done()
	for {
		p, err := ReadFrame(r.tcp)
		if err != nil {
			r.fail(err)
			return
		}
		if len(p) == 1 && p[0] == 0xff {
			continue
		}
		if _, err = r.udp.Write(p); err != nil {
			r.fail(err)
			return
		}
	}
}
