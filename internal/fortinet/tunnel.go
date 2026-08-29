package fortinet

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// A FortiGate can immediately reject the HTTP request. Give that response a
	// brief chance to arrive without consuming a queued tunnel packet.
	tunnelInitialResponseWait = 100 * time.Millisecond
)

const tunnelUserAgent = "FortiSSLVPN (Mac OS X; SV1 [SV{v=02.01; f=07;}])"

const (
	tunnelHeaderLength = 10
	tunnelMaxFrameSize = 65535
	tunnelMagicData    = "AD"
	tunnelMagicControl = "GF"
	etherTypeIPv4      = 0x0800
	etherTypeIPv6      = 0x86dd
)

// Tunnel2Options holds the metadata expected by FortiClient 7+ when it opens
// the modern tunnel endpoint. UUID is generated per call when omitted; it is
// never persisted. DNS is advisory metadata for the gateway, not local DNS
// configuration.
type Tunnel2Options struct {
	UUID string
	DNS  []netip.Addr
}

// Tunnel2 is the authenticated packet transport behind FortiGate's modern
// /remote/sslvpn-tunnel2 endpoint. It carries bare IPv4 and IPv6 packets using
// the Fortinet TUN v2 frame format.
type Tunnel2 struct {
	conn   net.Conn
	reader *bufio.Reader
	once   sync.Once
	write  sync.Mutex
}

// OpenTunnel2 opens the FortiClient 7+ TUN endpoint on a fresh TLS connection.
// A successful FortiGate endpoint does not send an HTTP response or a control
// hello. It starts transporting AD packet frames directly. HTTP rejections are
// detected during a short initial grace period and surfaced as HTTPStatusError.
func (c *Client) OpenTunnel2(ctx context.Context, options Tunnel2Options) (*Tunnel2, error) {
	if !c.hasSessionCookie() {
		return nil, errors.New("cannot open FortiGate tunnel without an SVPNCOOKIE")
	}
	if options.UUID == "" {
		uuid, err := newTunnelUUID()
		if err != nil {
			return nil, err
		}
		options.UUID = uuid
	}

	query := url.Values{"uuid": {options.UUID}}
	for index, address := range options.DNS {
		if !address.IsValid() {
			continue
		}
		query.Set("dns"+strconv.Itoa(index), address.String())
	}
	tunnelURL, err := url.Parse(c.url("/remote/sslvpn-tunnel2?" + query.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build tunnel URL: %w", err)
	}

	dialer := &net.Dialer{}
	connection, err := dialer.DialContext(ctx, "tcp", c.gatewayHostHeader())
	if err != nil {
		return nil, fmt.Errorf("dial FortiGate tunnel: %w", err)
	}
	tlsConfig := c.tls.Clone()
	tlsConfig.ServerName = c.baseURL.Hostname()
	tlsConnection := tls.Client(connection, tlsConfig)
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		_ = connection.Close()
		return nil, fmt.Errorf("TLS handshake for FortiGate tunnel: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, tunnelURL.String(), nil)
	if err != nil {
		_ = tlsConnection.Close()
		return nil, err
	}
	hostname, err := os.Hostname()
	if err != nil {
		_ = tlsConnection.Close()
		return nil, fmt.Errorf("get local hostname for FortiGate tunnel: %w", err)
	}
	// The native FortiClient sends this virtual host and client hostname to the
	// tunnel handler. They are distinct from TLS SNI and the TCP destination.
	request.Host = "sslvpn"
	request.Header.Set("User-Agent", tunnelUserAgent)
	request.Header.Set("FSV_HOSTNAME", hostname)
	cookies := c.http.Jar.Cookies(tunnelURL)
	request.Header.Set("Cookie", cookieHeader(cookies))
	cookieNames := requestCookieNames(cookies)
	c.tracef("GET /remote/sslvpn-tunnel2; sent cookies: %s", displayCookieNames(cookieNames))
	if err := request.Write(tlsConnection); err != nil {
		_ = tlsConnection.Close()
		return nil, fmt.Errorf("write FortiGate tunnel request: %w", err)
	}

	tunnel := &Tunnel2{conn: tlsConnection, reader: bufio.NewReader(tlsConnection)}
	if err := tunnel.awaitInitialTunnelResponse(request, cookieNames); err != nil {
		_ = tunnel.Close()
		return nil, err
	}
	return tunnel, nil
}

func (t *Tunnel2) awaitInitialTunnelResponse(request *http.Request, cookieNames []string) error {
	if err := t.conn.SetReadDeadline(time.Now().Add(tunnelInitialResponseWait)); err != nil {
		return fmt.Errorf("set tunnel response deadline: %w", err)
	}
	defer t.conn.SetReadDeadline(time.Time{})

	prefix, err := t.reader.Peek(1)
	if err != nil {
		if isTimeout(err) {
			return nil
		}
		if errors.Is(err, io.EOF) {
			return errors.New("FortiGate closed the tunnel before accepting it")
		}
		return fmt.Errorf("read FortiGate tunnel response: %w", err)
	}
	if prefix[0] != 'H' {
		return nil
	}
	prefix, err = t.reader.Peek(len("HTTP/"))
	if err != nil {
		if isTimeout(err) {
			return nil
		}
		return fmt.Errorf("read FortiGate tunnel response prefix: %w", err)
	}
	if string(prefix) != "HTTP/" {
		return nil
	}
	response, err := http.ReadResponse(t.reader, request)
	if err != nil {
		return fmt.Errorf("read FortiGate tunnel HTTP response: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return &HTTPStatusError{
			Method:      http.MethodGet,
			Path:        "/remote/sslvpn-tunnel2",
			Status:      response.Status,
			StatusCode:  response.StatusCode,
			CookieNames: cookieNames,
		}
	}
	return errors.New("FortiGate returned HTTP success instead of starting the TUN v2 protocol")
}

// Connect completes the interface used by the packet engine. OpenTunnel2 has
// already established the packet transport, so this only observes context
// cancellation before packet copies begin.
func (t *Tunnel2) Connect(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

// ReadPacket decodes exactly one Fortinet TUN v2 data frame into dst.
func (t *Tunnel2) ReadPacket(ctx context.Context, dst []byte) (int, error) {
	if err := setReadContextDeadline(t.conn, ctx); err != nil {
		return 0, err
	}
	defer t.conn.SetReadDeadline(time.Time{})
	frame, err := t.readFrame()
	if err != nil {
		return 0, err
	}
	if string(frame.magic) != tunnelMagicData {
		return 0, fmt.Errorf("unexpected FortiGate TUN frame %q", frame.magic)
	}
	if len(frame.payload) > len(dst) {
		return 0, io.ErrShortBuffer
	}
	if frame.payloadLength != len(frame.payload)+4 {
		return 0, errors.New("FortiGate TUN frame has an invalid payload length")
	}
	if familyForEtherType(frame.etherType) == 0 {
		return 0, fmt.Errorf("unsupported FortiGate TUN EtherType 0x%04x", frame.etherType)
	}
	if version := packetVersion(frame.payload); version != familyForEtherType(frame.etherType) {
		return 0, fmt.Errorf("FortiGate TUN frame family %d does not match IP version %d", familyForEtherType(frame.etherType), version)
	}
	return copy(dst, frame.payload), nil
}

// WritePacket wraps one bare IP packet in a Fortinet TUN v2 AD data frame.
func (t *Tunnel2) WritePacket(ctx context.Context, packet []byte) error {
	family := packetVersion(packet)
	etherType := etherTypeForFamily(family)
	if etherType == 0 {
		return fmt.Errorf("unsupported packet IP version %d", family)
	}
	if len(packet)+tunnelHeaderLength > tunnelMaxFrameSize {
		return fmt.Errorf("packet is too large for FortiGate TUN v2: %d bytes", len(packet))
	}
	if err := setWriteContextDeadline(t.conn, ctx); err != nil {
		return err
	}
	defer t.conn.SetWriteDeadline(time.Time{})
	frame := makeDataFrame(packet, etherType)
	t.write.Lock()
	defer t.write.Unlock()
	if err := writeAll(t.conn, frame); err != nil {
		return fmt.Errorf("write FortiGate TUN frame: %w", err)
	}
	return nil
}

func (t *Tunnel2) Close() error {
	var err error
	t.once.Do(func() { err = t.conn.Close() })
	return err
}

type tunnelFrame struct {
	magic         []byte
	payloadLength int
	etherType     uint16
	payload       []byte
}

func (t *Tunnel2) readFrame() (tunnelFrame, error) {
	var lengthBytes [2]byte
	if _, err := io.ReadFull(t.reader, lengthBytes[:]); err != nil {
		return tunnelFrame{}, err
	}
	length := int(binary.BigEndian.Uint16(lengthBytes[:]))
	if length < 4 || length > tunnelMaxFrameSize {
		return tunnelFrame{}, fmt.Errorf("invalid FortiGate TUN frame length %d", length)
	}
	raw := make([]byte, length)
	copy(raw, lengthBytes[:])
	if _, err := io.ReadFull(t.reader, raw[2:]); err != nil {
		return tunnelFrame{}, err
	}
	if len(raw) < 4 {
		return tunnelFrame{}, errors.New("FortiGate TUN frame is too short")
	}
	frame := tunnelFrame{magic: raw[2:4]}
	if string(frame.magic) == tunnelMagicControl {
		frame.payload = raw[4:]
		return frame, nil
	}
	if len(raw) < tunnelHeaderLength {
		return tunnelFrame{}, errors.New("FortiGate TUN data frame is too short")
	}
	frame.payloadLength = int(binary.BigEndian.Uint16(raw[4:6]))
	frame.etherType = binary.BigEndian.Uint16(raw[8:10])
	frame.payload = raw[tunnelHeaderLength:]
	return frame, nil
}

func makeDataFrame(packet []byte, etherType uint16) []byte {
	frame := make([]byte, tunnelHeaderLength+len(packet))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(frame)))
	copy(frame[2:4], tunnelMagicData)
	binary.BigEndian.PutUint16(frame[4:6], uint16(len(packet)+4))
	binary.BigEndian.PutUint16(frame[8:10], etherType)
	copy(frame[tunnelHeaderLength:], packet)
	return frame
}

func packetVersion(packet []byte) int {
	if len(packet) == 0 {
		return 0
	}
	return int(packet[0] >> 4)
}

func etherTypeForFamily(family int) uint16 {
	switch family {
	case 4:
		return etherTypeIPv4
	case 6:
		return etherTypeIPv6
	default:
		return 0
	}
}

func familyForEtherType(etherType uint16) int {
	switch etherType {
	case etherTypeIPv4:
		return 4
	case etherTypeIPv6:
		return 6
	default:
		return 0
	}
}

func writeAll(writer io.Writer, bytes []byte) error {
	for len(bytes) > 0 {
		written, err := writer.Write(bytes)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		bytes = bytes[written:]
	}
	return nil
}

func setReadContextDeadline(conn net.Conn, ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok {
		return conn.SetReadDeadline(deadline)
	}
	return nil
}

func setWriteContextDeadline(conn net.Conn, ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok {
		return conn.SetWriteDeadline(deadline)
	}
	return nil
}

func newTunnelUUID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate FortiClient UUID: %w", err)
	}
	return strings.ToUpper(hex.EncodeToString(bytes)), nil
}

func cookieHeader(cookies []*http.Cookie) string {
	parts := make([]string, 0, len(cookies))
	for _, cookie := range cookies {
		parts = append(parts, cookie.Name+"="+cookie.Value)
	}
	return strings.Join(parts, "; ")
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
