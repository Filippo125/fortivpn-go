//go:build darwin

package tun

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"github.com/Filippo125/fortivpn-go/internal/network"
)

const (
	afSystem          = 32
	afSysControl      = 2
	sysProtoControl   = 2
	ctlIOCGInfo       = 0xc0644e03
	utunControlName   = "com.apple.net.utun_control"
	utunOptIfName     = 2
	utunHeaderSize    = 4
	afInet            = 2
	afInet6           = 30
	maxKernelCtrlName = 96
)

type controlInfo struct {
	ID   uint32
	Name [maxKernelCtrlName]byte
}

type sockaddrCtl struct {
	Len      uint8
	Family   uint8
	SysAddr  uint16
	ID       uint32
	Unit     uint32
	Reserved [5]uint32
}

type utun struct {
	file *os.File
	name string
}

// Create opens an automatically numbered, native macOS utun interface. The
// device disappears when Close is called; callers own that lifecycle.
func Create() (Device, error) {
	fd, err := syscall.Socket(afSystem, syscall.SOCK_DGRAM, sysProtoControl)
	if err != nil {
		return nil, fmt.Errorf("open utun control socket: %w", err)
	}
	if err := configureControl(fd); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	name, err := interfaceName(fd)
	if err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	return &utun{file: os.NewFile(uintptr(fd), name), name: name}, nil
}

func configureControl(fd int) error {
	info := controlInfo{}
	copy(info.Name[:], utunControlName)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(ctlIOCGInfo), uintptr(unsafe.Pointer(&info))); errno != 0 {
		return fmt.Errorf("look up utun control: %w", errno)
	}
	address := sockaddrCtl{
		Len:     uint8(unsafe.Sizeof(sockaddrCtl{})),
		Family:  afSystem,
		SysAddr: afSysControl,
		ID:      info.ID,
		// Unit 0 lets macOS allocate the next available utun number.
		Unit: 0,
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&address)), uintptr(unsafe.Sizeof(address))); errno != 0 {
		return fmt.Errorf("connect utun control: %w", errno)
	}
	return nil
}

func interfaceName(fd int) (string, error) {
	var buffer [64]byte
	size := uint32(len(buffer))
	if _, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), uintptr(sysProtoControl), uintptr(utunOptIfName), uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)), 0); errno != 0 {
		return "", fmt.Errorf("read utun interface name: %w", errno)
	}
	name := strings.TrimRight(string(buffer[:size]), "\x00")
	if name == "" {
		return "", errors.New("kernel returned an empty utun interface name")
	}
	return name, nil
}

func (d *utun) Name() string { return d.name }

func (d *utun) Read(packet []byte) (int, error) {
	if len(packet) < utunHeaderSize+1 {
		return 0, io.ErrShortBuffer
	}
	n, err := d.file.Read(packet)
	if n <= utunHeaderSize {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return 0, err
	}
	copy(packet, packet[utunHeaderSize:n])
	return n - utunHeaderSize, err
}

func (d *utun) Write(packet []byte) (int, error) {
	frame, err := framePacket(packet)
	if err != nil {
		return 0, err
	}
	n, err := d.file.Write(frame)
	if n > utunHeaderSize {
		n -= utunHeaderSize
	} else {
		n = 0
	}
	return n, err
}

func (d *utun) Close() error { return d.file.Close() }

func (d *utun) Configure(ctx context.Context, config Config) error {
	if err := ValidateConfig(config); err != nil {
		return err
	}
	if config.MTU > 0 {
		if err := d.ifconfig(ctx, "mtu", fmt.Sprint(config.MTU)); err != nil {
			return err
		}
	}
	if config.IPv4 != nil {
		if err := d.configureIPv4(ctx, *config.IPv4); err != nil {
			return err
		}
	}
	if config.IPv6 != nil {
		if err := d.ifconfig(ctx, "inet6", config.IPv6.Address.String(), "up"); err != nil {
			return err
		}
	}
	if config.IPv4 == nil && config.IPv6 == nil {
		return d.ifconfig(ctx, "up")
	}
	return nil
}

func (d *utun) configureIPv4(ctx context.Context, config network.IPConfig) error {
	peer := config.Gateway
	if !peer.IsValid() {
		peer = config.Address.Addr()
	}
	return d.ifconfig(ctx, "inet", config.Address.Addr().String(), peer.String(), "netmask", ipv4Netmask(config.Address.Bits()), "up")
}

func (d *utun) ifconfig(ctx context.Context, args ...string) error {
	arguments := append([]string{d.name}, args...)
	command := exec.CommandContext(ctx, "/sbin/ifconfig", arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message != "" {
			return fmt.Errorf("configure %s: %w: %s", d.name, err, message)
		}
		return fmt.Errorf("configure %s: %w", d.name, err)
	}
	return nil
}

func ipv4Netmask(bits int) string {
	if bits == 0 {
		return "0.0.0.0"
	}
	mask := ^uint32(0) << (32 - bits)
	return fmt.Sprintf("%d.%d.%d.%d", byte(mask>>24), byte(mask>>16), byte(mask>>8), byte(mask))
}

func framePacket(packet []byte) ([]byte, error) {
	var family uint32
	switch IPVersion(packet) {
	case 4:
		family = afInet
	case 6:
		family = afInet6
	default:
		return nil, errors.New("utun accepts only IPv4 or IPv6 packets")
	}
	frame := make([]byte, utunHeaderSize+len(packet))
	binary.BigEndian.PutUint32(frame[:utunHeaderSize], family)
	copy(frame[utunHeaderSize:], packet)
	return frame, nil
}

var _ Device = (*utun)(nil)
var _ Configurer = (*utun)(nil)
