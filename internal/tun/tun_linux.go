//go:build linux

package tun

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/Filippo125/fortivpn-go/internal/network"
	"golang.org/x/sys/unix"
)

const linuxTunDevice = "/dev/net/tun"

// linuxTun is a kernel TUN device opened with IFF_NO_PI, so reads and writes
// contain bare IPv4 or IPv6 packets just like Device promises.
type linuxTun struct {
	file *os.File
	name string
}

// Create opens an automatically named Linux TUN device. It requires access to
// /dev/net/tun and CAP_NET_ADMIN (normally provided by running as root).
func Create() (Device, error) {
	file, err := os.OpenFile(linuxTunDevice, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", linuxTunDevice, err)
	}

	request, err := unix.NewIfreq("tun%d")
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("prepare TUN interface request: %w", err)
	}
	request.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(int(file.Fd()), unix.TUNSETIFF, request); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("create Linux TUN interface: %w", err)
	}
	name := request.Name()
	if name == "" {
		_ = file.Close()
		return nil, fmt.Errorf("create Linux TUN interface: kernel returned an empty interface name")
	}
	return &linuxTun{file: file, name: name}, nil
}

func (d *linuxTun) Name() string { return d.name }

func (d *linuxTun) Read(packet []byte) (int, error) { return d.file.Read(packet) }

func (d *linuxTun) Write(packet []byte) (int, error) { return d.file.Write(packet) }

func (d *linuxTun) Close() error { return d.file.Close() }

// Configure applies the allocated addresses and MTU with iproute2, which is
// provided by the iproute2 package on Ubuntu 22.04 and later.
func (d *linuxTun) Configure(ctx context.Context, config Config) error {
	if err := ValidateConfig(config); err != nil {
		return err
	}
	if config.MTU > 0 {
		if err := d.ip(ctx, "link", "set", "dev", d.name, "mtu", fmt.Sprint(config.MTU)); err != nil {
			return err
		}
	}
	if config.IPv4 != nil {
		if err := d.configureAddress(ctx, *config.IPv4, false); err != nil {
			return err
		}
	}
	if config.IPv6 != nil {
		if err := d.configureAddress(ctx, *config.IPv6, true); err != nil {
			return err
		}
	}
	return d.ip(ctx, "link", "set", "dev", d.name, "up")
}

func (d *linuxTun) configureAddress(ctx context.Context, config network.IPConfig, ipv6 bool) error {
	return d.ip(ctx, linuxAddressArgs(config, d.name, ipv6)...)
}

func linuxAddressArgs(config network.IPConfig, device string, ipv6 bool) []string {
	args := []string{"address", "add", config.Address.String()}
	if config.Gateway.IsValid() {
		args = append(args, "peer", config.Gateway.String())
	}
	args = append(args, "dev", device)
	if ipv6 {
		return append([]string{"-6"}, args...)
	}
	return append([]string{"-4"}, args...)
}

func (d *linuxTun) ip(ctx context.Context, args ...string) error {
	command := exec.CommandContext(ctx, "ip", args...)
	output, err := command.CombinedOutput()
	if err == nil {
		return nil
	}
	message := strings.TrimSpace(string(output))
	if message == "" {
		return fmt.Errorf("configure %s: ip %s: %w", d.name, strings.Join(args, " "), err)
	}
	return fmt.Errorf("configure %s: ip %s: %w: %s", d.name, strings.Join(args, " "), err, message)
}

var _ Device = (*linuxTun)(nil)
var _ Configurer = (*linuxTun)(nil)
