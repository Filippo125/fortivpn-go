package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	appconfig "github.com/Filippo125/fortivpn-go/internal/config"
	"github.com/Filippo125/fortivpn-go/internal/ipsec"
	"github.com/Filippo125/fortivpn-go/internal/network"
)

const ipsecUsage = `Experimental IKEv2 PSK/EAP client (dedicated strongSwan daemon required).
Usage: fortivpn ipsec connect --credentials FILE --remote-id ID --route PREFIX [--route PREFIX] [options]
  --transport MODE     udp or experimental tcp (default udp)
  --tcp-port PORT      Remote TCP port (default 4500 with TCP)
  --socket PATH        Local VICI socket (default /var/run/charon.vici)
  --ip-mode MODE       ipv4 or dual (default ipv4)
  --timeout DURATION   Setup deadline (default 30s)
  --duration DURATION  Disconnect after this interval (default until Ctrl-C)
Credentials are a mode-0600 JSON file with gateway, username, password, and psk.
The daemon owns routes and addresses. Disable resolve, osx-attr and updown plugins.
This experimental command does not accept SSL-VPN config, port, realm or insecure options.
`

type routeFlags []string

func (r *routeFlags) String() string         { return strings.Join(*r, ",") }
func (r *routeFlags) Set(value string) error { *r = append(*r, value); return nil }

func runIPsec(args []string, out io.Writer) error {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprint(out, ipsecUsage)
		return nil
	}
	if len(args) == 0 || args[0] != "connect" {
		return errors.New(ipsecUsage)
	}
	fs := flag.NewFlagSet("ipsec connect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	credentials := fs.String("credentials", "", "")
	remoteID := fs.String("remote-id", "", "")
	socket := fs.String("socket", "/var/run/charon.vici", "")
	transport := fs.String("transport", "udp", "")
	tcpPort := fs.Uint("tcp-port", 0, "")
	mode := fs.String("ip-mode", "ipv4", "")
	timeout := fs.Duration("timeout", 30*time.Second, "")
	duration := fs.Duration("duration", 0, "")
	var routes routeFlags
	fs.Var(&routes, "route", "")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(out, ipsecUsage)
			return nil
		}
		return err
	}
	if fs.NArg() != 0 || *credentials == "" {
		return errors.New(ipsecUsage)
	}
	if *timeout <= 0 || *duration < 0 {
		return errors.New("IPsec timeout must be positive and duration non-negative")
	}
	credentialsConfig, err := appconfig.LoadIPsecCredentials(*credentials)
	if err != nil {
		return err
	}
	opts := ipsec.Options{
		Gateway:  credentialsConfig.Gateway,
		Username: credentialsConfig.Username,
		Password: ipsec.Secret(credentialsConfig.Password),
		PSK:      ipsec.Secret(credentialsConfig.PSK),
	}
	if *tcpPort > 65535 {
		return errors.New("invalid IPsec TCP port")
	}
	opts.Transport = *transport
	opts.TCPPort = uint16(*tcpPort)
	opts.RemoteID = *remoteID
	opts.SocketPath = *socket
	opts.IPMode = network.IPMode(*mode)
	for _, raw := range routes {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return errors.New("invalid IPsec route prefix")
		}
		opts.Routes = append(opts.Routes, p)
	}
	backend, err := ipsec.New(opts)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	setup, cancel := context.WithTimeout(ctx, *timeout)
	active, err := backend.Connect(setup)
	cancel()
	if err != nil {
		return err
	}
	defer active.Close()
	info := active.Info()
	fmt.Fprintf(out, "Gateway: %s\nProtocol: IKEv2 / strongSwan (experimental)\n", info.Gateway)
	if opts.Transport == "tcp" {
		port := opts.TCPPort
		if port == 0 {
			port = 4500
		}
		fmt.Fprintf(out, "Transport: TCP/%d (experimental, userspace ESP)\n", port)
	} else {
		fmt.Fprintln(out, "Transport: UDP / NAT-T")
	}
	printConfig(out, info.Config)
	fmt.Fprintln(out, "IPsec active. Charon owns addresses and split routes; DNS integration is disabled in the lab daemon.")
	if *duration > 0 {
		var done context.CancelFunc
		ctx, done = context.WithTimeout(ctx, *duration)
		defer done()
	}
	return active.Run(ctx)
}
