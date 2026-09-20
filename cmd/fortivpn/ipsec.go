package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
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
Usage: fortivpn ipsec connect [gateway] --remote-id ID [options]
  --config PATH        JSON or YAML configuration file
  --instance SELECTOR  Instance in group/instance form
  --username USER      EAP username (defaults to the selected configuration)
  --password PASSWORD  EAP password (defaults to config; visible in process arguments)
  --password-stdin     Read the EAP password from standard input
  --psk PSK            Pre-shared key (defaults to config; visible in process arguments)
  --credentials FILE   Legacy mode-0600 IPsec credentials JSON
  --transport MODE     udp or experimental tcp (default udp)
  --tcp-port PORT      Remote TCP port (default 4500 with TCP)
  --socket PATH        Local VICI socket (default /var/run/charon.vici)
  --ip-mode MODE       ipv4 or dual (default ipv4)
  --timeout DURATION   Setup deadline (default 30s)
  --duration DURATION  Disconnect after this interval (default until Ctrl-C)
The selected configuration supplies gateway, credentials and IPsec connection defaults.
Routes are obtained from the traffic selectors negotiated with the gateway.
The daemon owns routes and addresses. Disable resolve, osx-attr and updown plugins.
SAML and the SSL-VPN port, realm and insecure settings do not apply to IPsec.
`

type legacyRouteFlags []string

func (r *legacyRouteFlags) String() string         { return strings.Join(*r, ",") }
func (r *legacyRouteFlags) Set(value string) error { *r = append(*r, value); return nil }

func runIPsec(args []string, out io.Writer) error {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprint(out, ipsecUsage)
		return nil
	}
	if len(args) == 0 || args[0] != "connect" {
		return errors.New(ipsecUsage)
	}
	connectArgs := args[1:]
	fileConfig, configPath, err := loadConfig(connectArgs)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("ipsec connect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.String("config", configPath, "")
	instance := fs.String("instance", "", "")
	credentials := fs.String("credentials", "", "")
	username := fs.String("username", fileConfig.Username, "")
	password := fs.String("password", fileConfig.Password, "")
	passwordStdin := fs.Bool("password-stdin", false, "")
	psk := fs.String("psk", fileConfig.PSK, "")
	remoteID := fs.String("remote-id", fileConfig.RemoteID, "")
	socket := fs.String("socket", defaultString(fileConfig.Socket, "/var/run/charon.vici"), "")
	transport := fs.String("transport", defaultString(fileConfig.Transport, "udp"), "")
	tcpPort := fs.Uint("tcp-port", uint(fileConfig.TCPPort), "")
	mode := fs.String("ip-mode", defaultString(fileConfig.IPMode, "ipv4"), "")
	timeout := fs.Duration("timeout", defaultDuration(fileConfig.Timeout, 30*time.Second), "")
	duration := fs.Duration("duration", 0, "")
	var legacyRoutes legacyRouteFlags
	fs.Var(&legacyRoutes, "route", "")
	var gateway string
	if len(connectArgs) > 0 && !strings.HasPrefix(connectArgs[0], "-") {
		gateway = connectArgs[0]
		connectArgs = connectArgs[1:]
	}
	if err := fs.Parse(connectArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(out, ipsecUsage)
			return nil
		}
		return err
	}
	if gateway == "" && fs.NArg() == 1 {
		gateway = fs.Arg(0)
	} else if fs.NArg() != 0 {
		return errors.New(ipsecUsage)
	}
	if configPath == "" && *instance != "" {
		return errors.New("--instance requires --config")
	}
	if configPath != "" && *credentials != "" {
		return errors.New("choose either --config or --credentials")
	}
	if fileConfig.SAML {
		return errors.New("IPsec does not support SAML; set saml: false for this instance")
	}
	if *timeout <= 0 || *duration < 0 {
		return errors.New("IPsec timeout must be positive and duration non-negative")
	}
	if *credentials != "" {
		credentialsConfig, loadErr := appconfig.LoadIPsecCredentials(*credentials)
		if loadErr != nil {
			return loadErr
		}
		if gateway == "" {
			gateway = credentialsConfig.Gateway.String()
		}
		if !flagWasSet(fs, "username") {
			*username = credentialsConfig.Username
		}
		if !flagWasSet(fs, "password") {
			*password = string(credentialsConfig.Password)
		}
		if !flagWasSet(fs, "psk") {
			*psk = string(credentialsConfig.PSK)
		}
	}
	if gateway == "" {
		gateway = fileConfig.Gateway
	}
	if gateway == "" {
		return errors.New("IPsec requires a gateway argument or gateway in --config")
	}
	if *passwordStdin && !flagWasSet(fs, "password") {
		*password = ""
	}
	if *username == "" {
		return errors.New("IPsec requires a username in --config or --username")
	}
	passwordValue, err := passwordForAuthentication(false, *username, *password, *passwordStdin, os.Stdin, os.Stderr)
	if err != nil {
		return err
	}
	if *psk == "" {
		return errors.New("IPsec requires a PSK in --config or --psk")
	}
	ipMode, err := parseIPsecMode(*mode)
	if err != nil {
		return err
	}
	if *tcpPort > 65535 {
		return errors.New("invalid IPsec TCP port")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	setup, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	gatewayAddress, err := resolveIPsecGateway(setup, gateway)
	if err != nil {
		return err
	}
	opts := ipsec.Options{
		Gateway:    gatewayAddress,
		Username:   *username,
		Password:   ipsec.Secret(passwordValue),
		PSK:        ipsec.Secret(*psk),
		Transport:  *transport,
		TCPPort:    uint16(*tcpPort),
		RemoteID:   *remoteID,
		SocketPath: *socket,
		IPMode:     ipMode,
	}
	backend, err := ipsec.New(opts)
	if err != nil {
		return err
	}
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
	fmt.Fprintln(out, "IPsec active. Charon owns addresses and negotiated routes; DNS integration is disabled in the lab daemon.")
	if *duration > 0 {
		var done context.CancelFunc
		ctx, done = context.WithTimeout(ctx, *duration)
		defer done()
	}
	return active.Run(ctx)
}

func parseIPsecMode(value string) (network.IPMode, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "auto", "ipv4":
		return network.IPModeIPv4, nil
	case "dual", "dual-stack", "dualstack":
		return network.IPModeDualStack, nil
	default:
		return "", fmt.Errorf("IPsec ip-mode %q must be ipv4 or dual", value)
	}
}

func resolveIPsecGateway(ctx context.Context, value string) (netip.Addr, error) {
	if address, err := netip.ParseAddr(value); err == nil {
		return address, nil
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", value)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("resolve IPsec gateway %q: %w", value, err)
	}
	for _, address := range addresses {
		if address.Is4() {
			return address, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("IPsec gateway %q has no IPv4 address", value)
}
