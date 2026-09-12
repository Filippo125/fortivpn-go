package main

import (
	"bufio"
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

	"github.com/Filippo125/fortivpn-go/internal/auth"
	appconfig "github.com/Filippo125/fortivpn-go/internal/config"
	"github.com/Filippo125/fortivpn-go/internal/fortinet"
	"github.com/Filippo125/fortivpn-go/internal/network"
	"github.com/Filippo125/fortivpn-go/internal/sslvpn"
	"github.com/Filippo125/fortivpn-go/internal/tun"
	"golang.org/x/term"
)

const usage = `Usage:
  fortivpn inspect [gateway] --saml [options]
  fortivpn inspect [gateway] --username <username> [--password <password>] [options]
  fortivpn ipsec connect --credentials FILE --remote-id ID --route PREFIX [options]
  fortivpn tun create [options]
  fortivpn tunnel probe [gateway] --saml [options]
  fortivpn tunnel probe [gateway] --username <username> [--password <password>] [options]
  fortivpn tunnel connect [gateway] --saml [options]
  fortivpn tunnel connect [gateway] --username <username> [--password <password>] [options]
  fortivpn config add-instance --config FILE --instance <group\instance> [options]
  fortivpn completion <bash|zsh|fish>

Options:

  --config <path>       JSON or YAML configuration file
  --instance <selector> Instance in group\instance form
  --port <port>          Gateway HTTPS port (default 443)
  --realm <realm>        FortiGate authentication realm
  --ip-mode <mode>       auto, ipv4, ipv6, or dual (default auto)
  --browser <browser>    SAML browser (default chrome; use default for system browser)

Authentication:
  --saml                 Authenticate through the system browser
  --username <username>  VPN username
  --password <password>  VPN password (visible in process arguments)
  --password-stdin       Read the VPN password from standard input
                       Otherwise prompt securely on the terminal
  --timeout <duration>   SAML authentication timeout (default 5m)
  --insecure             Disable TLS certificate verification (unsafe)
  --debug                Print redacted HTTP control-plane diagnostics

TUN options:
  --ipv4 <prefix>        IPv4 prefix, e.g. 10.20.4.12/32
  --ipv4-gateway <addr>  IPv4 peer/gateway address
  --ipv6 <prefix>        IPv6 prefix, e.g. 2001:db8::12/128
  --mtu <bytes>          Interface MTU

Tunnel probe:
  Opens the modern FortiGate TUN endpoint without creating an interface,
  changing routes, or changing DNS. It validates only the authenticated
  transport handshake; it does not create an interface or alter system routes.

Tunnel connect:
  Creates a native TUN interface, applies the addresses and split-tunnel
  routes supplied by the gateway, and forwards IPv4/IPv6 packets until Ctrl-C.
  DNS server settings are reported but left unchanged.
`

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "fortivpn:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(out, usage)
		return nil
	}
	if args[0] == "completion" {
		return runCompletion(args[1:], out)
	}
	if args[0] == "config" {
		return runConfig(args[1:], out)
	}
	if args[0] == "__complete-instances" {
		return completeInstances(args[1:], out)
	}
	if args[0] == "ipsec" {
		return runIPsec(args[1:], out)
	}
	if args[0] != "inspect" {
		if args[0] == "tun" {
			return runTun(args[1:], out)
		}
		if args[0] == "tunnel" {
			return runTunnel(args[1:], out)
		}
		return fmt.Errorf("unknown command %q\n%s", args[0], usage)
	}

	fileConfig, configPath, err := loadConfig(args[1:])
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.String("config", configPath, "")
	fs.String("instance", "", "")
	port := fs.Int("port", fileConfig.Port, "")
	realm := fs.String("realm", fileConfig.Realm, "")
	saml := fs.Bool("saml", fileConfig.SAML, "")
	username := fs.String("username", fileConfig.Username, "")
	password := fs.String("password", fileConfig.Password, "")
	passwordStdin := fs.Bool("password-stdin", false, "")
	insecure := fs.Bool("insecure", fileConfig.Insecure, "")
	debug := fs.Bool("debug", false, "")
	ipMode := fs.String("ip-mode", defaultString(fileConfig.IPMode, string(network.IPModeAuto)), "")
	browser := fs.String("browser", defaultString(fileConfig.Browser, "chrome"), "")
	timeout := fs.Duration("timeout", defaultDuration(fileConfig.Timeout, 5*time.Minute), "")
	inspectArgs := args[1:]
	var gateway string
	// The documented UX is `inspect <gateway> [options]`. The standard flag
	// package stops scanning at the first positional argument, so remove that
	// gateway before parsing the remaining options.
	if len(inspectArgs) > 0 && !strings.HasPrefix(inspectArgs[0], "-") {
		gateway = inspectArgs[0]
		inspectArgs = inspectArgs[1:]
	}
	if err := fs.Parse(inspectArgs); err != nil {
		return fmt.Errorf("%w\n%s", err, usage)
	}
	if gateway == "" && fs.NArg() == 1 {
		gateway = fs.Arg(0)
	}
	if gateway == "" {
		gateway = fileConfig.Gateway
	}
	if gateway == "" || fs.NArg() > 1 {
		return fmt.Errorf("inspect requires a gateway argument or gateway in --config\n%s", usage)
	}
	if *passwordStdin && !flagWasSet(fs, "password") {
		*password = ""
	}
	passwordValue, err := passwordForAuthentication(*saml, *username, *password, *passwordStdin, os.Stdin, os.Stderr)
	if err != nil {
		return err
	}
	*password = passwordValue
	if *timeout <= 0 {
		return errors.New("--timeout must be greater than zero")
	}
	mode, err := parseIPMode(*ipMode)
	if err != nil {
		return err
	}

	var authenticator auth.Authenticator
	if *saml {
		authenticator = &auth.SAMLAuthenticator{Realm: *realm, OpenURL: samlBrowser(*browser, out), OnCallbackListener: samlCallbackListener(out)}
	} else {
		authenticator = &auth.PasswordAuthenticator{Username: *username, Password: auth.Secret(*password), Realm: *realm}
	}
	options := sslvpn.Options{
		Client:         fortinet.ClientOptions{Gateway: gateway, Port: *port, Insecure: *insecure},
		Authenticator:  authenticator,
		IPMode:         mode,
		OnCleanupError: func(err error) { fmt.Fprintf(out, "Warning: %v\n", err) },
	}
	if *debug {
		options.DebugWriter = out
	}
	options.OnAuthenticated = func() {
		name := "Username/password"
		if *saml {
			name = "SAML"
		}
		fmt.Fprintf(out, "Authentication: %s OK\n", name)
	}
	backend, err := sslvpn.New(options)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	fmt.Fprintf(out, "Gateway: %s\n", backend.Gateway())
	config, err := backend.Inspect(ctx)
	if err != nil {
		return err
	}
	printConfig(out, config)
	return nil
}

func runTun(args []string, out io.Writer) error {
	const tunUsage = "Usage: fortivpn tun create [--ipv4 prefix] [--ipv4-gateway addr] [--ipv6 prefix] [--mtu bytes]\n"
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprint(out, tunUsage)
		return nil
	}
	if len(args) == 0 || args[0] != "create" {
		return errors.New(strings.TrimSpace(tunUsage))
	}
	fs := flag.NewFlagSet("tun create", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	ipv4 := fs.String("ipv4", "", "")
	ipv4Gateway := fs.String("ipv4-gateway", "", "")
	ipv6 := fs.String("ipv6", "", "")
	mtu := fs.Int("mtu", 0, "")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(out, tunUsage)
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("tun create does not accept positional arguments")
	}
	config, err := tunConfig(*ipv4, *ipv4Gateway, *ipv6, *mtu)
	if err != nil {
		return err
	}
	device, err := tun.Create()
	if err != nil {
		return err
	}
	defer device.Close()
	configurer, ok := device.(tun.Configurer)
	if !ok {
		return errors.New("native TUN implementation cannot configure the interface")
	}
	if err := configurer.Configure(context.Background(), config); err != nil {
		return err
	}
	fmt.Fprintf(out, "Interface: %s\n", device.Name())
	fmt.Fprintln(out, "Configured without routes or DNS. Press Ctrl-C to remove it.")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	return nil
}

func runTunnel(args []string, out io.Writer) error {
	const tunnelUsage = "Usage: fortivpn tunnel <probe|connect> <gateway> (--saml | --username user [--password password]) [options]\n"
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprint(out, tunnelUsage)
		return nil
	}
	if len(args) == 0 {
		return errors.New(strings.TrimSpace(tunnelUsage))
	}
	switch args[0] {
	case "probe":
		return runTunnelProbe(args[1:], out)
	case "connect":
		return runTunnelConnect(args[1:], out)
	default:
		return errors.New(strings.TrimSpace(tunnelUsage))
	}
}

func runTunnelProbe(args []string, out io.Writer) error {
	const tunnelUsage = "Usage: fortivpn tunnel probe [gateway] (--saml | --username user [--password password]) [options]\n"
	fileConfig, configPath, err := loadConfig(args)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("tunnel probe", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.String("config", configPath, "")
	fs.String("instance", "", "")
	port := fs.Int("port", fileConfig.Port, "")
	realm := fs.String("realm", fileConfig.Realm, "")
	saml := fs.Bool("saml", fileConfig.SAML, "")
	username := fs.String("username", fileConfig.Username, "")
	password := fs.String("password", fileConfig.Password, "")
	passwordStdin := fs.Bool("password-stdin", false, "")
	insecure := fs.Bool("insecure", fileConfig.Insecure, "")
	debug := fs.Bool("debug", false, "")
	ipMode := fs.String("ip-mode", defaultString(fileConfig.IPMode, string(network.IPModeAuto)), "")
	browser := fs.String("browser", defaultString(fileConfig.Browser, "chrome"), "")
	timeout := fs.Duration("timeout", defaultDuration(fileConfig.Timeout, 5*time.Minute), "")
	probeArgs := args
	var gateway string
	if len(probeArgs) > 0 && !strings.HasPrefix(probeArgs[0], "-") {
		gateway = probeArgs[0]
		probeArgs = probeArgs[1:]
	}
	if err := fs.Parse(probeArgs); err != nil {
		return fmt.Errorf("%w\n%s", err, tunnelUsage)
	}
	if gateway == "" && fs.NArg() == 1 {
		gateway = fs.Arg(0)
	}
	if gateway == "" {
		gateway = fileConfig.Gateway
	}
	if gateway == "" || fs.NArg() > 1 {
		return fmt.Errorf("tunnel probe requires a gateway argument or gateway in --config\n%s", tunnelUsage)
	}
	if *passwordStdin && !flagWasSet(fs, "password") {
		*password = ""
	}
	passwordValue, err := passwordForAuthentication(*saml, *username, *password, *passwordStdin, os.Stdin, os.Stderr)
	if err != nil {
		return err
	}
	*password = passwordValue
	if *timeout <= 0 {
		return errors.New("--timeout must be greater than zero")
	}
	mode, err := parseIPMode(*ipMode)
	if err != nil {
		return err
	}

	var authenticator auth.Authenticator
	if *saml {
		authenticator = &auth.SAMLAuthenticator{Realm: *realm, OpenURL: samlBrowser(*browser, out), OnCallbackListener: samlCallbackListener(out)}
	} else {
		authenticator = &auth.PasswordAuthenticator{Username: *username, Password: auth.Secret(*password), Realm: *realm}
	}
	options := sslvpn.Options{
		Client:         fortinet.ClientOptions{Gateway: gateway, Port: *port, Insecure: *insecure},
		Authenticator:  authenticator,
		IPMode:         mode,
		OnCleanupError: func(err error) { fmt.Fprintf(out, "Warning: %v\n", err) },
	}
	if *debug {
		options.DebugWriter = out
	}
	backend, err := sslvpn.New(options)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if err := backend.Probe(ctx); err != nil {
		return err
	}
	fmt.Fprintf(out, "Gateway: %s\n", backend.Gateway())
	fmt.Fprintln(out, "FortiGate TUN endpoint: accepted")
	fmt.Fprintln(out, "No TUN interface, routes, DNS, or packets were changed.")
	return nil
}

func runTunnelConnect(args []string, out io.Writer) error {
	const tunnelUsage = "Usage: fortivpn tunnel connect [gateway] (--saml | --username user [--password password]) [options]\n"
	fileConfig, configPath, err := loadConfig(args)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("tunnel connect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.String("config", configPath, "")
	fs.String("instance", "", "")
	port := fs.Int("port", fileConfig.Port, "")
	realm := fs.String("realm", fileConfig.Realm, "")
	saml := fs.Bool("saml", fileConfig.SAML, "")
	username := fs.String("username", fileConfig.Username, "")
	password := fs.String("password", fileConfig.Password, "")
	passwordStdin := fs.Bool("password-stdin", false, "")
	insecure := fs.Bool("insecure", fileConfig.Insecure, "")
	debug := fs.Bool("debug", false, "")
	ipMode := fs.String("ip-mode", defaultString(fileConfig.IPMode, string(network.IPModeAuto)), "")
	browser := fs.String("browser", defaultString(fileConfig.Browser, "chrome"), "")
	timeout := fs.Duration("timeout", defaultDuration(fileConfig.Timeout, 5*time.Minute), "")
	connectArgs := args
	var gateway string
	if len(connectArgs) > 0 && !strings.HasPrefix(connectArgs[0], "-") {
		gateway = connectArgs[0]
		connectArgs = connectArgs[1:]
	}
	if err := fs.Parse(connectArgs); err != nil {
		return fmt.Errorf("%w\n%s", err, tunnelUsage)
	}
	if gateway == "" && fs.NArg() == 1 {
		gateway = fs.Arg(0)
	}
	if gateway == "" {
		gateway = fileConfig.Gateway
	}
	if gateway == "" || fs.NArg() > 1 {
		return fmt.Errorf("tunnel connect requires a gateway argument or gateway in --config\n%s", tunnelUsage)
	}
	if *passwordStdin && !flagWasSet(fs, "password") {
		*password = ""
	}
	passwordValue, err := passwordForAuthentication(*saml, *username, *password, *passwordStdin, os.Stdin, os.Stderr)
	if err != nil {
		return err
	}
	*password = passwordValue
	if *timeout <= 0 {
		return errors.New("--timeout must be greater than zero")
	}
	mode, err := parseIPMode(*ipMode)
	if err != nil {
		return err
	}

	var authenticator auth.Authenticator
	if *saml {
		authenticator = &auth.SAMLAuthenticator{Realm: *realm, OpenURL: samlBrowser(*browser, out), OnCallbackListener: samlCallbackListener(out)}
	} else {
		authenticator = &auth.PasswordAuthenticator{Username: *username, Password: auth.Secret(*password), Realm: *realm}
	}
	options := sslvpn.Options{
		Client:         fortinet.ClientOptions{Gateway: gateway, Port: *port, Insecure: *insecure},
		Authenticator:  authenticator,
		IPMode:         mode,
		OnCleanupError: func(err error) { fmt.Fprintf(out, "Warning: %v\n", err) },
	}
	if *debug {
		options.DebugWriter = out
	}
	backend, err := sslvpn.New(options)
	if err != nil {
		return err
	}
	sessionCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	setupCtx, cancel := context.WithTimeout(sessionCtx, *timeout)
	defer cancel()
	active, err := backend.Connect(setupCtx)
	if err != nil {
		return err
	}
	defer active.Close()
	cancel()
	info := active.Info()
	config := info.Config
	fmt.Fprintf(out, "Gateway: %s\n", backend.Gateway())
	fmt.Fprintf(out, "Interface: %s\n", info.Interface)
	printConfig(out, config)
	if len(config.DNS) > 0 {
		fmt.Fprintln(out, "\nDNS settings were not changed.")
	}
	fmt.Fprintln(out, "VPN tunnel is active. Press Ctrl-C to disconnect.")
	return active.Run(sessionCtx)
}

func loadConfig(args []string) (appconfig.Config, string, error) {
	path, err := configPath(args)
	if err != nil {
		return appconfig.Config{}, "", err
	}
	if path == "" {
		return appconfig.Config{}, "", nil
	}
	instance, err := optionValue(args, "instance")
	if err != nil {
		return appconfig.Config{}, "", err
	}
	cfg, err := appconfig.Load(path, instance)
	if err != nil {
		return appconfig.Config{}, "", err
	}
	return cfg, path, nil
}

// configPath reads --config before flag parsing so that the file can provide
// defaults to all the remaining command-line flags.
func configPath(args []string) (string, error) {
	return optionValue(args, "config")
}

// optionValue reads a named option before flag parsing so configuration can
// provide defaults for all other flags.
func optionValue(args []string, name string) (string, error) {
	var path string
	for i := 0; i < len(args); i++ {
		argument := args[i]
		if argument == "--"+name {
			if i+1 == len(args) {
				return "", fmt.Errorf("--%s requires a value", name)
			}
			i++
			path = args[i]
			continue
		}
		if value, found := strings.CutPrefix(argument, "--"+name+"="); found {
			if value == "" {
				return "", fmt.Errorf("--%s requires a value", name)
			}
			path = value
		}
	}
	return path, nil
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func defaultDuration(value, fallback time.Duration) time.Duration {
	if value == 0 {
		return fallback
	}
	return value
}

func flagWasSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(current *flag.Flag) {
		if current.Name == name {
			set = true
		}
	})
	return set
}

func parseIPMode(value string) (network.IPMode, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", string(network.IPModeAuto):
		return network.IPModeAuto, nil
	case string(network.IPModeIPv4):
		return network.IPModeIPv4, nil
	case string(network.IPModeIPv6):
		return network.IPModeIPv6, nil
	case string(network.IPModeDualStack), "dual-stack", "dualstack":
		return network.IPModeDualStack, nil
	default:
		return "", fmt.Errorf("invalid --ip-mode %q: use auto, ipv4, ipv6, or dual", value)
	}
}

func samlBrowser(browser string, out io.Writer) func(string) error {
	return func(rawURL string) error {
		fmt.Fprintf(out, "Opening %s for SAML authentication…\n", browser)
		return auth.OpenBrowserWith(rawURL, browser)
	}
}

func samlCallbackListener(out io.Writer) func(string) {
	return func(callbackURL string) {
		fmt.Fprintf(out, "Waiting for SAML callback on %s\n", callbackURL)
	}
}

func passwordForAuthentication(saml bool, username, password string, passwordStdin bool, input *os.File, prompt io.Writer) (string, error) {
	if saml {
		if username != "" || password != "" || passwordStdin {
			return "", errors.New("choose either --saml or --username/--password")
		}
		return "", nil
	}
	if username == "" {
		return "", errors.New("provide --saml or a --username")
	}
	if password != "" {
		if passwordStdin {
			return "", errors.New("choose either --password or --password-stdin")
		}
		return password, nil
	}
	if passwordStdin {
		return readPassword(input)
	}
	return readTerminalPassword(input, prompt)
}

func readTerminalPassword(input *os.File, prompt io.Writer) (string, error) {
	if input == nil || !term.IsTerminal(int(input.Fd())) {
		return "", errors.New("password was not provided; use --password, --password-stdin, or an interactive terminal")
	}
	fmt.Fprint(prompt, "Insert VPN Password: ")
	state, err := term.MakeRaw(int(input.Fd()))
	if err != nil {
		return "", fmt.Errorf("disable terminal echo for VPN password: %w", err)
	}
	password, readErr := readMaskedPassword(input, prompt)
	fmt.Fprint(prompt, "\r\n")
	restoreErr := term.Restore(int(input.Fd()), state)
	if readErr != nil {
		return "", readErr
	}
	if restoreErr != nil {
		return "", fmt.Errorf("restore terminal after VPN password: %w", restoreErr)
	}
	return password, nil
}

func readMaskedPassword(input io.Reader, prompt io.Writer) (string, error) {
	const maxPasswordBytes = 4096
	password := make([]byte, 0, 64)
	var character [1]byte
	for {
		n, err := input.Read(character[:])
		if n > 0 {
			switch character[0] {
			case '\r', '\n':
				if len(password) == 0 {
					return "", errors.New("VPN password is empty")
				}
				return string(password), nil
			case 0x03:
				return "", context.Canceled
			case 0x04:
				return "", io.EOF
			case 0x08, 0x7f:
				if len(password) > 0 {
					password = password[:len(password)-1]
					fmt.Fprint(prompt, "\b \b")
				}
			default:
				if character[0] < 0x20 {
					continue
				}
				if len(password) == maxPasswordBytes {
					return "", errors.New("VPN password is too long")
				}
				password = append(password, character[0])
				fmt.Fprint(prompt, "*")
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return "", errors.New("VPN password input ended before Enter")
			}
			return "", fmt.Errorf("read VPN password from terminal: %w", err)
		}
	}
}

func readPassword(input io.Reader) (string, error) {
	const maxPasswordBytes = 4096
	reader := bufio.NewReader(io.LimitReader(input, maxPasswordBytes+1))
	value, err := reader.ReadString('\n')
	if err != nil {
		if !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("read password from standard input: %w", err)
		}
	}
	if len(value) > maxPasswordBytes {
		return "", errors.New("password from standard input is too long")
	}
	password := strings.TrimSuffix(value, "\n")
	password = strings.TrimSuffix(password, "\r")
	if password == "" {
		return "", errors.New("password from standard input is empty")
	}
	return password, nil
}

func tunConfig(ipv4, ipv4Gateway, ipv6 string, mtu int) (tun.Config, error) {
	config := tun.Config{MTU: mtu}
	var err error
	if config.IPv4, err = parseIPConfig(ipv4, ipv4Gateway, 4); err != nil {
		return tun.Config{}, err
	}
	if config.IPv6, err = parseIPConfig(ipv6, "", 6); err != nil {
		return tun.Config{}, err
	}
	if config.IPv4 == nil && config.IPv6 == nil && config.MTU == 0 {
		return tun.Config{}, errors.New("provide --ipv4, --ipv6, or --mtu")
	}
	return config, tun.ValidateConfig(config)
}

func parseIPConfig(rawPrefix, rawGateway string, family int) (*network.IPConfig, error) {
	if rawPrefix == "" {
		if rawGateway != "" {
			return nil, errors.New("a gateway requires its corresponding IP prefix")
		}
		return nil, nil
	}
	prefix, err := netip.ParsePrefix(rawPrefix)
	if err != nil || (family == 4 && !prefix.Addr().Is4()) || (family == 6 && !prefix.Addr().Is6()) {
		return nil, fmt.Errorf("invalid IPv%d prefix %q", family, rawPrefix)
	}
	config := &network.IPConfig{Address: prefix}
	if rawGateway != "" {
		gateway, err := netip.ParseAddr(rawGateway)
		if err != nil || (family == 4 && !gateway.Is4()) || (family == 6 && !gateway.Is6()) {
			return nil, fmt.Errorf("invalid IPv%d gateway %q", family, rawGateway)
		}
		config.Gateway = gateway
	}
	return config, nil
}

func printConfig(out io.Writer, cfg *network.Config) {
	if cfg.IPv4 != nil {
		fmt.Fprintln(out, "\nIPv4:")
		fmt.Fprintf(out, "  Address: %s\n", cfg.IPv4.Address)
		if cfg.IPv4.Gateway.IsValid() {
			fmt.Fprintf(out, "  Gateway: %s\n", cfg.IPv4.Gateway)
		}
	}
	if cfg.IPv6 != nil {
		fmt.Fprintln(out, "\nIPv6:")
		fmt.Fprintf(out, "  Address: %s\n", cfg.IPv6.Address)
		if cfg.IPv6.Gateway.IsValid() {
			fmt.Fprintf(out, "  Gateway: %s\n", cfg.IPv6.Gateway)
		}
	}
	if len(cfg.DNS) > 0 || len(cfg.Domains) > 0 {
		fmt.Fprintln(out, "\nDNS:")
		for _, addr := range cfg.DNS {
			fmt.Fprintf(out, "  Server: %s\n", addr)
		}
		for _, domain := range cfg.Domains {
			fmt.Fprintf(out, "  Domain: %s\n", domain)
		}
	}
	if len(cfg.Routes4) > 0 || len(cfg.Routes6) > 0 {
		fmt.Fprintln(out, "\nRoutes:")
		for _, route := range cfg.Routes4 {
			fmt.Fprintf(out, "  IPv4: %s\n", route)
		}
		for _, route := range cfg.Routes6 {
			fmt.Fprintf(out, "  IPv6: %s\n", route)
		}
	}
	if cfg.MTU > 0 {
		fmt.Fprintf(out, "\nMTU: %d\n", cfg.MTU)
	}
	if len(cfg.TunnelMethods) > 0 {
		fmt.Fprintln(out, "\nTunnel methods:")
		for _, method := range cfg.TunnelMethods {
			fmt.Fprintf(out, "  - %s\n", method)
		}
	}
	if cfg.Empty() {
		fmt.Fprintln(out, "\nNo network settings were returned by the gateway.")
	}
}
