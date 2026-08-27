package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/filippoferrazini/fortivpn-go/internal/auth"
	"github.com/filippoferrazini/fortivpn-go/internal/fortinet"
	"github.com/filippoferrazini/fortivpn-go/internal/network"
)

const usage = `Usage:
  fortivpn inspect <gateway> --saml [options]
  fortivpn inspect <gateway> --username <username> --password <password> [options]

Options:
  --port <port>          Gateway HTTPS port (default 443)
  --realm <realm>        FortiGate authentication realm

Authentication:
  --saml                 Authenticate through the system browser
  --username <username>  VPN username
  --password <password>  VPN password (visible in process arguments)
  --timeout <duration>   SAML authentication timeout (default 5m)
  --insecure             Disable TLS certificate verification (unsafe)
  --debug                Print redacted HTTP control-plane diagnostics
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
	if args[0] != "inspect" {
		return fmt.Errorf("unknown command %q\n%s", args[0], usage)
	}

	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	port := fs.Int("port", 0, "")
	realm := fs.String("realm", "", "")
	saml := fs.Bool("saml", false, "")
	username := fs.String("username", "", "")
	password := fs.String("password", "", "")
	insecure := fs.Bool("insecure", false, "")
	debug := fs.Bool("debug", false, "")
	timeout := fs.Duration("timeout", 5*time.Minute, "")
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
	if gateway == "" || fs.NArg() > 1 {
		return fmt.Errorf("inspect requires exactly one gateway\n%s", usage)
	}
	if *saml && (*username != "" || *password != "") {
		return errors.New("choose either --saml or --username/--password")
	}
	if !*saml && (*username == "" || *password == "") {
		return errors.New("provide --saml or both --username and --password")
	}
	if *timeout <= 0 {
		return errors.New("--timeout must be greater than zero")
	}

	client, err := fortinet.NewClient(fortinet.ClientOptions{
		Gateway:  gateway,
		Port:     *port,
		Insecure: *insecure,
	})
	if err != nil {
		return err
	}
	if *debug {
		client.SetDebugWriter(out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	fmt.Fprintf(out, "Gateway: %s\n", client.Gateway())
	var authenticator auth.Authenticator
	authenticationName := "Username/password"
	if *saml {
		authenticationName = "SAML"
		authenticator = &auth.SAMLAuthenticator{
			Realm: *realm,
			OpenURL: func(rawURL string) error {
				fmt.Fprintln(out, "Opening browser for SAML authentication…")
				return auth.OpenBrowser(rawURL)
			},
		}
	} else {
		authenticator = &auth.PasswordAuthenticator{Username: *username, Password: auth.Secret(*password), Realm: *realm}
	}
	result, err := authenticator.Authenticate(ctx, client)
	if err != nil {
		return err
	}
	defer result.Clear()
	fmt.Fprintf(out, "Authentication: %s OK\n", authenticationName)

	config, err := client.NetworkConfig(ctx)
	if err != nil {
		return err
	}
	printConfig(out, config)
	return nil
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
