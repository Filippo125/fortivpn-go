package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"

	appconfig "github.com/Filippo125/fortivpn-go/internal/config"
)

const addInstanceUsage = `Usage:
  fortivpn config add-instance --config FILE --instance <group\instance> [options]

Instance options:
  --gateway <host>       FortiGate hostname or address
  --port <port>          Gateway HTTPS port
  --realm <realm>        Authentication realm
  --username <username>  VPN username
  --password <password>  VPN password (visible in process arguments)
  --saml[=true|false]     Enable or disable SAML
  --ip-mode <mode>       auto, ipv4, ipv6, or dual
  --browser <browser>    SAML browser
  --timeout <duration>   Authentication timeout
  --insecure[=true|false] Disable TLS certificate verification
`

func runConfig(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(out, addInstanceUsage)
		return nil
	}
	if args[0] != "add-instance" {
		return fmt.Errorf("unknown config command %q\n%s", args[0], addInstanceUsage)
	}
	return runAddInstance(args[1:], out)
}

func runAddInstance(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("config add-instance", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("config", "", "")
	selector := fs.String("instance", "", "")
	gateway := fs.String("gateway", "", "")
	port := fs.Int("port", 0, "")
	realm := fs.String("realm", "", "")
	username := fs.String("username", "", "")
	password := fs.String("password", "", "")
	ipMode := fs.String("ip-mode", "", "")
	browser := fs.String("browser", "", "")
	timeout := fs.Duration("timeout", 0, "")
	var saml optionalBool
	var insecure optionalBool
	fs.Var(&saml, "saml", "")
	fs.Var(&insecure, "insecure", "")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w\n%s", err, addInstanceUsage)
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("config add-instance does not accept positional arguments\n%s", addInstanceUsage)
	}
	if *path == "" || *selector == "" {
		return errors.New("config add-instance requires --config and --instance")
	}
	group, name, err := appconfig.ParseInstanceSelector(*selector)
	if err != nil {
		return err
	}
	instance := appconfig.Instance{Name: name, Group: group, Gateway: *gateway, Realm: *realm}
	if flagWasSet(fs, "port") {
		instance.Port = port
	}
	if flagWasSet(fs, "username") {
		instance.Username = username
	}
	if flagWasSet(fs, "password") {
		instance.Password = password
	}
	if flagWasSet(fs, "ip-mode") {
		instance.IPMode = ipMode
	}
	if flagWasSet(fs, "browser") {
		instance.Browser = browser
	}
	if flagWasSet(fs, "timeout") {
		value := appconfig.Duration(*timeout)
		instance.Timeout = &value
	}
	if saml.set {
		instance.SAML = &saml.value
	}
	if insecure.set {
		instance.Insecure = &insecure.value
	}
	if err := appconfig.AddInstance(*path, instance); err != nil {
		return err
	}
	fmt.Fprintf(out, "Added instance %s to %s\n", *selector, *path)
	return nil
}

type optionalBool struct {
	set   bool
	value bool
}

func (value *optionalBool) Set(raw string) error {
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return err
	}
	value.set = true
	value.value = parsed
	return nil
}

func (*optionalBool) IsBoolFlag() bool { return true }

func (value *optionalBool) String() string {
	if value == nil || !value.set {
		return ""
	}
	return strconv.FormatBool(value.value)
}

var _ flag.Getter = (*optionalBool)(nil)

func (value *optionalBool) Get() any { return value.value }
