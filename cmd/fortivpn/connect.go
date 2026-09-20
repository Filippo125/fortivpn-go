package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	appconfig "github.com/Filippo125/fortivpn-go/internal/config"
)

const connectUsage = `Usage: fortivpn connect <group/instance> [--config PATH] [options]

Loads the selected instance and dispatches to its configured protocol.
The default configuration is ~/.config/fortivpn/config.yaml; set
FORTIVPN_CONFIG or pass --config to use another file.
`

func runConnect(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(out, connectUsage)
		return nil
	}
	selector := args[0]
	if strings.HasPrefix(selector, "-") {
		return errors.New(connectUsage)
	}
	if _, _, err := appconfig.ParseInstanceSelector(selector); err != nil {
		return err
	}
	forwarded := args[1:]
	if instance, err := optionValue(forwarded, "instance"); err != nil {
		return err
	} else if instance != "" {
		return errors.New("fortivpn connect takes the instance as its positional argument")
	}
	path, err := configPath(forwarded)
	if err != nil {
		return err
	}
	if path == "" {
		path, err = defaultConfigPath()
		if err != nil {
			return err
		}
	}
	cfg, err := appconfig.Load(path, selector)
	if err != nil {
		return err
	}
	forwarded, err = withoutOption(forwarded, "config")
	if err != nil {
		return err
	}
	backendArgs := append([]string{"--config", path, "--instance", selector}, forwarded...)
	protocol := cfg.Protocol
	if protocol == "" {
		protocol = "sslvpn"
	}
	switch protocol {
	case "ipsec":
		return runIPsec(append([]string{"connect"}, backendArgs...), out)
	case "sslvpn":
		return runTunnelConnect(backendArgs, out)
	default:
		return fmt.Errorf("instance %q has unsupported protocol %q", selector, protocol)
	}
}

func defaultConfigPath() (string, error) {
	if path := os.Getenv("FORTIVPN_CONFIG"); path != "" {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find home directory for default configuration: %w", err)
	}
	return filepath.Join(home, ".config", "fortivpn", "config.yaml"), nil
}

func withoutOption(args []string, name string) ([]string, error) {
	result := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		argument := args[i]
		if argument == "--"+name {
			if i+1 == len(args) {
				return nil, fmt.Errorf("--%s requires a value", name)
			}
			i++
			continue
		}
		if _, found := strings.CutPrefix(argument, "--"+name+"="); found {
			continue
		}
		result = append(result, argument)
	}
	return result, nil
}
