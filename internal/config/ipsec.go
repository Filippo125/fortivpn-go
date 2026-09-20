package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
)

const maxIPsecCredentialsSize = 64 * 1024

// Secret prevents credentials from being exposed by common formatting verbs.
type Secret string

func (Secret) String() string   { return "<redacted>" }
func (Secret) GoString() string { return "<redacted>" }

// IPsecCredentials contains the user-provided values needed to configure an
// IPsec connection. Runtime-only connection options belong to the IPsec
// backend and are intentionally not represented here.
type IPsecCredentials struct {
	Gateway  netip.Addr
	Username string
	Password Secret
	PSK      Secret
}

// LoadIPsecCredentials reads a bounded JSON credentials file and verifies that
// it is a regular file accessible only by its owner.
func LoadIPsecCredentials(path string) (IPsecCredentials, error) {
	file, err := os.Open(path)
	if err != nil {
		return IPsecCredentials{}, fmt.Errorf("open IPsec credentials: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return IPsecCredentials{}, fmt.Errorf("stat IPsec credentials: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return IPsecCredentials{}, errors.New("IPsec credentials must be a regular file readable only by its owner (chmod 600)")
	}
	if info.Size() > maxIPsecCredentialsSize {
		return IPsecCredentials{}, errors.New("IPsec credentials file is too large")
	}

	var raw struct {
		Gateway  string `json:"gateway"`
		Username string `json:"username"`
		Password string `json:"password"`
		PSK      string `json:"psk"`
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxIPsecCredentialsSize+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return IPsecCredentials{}, errors.New("invalid IPsec credentials JSON (expected gateway, username, password, psk)")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return IPsecCredentials{}, errors.New("unexpected trailing data in IPsec credentials")
	}

	gateway, err := netip.ParseAddr(raw.Gateway)
	if err != nil {
		return IPsecCredentials{}, errors.New("IPsec credentials require a literal gateway IP")
	}
	return IPsecCredentials{
		Gateway:  gateway,
		Username: raw.Username,
		Password: Secret(raw.Password),
		PSK:      Secret(raw.PSK),
	}, nil
}
