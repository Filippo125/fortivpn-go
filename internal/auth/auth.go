// Package auth provides FortiGate SSL-VPN authentication implementations. Its
// client and session-cookie contract must not be used for IPsec authentication.
package auth

import (
	"context"

	"github.com/Filippo125/fortivpn-go/internal/fortinet"
)

type Secret string

func (Secret) String() string { return "<redacted>" }

type AuthResult struct {
	SessionID Secret
}

func (r *AuthResult) Clear() {
	if r != nil {
		r.SessionID = ""
	}
}

type Authenticator interface {
	Authenticate(ctx context.Context, client *fortinet.Client) (*AuthResult, error)
}
