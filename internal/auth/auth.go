// Package auth provides authentication implementations independent of the
// tunnel data plane.
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
