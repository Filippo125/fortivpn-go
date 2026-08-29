package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/filippoferrazini/fortivpn-go/internal/fortinet"
)

// PasswordAuthenticator implements the traditional FortiGate form login.
// Password is a Secret so accidental formatting always redacts it.
type PasswordAuthenticator struct {
	Username string
	Password Secret
	Realm    string
}

func (a *PasswordAuthenticator) Authenticate(ctx context.Context, client *fortinet.Client) (*AuthResult, error) {
	if strings.TrimSpace(a.Username) == "" || a.Password == "" {
		return nil, fmt.Errorf("username and password are required")
	}
	if err := client.AuthenticatePassword(ctx, a.Username, string(a.Password), a.Realm); err != nil {
		if errors.Is(err, fortinet.ErrInvalidPassword) {
			return nil, err
		}
		return nil, fmt.Errorf("authenticate with username and password: %w", err)
	}
	return &AuthResult{}, nil
}
