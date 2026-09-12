// Package session defines the protocol-neutral VPN lifecycle. Authentication
// credentials and transport details belong to the concrete backend.
package session

import (
	"context"

	"github.com/Filippo125/fortivpn-go/internal/network"
)

// Backend establishes a session, including its network configuration. On error
// it must release all resources acquired during setup. The setup context does
// not control the lifetime of a successfully returned session.
type Backend interface {
	Connect(context.Context) (Session, error)
}

// Info is the negotiated, read-only session description. Interface may be empty
// for backends whose operating system does not expose a named interface.
type Info struct {
	Gateway   string
	Interface string
	Config    *network.Config
}

// Session owns its interface, routes, transport, and teardown. Run is called
// once, blocks until disconnect or cancellation, and releases all owned state
// before returning. Close is idempotent and may be called concurrently with Run.
// Callers must also defer Close after Connect in case Run is never reached.
// OS-managed backends need not expose packets or use a TUN device.
type Session interface {
	Info() Info
	Run(context.Context) error
	Close() error
}
