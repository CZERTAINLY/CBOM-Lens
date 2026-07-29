// Package portscanner defines the interface shared by internal/nmap and
// internal/zgrab. Any implementation that satisfies Scanner can be used
// interchangeably wherever port-based TLS/SSH scanning is required.
package portscanner

import (
	"context"
	"net/netip"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
)

// Scanner is the runtime interface for port scanners.
// Builder methods (WithPorts, WithNmapBinary, etc.) are intentionally excluded
// because they return the concrete type; this interface covers the callable
// scanning surface used by Lens.
type Scanner interface {
	Scan(ctx context.Context, addr netip.Addr) (model.Nmap, error)
}
