// Package relay implements `control relay` — the user-device WireGuard
// terminator. See docs/device-vpn.md.
//
// A relay is registered as a host with role='relay'. It joins the
// existing wg-hosts mesh as a regular peer (so it can forward into the
// rest of the fleet) and additionally brings up a separate wg-devices
// iface on a public UDP port, where end-user devices handshake.
//
// Every five seconds, the relay fetches its session and network-policy
// state from control's /v1/internal/relay-state endpoint over mTLS, then
// reconciles wg-devices peers and BPF policy maps. It does not connect
// directly to Postgres or need database credentials.
//
// WireGuard keys and TLS credentials are persisted on disk. On restart,
// the relay reuses that identity, recreates wg-devices without old peers, and
// rebuilds its in-memory reconciliation state from control.
package relay

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/urfave/cli/v2"

	"github.com/NodeOps-app/sandbox/config"
)

// Cli is the urfave/cli Action for `control relay`.
func Cli(c *cli.Context) error {
	cfg, err := config.RelayFromContext(c)
	if err != nil {
		return err
	}
	if cfg.HostID == "" {
		return fmt.Errorf("relay: --host-id required (registers as role=relay)")
	}
	if cfg.PublicEndpoint == "" {
		return fmt.Errorf("relay: --public-endpoint required (e.g. relay-1.example.com:51820)")
	}
	r := New(cfg)
	// Cancel Run on service shutdown so it removes device peers before exit.
	ctx, stop := signal.NotifyContext(c.Context, os.Interrupt, syscall.SIGTERM)
	defer stop()
	return r.Run(ctx)
}
