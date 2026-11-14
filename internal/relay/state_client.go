package relay

// state_client.go — wire→local projections for the relay-state payload.
//
// The HTTP call itself lives on controlclient.Client.RelayState (the
// canonical place for "any caller → control" RPCs); this file only
// holds the small internal shapes the BPF reconciler consumes and the
// converter from the wire view to those shapes.

import (
	"encoding/base64"
	"net"
	"time"

	"github.com/NodeOps-app/createos-sandbox/internal/proto"
)

// sessionPeer is one wg-devices peer entry the reconciler needs in raw
// form (Pubkey is the 32-byte key, not base64).
type sessionPeer struct {
	SessionID string
	Pubkey    []byte
	ClientIP  string
	ExpiresAt time.Time
}

type devicePair struct {
	SrcIP string
	DstIP string
}

type relayState struct {
	Sessions      []sessionPeer
	DevicePairs   []devicePair
	DeviceVMPairs []devicePair
}

// toLocalState projects the on-the-wire RelayStateResp (which uses
// base64 pubkeys to stay JSON-clean) into the relay's internal form
// (raw 32-byte pubkeys ready for wgctrl). Drops any session whose
// pubkey is malformed or not 32 bytes, or whose client IP is not IPv4.
func toLocalState(w *proto.RelayStateResp) *relayState {
	out := &relayState{
		Sessions:      make([]sessionPeer, 0, len(w.Sessions)),
		DevicePairs:   make([]devicePair, 0, len(w.DevicePairs)),
		DeviceVMPairs: make([]devicePair, 0, len(w.DeviceVMPairs)),
	}
	for _, s := range w.Sessions {
		pk, err := base64.StdEncoding.DecodeString(s.Pubkey)
		if err != nil || len(pk) != 32 || net.ParseIP(s.ClientIP).To4() == nil {
			continue
		}
		out.Sessions = append(out.Sessions, sessionPeer{
			SessionID: s.SessionID,
			Pubkey:    pk,
			ClientIP:  s.ClientIP,
			ExpiresAt: time.Unix(s.ExpiresAtUnix, 0),
		})
	}
	for _, p := range w.DevicePairs {
		out.DevicePairs = append(out.DevicePairs, devicePair{SrcIP: p.SrcIP, DstIP: p.DstIP})
	}
	for _, p := range w.DeviceVMPairs {
		out.DeviceVMPairs = append(out.DeviceVMPairs, devicePair{SrcIP: p.SrcIP, DstIP: p.DstIP})
	}
	return out
}

// activeAt applies expiry even when control is unavailable. Filter policy pairs
// as well as peers, so expired sessions cannot retain kernel permissions.
func (s *relayState) activeAt(now time.Time) *relayState {
	out := &relayState{}
	active := make(map[string]bool, len(s.Sessions))
	for _, peer := range s.Sessions {
		if !now.Before(peer.ExpiresAt) {
			continue
		}
		out.Sessions = append(out.Sessions, peer)
		active[peer.ClientIP] = true
	}
	for _, pair := range s.DevicePairs {
		if active[pair.SrcIP] && active[pair.DstIP] {
			out.DevicePairs = append(out.DevicePairs, pair)
		}
	}
	for _, pair := range s.DeviceVMPairs {
		if active[pair.SrcIP] || active[pair.DstIP] {
			out.DeviceVMPairs = append(out.DeviceVMPairs, pair)
		}
	}
	return out
}
