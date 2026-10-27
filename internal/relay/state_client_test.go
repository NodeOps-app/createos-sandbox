package relay

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/NodeOps-app/sandbox/internal/proto"
)

func TestCachedStateExpiresWithoutRefresh(t *testing.T) {
	now := time.Unix(1000, 0)
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	state := toLocalState(&proto.RelayStateResp{
		Sessions: []proto.RelaySessionView{
			{ClientIP: "100.64.0.1", Pubkey: key, ExpiresAtUnix: 1010},
			{ClientIP: "100.64.0.2", Pubkey: key, ExpiresAtUnix: 1020},
		},
		DevicePairs: []proto.RelayPairView{
			{SrcIP: "100.64.0.1", DstIP: "100.64.0.2"},
			{SrcIP: "100.64.0.2", DstIP: "100.64.0.1"},
		},
		DeviceVMPairs: []proto.RelayPairView{
			{SrcIP: "100.64.0.1", DstIP: "10.0.0.1"},
			{SrcIP: "10.0.0.1", DstIP: "100.64.0.1"},
			{SrcIP: "100.64.0.2", DstIP: "10.0.0.2"},
		},
	})
	if active := state.activeAt(now); len(active.Sessions) != 2 || len(active.DevicePairs) != 2 || len(active.DeviceVMPairs) != 3 {
		t.Fatalf("lost unexpired permissions: %+v", active)
	}
	// Reuse the same snapshot, as when control polling keeps failing.
	active := state.activeAt(now.Add(10 * time.Second))
	if len(active.Sessions) != 1 || active.Sessions[0].ClientIP != "100.64.0.2" || len(active.DevicePairs) != 0 || len(active.DeviceVMPairs) != 1 || active.DeviceVMPairs[0].SrcIP != "100.64.0.2" {
		t.Fatalf("expired device retained permissions: %+v", active)
	}
	active = state.activeAt(now.Add(20 * time.Second))
	if len(active.Sessions)+len(active.DevicePairs)+len(active.DeviceVMPairs) != 0 {
		t.Fatalf("expired snapshot retained access: %+v", active)
	}
	if len(state.Sessions) != 2 {
		t.Fatal("expiry filtering mutated the cached snapshot")
	}
}
