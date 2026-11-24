package issuer

import (
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/store"
	"github.com/Jkaotlic/awg3-panel/internal/wgconf"
)

func TestRepeatedRouteIsOwnedAndReserved(t *testing.T) {
	cfg, err := wgconf.Parse("[Interface]\nAddress = 198.51.100.1/24\n[Peer]\nAllowedIPs = 198.51.100.2/32, 203.0.113.0/24\nallowedips = 198.51.100.3/32\n")
	if err != nil {
		t.Fatal(err)
	}
	if owner, ok := peerHoldingAddress(cfg, "198.51.100.3/32"); !ok || owner != cfg.Peers[0] {
		t.Error("second AllowedIPs directive did not reserve the address for this peer")
	}
	got, err := AllocateAddress(cfg.Interface.Get("Address"), usedAddresses(cfg, &store.State{}))
	if err != nil || got != "198.51.100.4/32" {
		t.Fatalf("next address = %q, %v; want 198.51.100.4/32", got, err)
	}
}
