package wgconf

import (
	"slices"
	"testing"
)

func TestAllowedIPEntriesMixed(t *testing.T) {
	cfg, err := Parse("[Interface]\n[Peer]\nAllowedIPs = 198.51.100.2/32, 203.0.113.0/24\nallowedips = 198.51.100.3/32\n")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"198.51.100.2/32", "203.0.113.0/24", "198.51.100.3/32"}
	if got := cfg.Peers[0].AllowedIPEntries(); !slices.Equal(got, want) {
		t.Errorf("AllowedIPEntries() = %q, want %q", got, want)
	}
}
