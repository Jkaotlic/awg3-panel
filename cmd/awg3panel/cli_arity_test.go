//go:build !readonly

package main

import (
	"bytes"
	"maps"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/issuer"
)

func TestCLIMutationsRequireExactlyOneArgument(t *testing.T) {
	for _, cmd := range []string{"add", "rm", "disable", "enable"} {
		t.Run(cmd, func(t *testing.T) {
			svc := cliService(t)
			issued, err := svc.Add("test-peer")
			if err != nil {
				t.Fatal(err)
			}
			arg := issued.ID
			if cmd == "add" {
				arg = "another-peer"
			}
			if cmd == "enable" {
				if err := svc.Disable(issued.ID); err != nil {
					t.Fatal(err)
				}
			}
			for _, tc := range []struct {
				name string
				args []string
			}{
				{name: "missing"},
				{name: "extra", args: []string{arg, "-iface=other"}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					before := cliPeerEnabledStates(t, svc)
					var out bytes.Buffer
					err := runCLI(cmd, tc.args, svc, &out)
					if err == nil || exitCodeFor(err) != exitInvalidInput {
						t.Fatalf("expected CLI input error, got %v", err)
					}
					if out.Len() != 0 {
						t.Error("invalid invocation wrote to stdout")
					}
					if !maps.Equal(before, cliPeerEnabledStates(t, svc)) {
						t.Error("invalid invocation changed peer state")
					}
				})
			}
		})
	}
}

func cliPeerEnabledStates(t *testing.T, svc *issuer.Service) map[string]bool {
	t.Helper()
	peers, err := svc.List()
	if err != nil {
		t.Fatal(err)
	}
	states := make(map[string]bool, len(peers))
	for _, peer := range peers {
		states[peer.ID] = peer.Enabled
	}
	return states
}
