package iface

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRecoverApplyPhases(t *testing.T) {
	for _, tc := range []struct {
		name          string
		phase         applyPhase
		device        string
		alreadyUndone bool
		failShow      bool
		wantApplied   bool
		wantRestarts  int
	}{
		{name: "before restart", phase: phasePrepared},
		{name: "detach during restart", phase: phaseRestarting, wantApplied: true, wantRestarts: 1},
		{name: "attach during restart", phase: phaseRestarting, device: "awg2", wantApplied: true, wantRestarts: 1},
		{name: "attach cannot be resumed", phase: phaseRestarting, device: "awg2", failShow: true, wantRestarts: 2},
		{name: "rollback awaiting restart", phase: phaseRollback, alreadyUndone: true, wantRestarts: 1},
		{name: "committed awaiting removal", phase: phaseCommitted, wantApplied: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.yaml")
			backup := configPath + ".bak-test"
			before, after := []byte("original YAML"), []byte("edited YAML")
			host := &FakeHost{Files: map[string][]byte{configPath: after, backup: before}}
			if tc.alreadyUndone {
				host.Files[configPath] = before
			}
			r := Request{Version: RequestVersion, Action: ActionDetach, ID: "awg2",
				CreatedAt: "2026-11-24T01:00:00Z", Detach: &DetachPayload{ID: "awg2"}}
			if tc.device != "" {
				r.Action = ActionAttach
				r.Detach = nil
				r.Attach = &AttachPayload{Device: tc.device}
				r.Attach.Block.ID = r.ID
			}
			queue := filepath.Join(dir, "requests")
			name, err := Save(queue, r)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			j := applyJournal{Phase: tc.phase, Queue: queue, Name: name, Request: revision(raw),
				Backup: backup, Before: revision(before), After: revision(after), Device: tc.device}
			if err := j.save(configPath); err != nil {
				t.Fatal(err)
			}
			showCalls := 0
			show := func(_, device string) error {
				showCalls++
				if device != tc.device {
					t.Errorf("unexpected device %q", device)
				}
				if tc.failShow {
					return errors.New("device unavailable")
				}
				return nil
			}
			recovered, err := recoverApply(configPath, host, show)
			if err != nil || !recovered {
				t.Fatalf("recovery = %v, %v", recovered, err)
			}
			reqs, err := List(queue)
			if err != nil {
				t.Fatal(err)
			}
			want := before
			if tc.wantApplied {
				want = after
			}
			if string(host.Files[configPath]) != string(want) || (len(reqs) == 0) != tc.wantApplied {
				t.Fatalf("unexpected recovery result: YAML %q, queue length %d", host.Files[configPath], len(reqs))
			}
			restarts := 0
			for _, call := range host.Calls {
				if call == "systemctl restart "+PanelUnit {
					restarts++
				}
			}
			if restarts != tc.wantRestarts || (showCalls == 1) != (tc.device != "") {
				t.Fatalf("restarts = %d, device checks = %d", restarts, showCalls)
			}
			calls := len(host.Calls)
			if recovered, err := recoverApply(configPath, host, show); recovered || err != nil || len(host.Calls) != calls {
				t.Fatalf("repeated recovery = %v, %v, calls %v", recovered, err, host.Calls[calls:])
			}
		})
	}
}

func TestRecoverApplyPreservesManualEdit(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	host := &FakeHost{Files: map[string][]byte{configPath: []byte("operator edit")}}
	j := applyJournal{Phase: phaseRestarting, Before: revision([]byte("before")), After: revision([]byte("after"))}
	if err := j.save(configPath); err != nil {
		t.Fatal(err)
	}
	if _, err := RecoverApply(configPath, host); err == nil {
		t.Fatal("recovery accepted a different config revision")
	}
	if string(host.Files[configPath]) != "operator edit" {
		t.Fatal("recovery overwrote the operator edit")
	}
	for _, call := range host.Calls {
		if strings.HasPrefix(call, "write ") || strings.HasPrefix(call, "systemctl ") {
			t.Fatalf("unexpected mutation: %s", call)
		}
	}
	if _, err := os.Stat(journalPath(configPath)); err != nil {
		t.Fatal(err)
	}
}

func TestApplyConfirmedRequiresSameRequest(t *testing.T) {
	queue := t.TempDir()
	r := Request{Version: RequestVersion, Action: ActionDetach, ID: "awg2",
		CreatedAt: "2026-11-24T01:00:00Z", Detach: &DetachPayload{ID: "awg2"}}
	name, err := Save(queue, r)
	if err != nil {
		t.Fatal(err)
	}
	r.Name = name
	replacement := r
	replacement.Detach = &DetachPayload{ID: r.ID, Peers: 1}
	raw, err := json.Marshal(replacement)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(queue, name), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ApplyConfirmed(queue, r, func(Request) error {
		t.Fatal("apply called for a changed request")
		return nil
	}); err == nil {
		t.Fatal("changed request accepted")
	}
	reqs, err := List(queue)
	if err != nil || !reflect.DeepEqual(reqs, []Request{replacement}) {
		t.Fatalf("queue changed: %v, %v", reqs, err)
	}
}
