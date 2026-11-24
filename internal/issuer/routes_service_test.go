package issuer_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/runtime"
	"github.com/Jkaotlic/awg3-panel/internal/store"
	"github.com/Jkaotlic/awg3-panel/internal/wgconf"
)

const extraNet = "203.0.113.0/24"
const extraV6 = "2001:db8::/64"

// Capture the complete storage tree (including absent files), without logging contents.
func routeTree(t *testing.T, root string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// The stable lock inode contains no application data.
		if strings.HasSuffix(path, ".awg3panel.lock") {
			return nil
		}
		if d.IsDir() {
			files[path] = "directory"
			return nil
		}
		b, err := os.ReadFile(path)
		files[path] = string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func withRoutes(text, addr, routes string) string {
	return strings.Replace(text, "AllowedIPs = "+addr, "aLLoWedIPs = "+routes, 1)
}

func TestUpdateOnePrimaryAmongRoutes(t *testing.T) {
	s, f, cfg := service(t)
	peer, err := s.Add("issued")
	if err != nil {
		t.Fatal(err)
	}
	path := cfg.Interfaces[0].Config
	body := withRoutes(readConf(t, path), peer.Address, "10.11.0.88/32, "+extraNet+"\n# keep\naLLoWedIPs\t=  "+extraV6+",  "+peer.Address)
	body = strings.ReplaceAll(body, "\n", "\r\n")
	if err = os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	f.Conf = body
	if _, err = s.List(); err != nil {
		t.Fatal(err)
	}
	addr := "10.11.0.99/32"
	name := "updated"
	if err = s.Update(peer.ID, issuer.PeerPatch{Address: &addr, Name: &name}); err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(strings.Replace(body, peer.Address, addr, 1), "# awg3panel: issued", "# awg3panel: updated", 1)
	if readConf(t, path) != want {
		t.Error("update changed bytes outside the primary host and name")
	}
}

func TestUpdateAmbiguousWritesNothing(t *testing.T) {
	for _, tc := range []struct {
		name, routes   string
		issued, listed bool
	}{
		{"manual before reconcile", "10.11.0.2/32\nAllowedIPs = 10.11.0.8/32", false, false}, {"manual after reconcile", "10.11.0.2/32\nAllowedIPs = 10.11.0.8/32", false, true}, {"duplicate primary", "10.11.0.4/32, 10.11.0.4/32", true, false}, {"assigned host absent", "10.11.0.8/32", true, false}, {"new address already secondary", "10.11.0.4/32, 10.11.0.99/32", true, false}, {"only network prefix", "10.11.0.8/30", false, false}} {
		t.Run(tc.name, func(t *testing.T) {
			s, f, cfg := service(t)
			id, old := store.PeerID(meKey), "10.11.0.2/32"
			if tc.issued {
				p, err := s.Add("issued")
				if err != nil {
					t.Fatal(err)
				}
				id, old = p.ID, p.Address
			}
			path := cfg.Interfaces[0].Config
			body := withRoutes(readConf(t, path), old, tc.routes)
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			f.Conf = body
			if tc.listed {
				if _, err := s.List(); err != nil {
					t.Fatal(err)
				}
			}
			root := filepath.Dir(path)
			before := routeTree(t, root)
			calls := len(f.Calls)
			addr := "10.11.0.99/32"
			if err := s.Update(id, issuer.PeerPatch{Address: &addr}); !errors.Is(err, issuer.ErrInvalidInput) {
				t.Errorf("expected invalid address selection, got %v", err)
			}
			if !reflect.DeepEqual(before, routeTree(t, root)) {
				t.Error("refused update changed files")
			}
			for _, c := range f.Calls[calls:] {
				if strings.HasPrefix(c, "syncconf ") {
					t.Error("refused update called syncconf")
				}
			}
		})
	}
}

func TestRenameLeavesRouteLinesUntouched(t *testing.T) {
	body := withRoutes(liveConf, "10.11.0.2/32", "10.11.0.2/32\n# keep comment\nAllowedIPs = 10.11.0.8/32, "+extraV6)
	s, _, cfg := serviceWithConf(t, body)
	name := "new"
	if err := s.Update(store.PeerID(meKey), issuer.PeerPatch{Name: &name}); err != nil {
		t.Fatal(err)
	}
	if readConf(t, cfg.Interfaces[0].Config) != strings.Replace(body, "# awg3panel: me", "# awg3panel: new", 1) {
		t.Error("rename altered routes")
	}
}

// The device accepts the new key but loses exactly one extra route on the first sync.
type routeLossRunner struct {
	*runtime.Fake
	lost bool
}

func (r *routeLossRunner) SyncConf(iface, path string) error {
	if err := r.Fake.SyncConf(iface, path); err != nil {
		return err
	}
	if !r.lost {
		r.Conf = strings.Replace(r.Conf, ", "+extraV6, "", 1)
		r.lost = true
	}
	return nil
}
func rotateRoutes(t *testing.T, loss bool) {
	body := withRoutes(liveConf, "10.11.0.2/32", extraNet+"\nAllowedIPs = 10.11.0.2/32, "+extraV6)
	s, f, cfg := serviceWithRunner(t, body, func(f *runtime.Fake) runtime.Runner {
		if loss {
			return &routeLossRunner{Fake: f}
		}
		return f
	})
	path := cfg.Interfaces[0].Config
	seed := bootstrapSeed()
	if err := seed.Save(cfg.Interfaces[0].Storage.State); err != nil {
		t.Fatal(err)
	}
	state := readConf(t, cfg.Interfaces[0].Storage.State)
	issued, err := s.Rotate(store.PeerID(meKey))
	if loss {
		if !errors.Is(err, issuer.ErrPostcondition) {
			t.Fatalf("missing route not detected: %v", err)
		}
		if readConf(t, path) != body || readConf(t, cfg.Interfaces[0].Storage.State) != state {
			t.Error("rollback did not restore original files")
		}
		if _, e := os.Stat(filepath.Join(cfg.Interfaces[0].Storage.Keys, store.PeerID(meKey)+".key")); !os.IsNotExist(e) {
			t.Error("unexpected rotated key after failure")
		}
	} else if err != nil {
		t.Fatal(err)
	} else if issued.Address != "10.11.0.2/32" {
		t.Error("client address is not the single host route")
	}
	parsed, _ := wgconf.Parse(readConf(t, path))
	orig, _ := wgconf.Parse(body)
	if orig.Interface.Bytes(body) != parsed.Interface.Bytes(readConf(t, path)) {
		t.Error("interface changed")
	}
	key := parsed.Peers[0].Get("PublicKey")
	if (key == meKey) != loss {
		t.Error("unexpected key after rotation")
	}
	if !reflect.DeepEqual(parsed.Peers[0].AllowedIPEntries(), []string{extraNet, "10.11.0.2/32", extraV6}) {
		t.Error("file routes changed")
	}
	dump, err := f.Show("awg3")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, line := range strings.Split(dump, "\n") {
		cols := strings.Split(line, "\t")
		if cols[0] == key {
			found = true
			if cols[3] != strings.Join([]string{extraNet, "10.11.0.2/32", extraV6}, ",") {
				t.Error("device routes differ")
			}
		} else if !loss && cols[0] == meKey {
			t.Error("old key still on device")
		}
	}
	if !found {
		t.Error("expected key absent from device")
	}
}
func TestRotateKeepsAllServerRoutes(t *testing.T)    { rotateRoutes(t, false) }
func TestRotateRejectsMissingLiveRoute(t *testing.T) { rotateRoutes(t, true) }

func TestRotateAmbiguousDoesNotIssueClientAddress(t *testing.T) {
	body := withRoutes(liveConf, "10.11.0.2/32", "10.11.0.2/32, 10.11.0.8/32")
	s, _, cfg := serviceWithConf(t, body)
	if _, err := s.List(); err != nil {
		t.Fatal(err)
	}
	before := routeTree(t, filepath.Dir(cfg.Interfaces[0].Config))
	if _, err := s.Rotate(store.PeerID(meKey)); !errors.Is(err, issuer.ErrInvalidInput) {
		t.Fatalf("expected ambiguous-address refusal, got %v", err)
	}
	if !reflect.DeepEqual(before, routeTree(t, filepath.Dir(cfg.Interfaces[0].Config))) {
		t.Error("ambiguous rotation changed files")
	}
}

func TestDisabledUpdateKeepsRoutes(t *testing.T) {
	for _, ambiguous := range []bool{false, true} {
		routes := "10.11.0.2/32, " + extraV6
		if ambiguous {
			routes += ", 10.11.0.8/32"
		}
		body := withRoutes(liveConf, "10.11.0.2/32", routes+"\nAllowedIPs = "+extraNet)
		s, _, cfg := serviceWithConf(t, body)
		id := store.PeerID(meKey)
		if err := s.Disable(id); err != nil {
			t.Fatal(err)
		}
		path := cfg.Interfaces[0].Config
		before := routeTree(t, filepath.Dir(path))
		addr := "10.11.0.99/32"
		err := s.Update(id, issuer.PeerPatch{Address: &addr})
		if ambiguous {
			if !errors.Is(err, issuer.ErrInvalidInput) || !reflect.DeepEqual(before, routeTree(t, filepath.Dir(path))) {
				t.Error("ambiguous disabled update not refused without writes")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if err = s.Enable(id); err != nil {
			t.Fatal(err)
		}
		parsed, _ := wgconf.Parse(readConf(t, path))
		sec, _ := wgconf.FindPeer(parsed, meKey)
		if !reflect.DeepEqual(sec.AllowedIPEntries(), []string{addr, extraV6, extraNet}) {
			t.Error("lost saved routes on update while disabled")
		}
	}
}
func TestUpdateRefusesPoolBoundaries(t *testing.T) {
	for _, addr := range []string{"10.11.0.0/32", "10.11.0.255/32"} {
		s, _, cfg := service(t)
		before := routeTree(t, filepath.Dir(cfg.Interfaces[0].Config))
		if err := s.Update(store.PeerID(meKey), issuer.PeerPatch{Address: &addr}); !errors.Is(err, issuer.ErrInvalidInput) || !reflect.DeepEqual(before, routeTree(t, filepath.Dir(cfg.Interfaces[0].Config))) {
			t.Error("reserved pool address not rejected without writes", addr)
		}
	}
}

type canonicalDump struct{ *runtime.Fake }

func (r canonicalDump) Show(iface string) (string, error) {
	d, e := r.Fake.Show(iface)
	return strings.ReplaceAll(d, "2001:0db8:0000:0000::/64", extraV6), e
}
func TestRotateCanonicalLiveIPv6(t *testing.T) {
	body := withRoutes(liveConf, "10.11.0.2/32", "10.11.0.2/32, 2001:0db8:0000:0000::/64")
	s, _, cfg := serviceWithRunner(t, body, func(f *runtime.Fake) runtime.Runner { return canonicalDump{f} })
	if _, err := s.Rotate(store.PeerID(meKey)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readConf(t, cfg.Interfaces[0].Config), "2001:0db8:0000:0000::/64") {
		t.Error("source route reformatted")
	}
}

func TestDisableEnablePreservesServerPeerOptions(t *testing.T) {
	const options = "Endpoint = [2001:db8::5]:51820\nPersistentKeepalive = 25\n"
	body := strings.Replace(liveConf, "AllowedIPs = 10.11.0.2/32\n", "AllowedIPs = 10.11.0.2/32\n"+options, 1)
	svc, _, cfg := serviceWithConf(t, body)
	id := store.PeerID(meKey)
	if err := svc.Disable(id); err != nil {
		t.Fatal(err)
	}
	if err := svc.Enable(id); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readConf(t, cfg.Interfaces[0].Config), options) {
		t.Fatal("server peer options disappeared")
	}
}

func TestInterruptedPeerChangesRecover(t *testing.T) {
	for _, op := range []string{"rotate", "remove", "update", "disable", "enable"} {
		t.Run(op, func(t *testing.T) {
			s, f, cfg := service(t)
			issued, err := s.Add("issued")
			if err != nil {
				t.Fatal(err)
			}
			if op == "enable" {
				if err := s.Disable(issued.ID); err != nil {
					t.Fatal(err)
				}
			}

			iface := cfg.Interfaces[0]
			original := readConf(t, iface.Config)
			state := readConf(t, iface.Storage.State)
			keyPath := filepath.Join(iface.Storage.Keys, issued.ID+".key")
			key := readConf(t, keyPath)
			interrupted := issuer.New(iface, cfg.Listen, interruptedAddRunner{f})
			func() {
				defer func() {
					if recover() == nil {
						t.Error("interruption not reached")
					}
				}()
				switch op {
				case "rotate":
					_, _ = interrupted.Rotate(issued.ID)
				case "remove":
					_ = interrupted.Remove(issued.ID)
				case "disable":
					_ = interrupted.Disable(issued.ID)
				case "enable":
					_ = interrupted.Enable(issued.ID)

				case "update":
					name := "changed"
					_ = interrupted.Update(issued.ID, issuer.PeerPatch{Name: &name})
				}
			}()
			restored := issuer.New(iface, cfg.Listen, f)
			if err := restored.Recover(); err != nil {
				t.Fatal(err)
			}
			if readConf(t, iface.Config) != original || readConf(t, iface.Storage.State) != state || readConf(t, keyPath) != key {
				t.Fatal("recovery did not roll back all files")
			}
			if _, _, err := restored.ConfigFor(issued.ID); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestExportRefusesDeviceDrift(t *testing.T) {
	s, f, _ := service(t)
	issued, err := s.Add("issued")
	if err != nil {
		t.Fatal(err)
	}
	f.Conf = strings.Replace(f.Conf, issued.Address, "198.51.100.42/32", 1)
	if _, _, err := s.ConfigFor(issued.ID); !errors.Is(err, issuer.ErrStateConflict) {
		t.Fatalf("config export: %v", err)
	}
	if _, err := s.VPNURIFor(issued.ID); !errors.Is(err, issuer.ErrStateConflict) {
		t.Fatalf("URI export: %v", err)
	}
}
