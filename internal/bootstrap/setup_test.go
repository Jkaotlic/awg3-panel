package bootstrap

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupOptions(t *testing.T) Options {
	t.Helper()
	return Options{Root: t.TempDir(), Endpoint: "203.0.113.10", Subnet: "10.66.0.1/24", Egress: "eth0"}
}

func TestIncompletePrepareRejectsMutableContent(t *testing.T) {
	for _, path := range []string{ServerPath, DefaultsPath} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			o := setupOptions(t)
			o.AfterWrite = func(p string) error {
				if p == path {
					return errors.New("interrupted")
				}
				return nil
			}
			if _, err := Prepare(o, rand.Reader); err == nil {
				t.Fatal("fault not reached")
			}
			name := target(o.Root, path)
			b, _ := os.ReadFile(name)
			if path == ServerPath {
				b = append(b, []byte("[Peer]\nPublicKey = foreign\n")...)
			} else {
				b = []byte(`{"version":1,"endpoint":"203.0.113.20:3478"}`)
			}
			if err := os.WriteFile(name, b, 0600); err != nil {
				t.Fatal(err)
			}
			o.AfterWrite = nil
			if _, err := Prepare(o, rand.Reader); err == nil {
				t.Fatal("adopted changed partial configuration")
			}
		})
	}
}

func TestPrepareRejectsUnmanagedStateDirectory(t *testing.T) {
	o := setupOptions(t)
	if err := os.MkdirAll(target(o.Root, "/var/lib/awg3panel/awgtop/keys"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(o, rand.Reader); err == nil {
		t.Fatal("adopted unmanaged state tree")
	}
}

func TestVerifyRejectsAuxiliarySymlinks(t *testing.T) {
	for _, p := range []string{"/var/lib/awg3panel/awgtop/keys", "/var/lib/awg3panel/awgtop/backups", "/var/lib/awg3panel/awgtop/peers.json", "/var/lib/awg3panel-bootstrap/network.owned"} {
		t.Run(filepath.Base(p), func(t *testing.T) {
			o := setupOptions(t)
			if _, err := Prepare(o, rand.Reader); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(t.TempDir(), target(o.Root, p)); err != nil {
				t.Skip("symlink unavailable")
			}
			if err := Verify(o.Root); err == nil {
				t.Fatal("accepted auxiliary symlink")
			}
		})
	}
}

func TestPrepareStableRepeatAndVerify(t *testing.T) {
	o := setupOptions(t)
	r, err := Prepare(o, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(o.Root, strings.TrimPrefix(ServerPath, "/")))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(before), "S1 = ") || r.Listen != "10.66.0.1:8081" {
		t.Fatal("wrong result")
	}
	if err := Verify(o.Root); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(o, rand.Reader); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(o.Root, strings.TrimPrefix(ServerPath, "/")))
	if string(before) != string(after) {
		t.Fatal("repeat rotated configuration")
	}
	changed := o
	changed.Endpoint = "203.0.113.20"
	if _, err := Prepare(changed, rand.Reader); err == nil {
		t.Fatal("adopted changed installation options")
	}
}

func TestPrepareRefusesForeignFileAndTampering(t *testing.T) {
	o := setupOptions(t)
	p := filepath.Join(o.Root, strings.TrimPrefix(ServerPath, "/"))
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(o, rand.Reader); err == nil {
		t.Fatal("overwrote foreign server")
	}
	b, _ := os.ReadFile(p)
	if string(b) != "foreign" {
		t.Fatal("foreign content changed")
	}
	o = setupOptions(t)
	if _, err := Prepare(o, rand.Reader); err != nil {
		t.Fatal(err)
	}
	p = filepath.Join(o.Root, strings.TrimPrefix(ServerPath, "/"))
	if err := os.WriteFile(p, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(o.Root); err == nil {
		t.Fatal("accepted tampered server")
	}
	if _, err := Prepare(o, rand.Reader); err == nil {
		t.Fatal("repaired unknown server silently")
	}
}

func TestPrepareResumeAfterEachWrite(t *testing.T) {
	for stop := 1; stop <= 5; stop++ {
		o := setupOptions(t)
		count := 0
		o.AfterWrite = func(string) error {
			count++
			if count == stop {
				return errors.New("injected interruption")
			}
			return nil
		}
		_, err := Prepare(o, rand.Reader)
		if err == nil {
			t.Fatal("fault not reached")
		}
		o.AfterWrite = nil
		if _, err := Prepare(o, rand.Reader); err != nil {
			t.Fatalf("resume stage %d: %v", stop, err)
		}
		if err := Verify(o.Root); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPrepareRejectsInvalidInputsAndDryRunWritesNothing(t *testing.T) {
	for _, mut := range []func(*Options){func(o *Options) { o.Endpoint = "bad;endpoint" }, func(o *Options) { o.Subnet = "0.0.0.0/0" }, func(o *Options) { o.Subnet = "10.1.0.0/24" }, func(o *Options) { o.Egress = "eth0;reboot" }} {
		o := setupOptions(t)
		mut(&o)
		if _, err := Prepare(o, rand.Reader); err == nil {
			t.Fatal("accepted invalid input")
		}
	}
	o := setupOptions(t)
	o.DryRun = true
	if _, err := Prepare(o, rand.Reader); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(o.Root)
	if len(entries) != 0 {
		t.Fatal("dry-run wrote files")
	}
}

func TestPrepareRefusesSymlinkAncestor(t *testing.T) {
	o := setupOptions(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(o.Root, "etc")); err != nil {
		t.Skip("symlinks unavailable")
	}
	if _, err := Prepare(o, rand.Reader); err == nil {
		t.Fatal("followed symlink")
	}
	entries, _ := os.ReadDir(outside)
	if len(entries) != 0 {
		t.Fatal("wrote outside root")
	}
}

func TestPrepareRejectsLoopbackAndLinkLocalEndpoints(t *testing.T) {
	for _, endpoint := range []string{"127.0.0.1", "169.254.169.254"} {
		o := setupOptions(t)
		o.Endpoint = endpoint
		if _, err := Prepare(o, rand.Reader); err == nil {
			t.Fatalf("accepted non-routable endpoint %s", endpoint)
		}
	}
}

func TestCompletedInstallDoesNotRestoreStaleFiles(t *testing.T) {
	for _, path := range []string{ServerPath, DefaultsPath} {
		o := setupOptions(t)
		if _, err := Prepare(o, rand.Reader); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(o.Root, strings.TrimPrefix(path, "/"))
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if _, err := Prepare(o, rand.Reader); err == nil {
			t.Fatalf("silently restored stale file after completed installation: %s", path)
		}
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatal("recreated a lost live file")
		}
	}
}
