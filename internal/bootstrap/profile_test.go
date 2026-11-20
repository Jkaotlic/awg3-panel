package bootstrap_test

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/bootstrap"
	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/runtime"
)

func TestPreparedInstallationUsesAutomaticPersonalI1AndInheritedI2(t *testing.T) {
	root := t.TempDir()
	if _, err := bootstrap.Prepare(bootstrap.Options{Root: root, Endpoint: "203.0.113.10", Egress: "eth0"}, rand.Reader); err != nil {
		t.Fatal(err)
	}
	local := func(p string) string { return filepath.ToSlash(filepath.Join(root, strings.TrimPrefix(p, "/"))) }
	cfg, err := config.Load(local(bootstrap.PanelPath))
	if err != nil {
		t.Fatal(err)
	}
	i := cfg.Interfaces[0]
	i.Config = local(bootstrap.ServerPath)
	i.Storage.State = local("/var/lib/awg3panel/awgtop/peers.json")
	i.Storage.Backups = local("/var/lib/awg3panel/awgtop/backups")
	i.Storage.Keys = local("/var/lib/awg3panel/awgtop/keys")
	raw, err := os.ReadFile(i.Config)
	if err != nil {
		t.Fatal(err)
	}
	fake := runtime.NewFake(string(raw))
	fake.ConfPath = i.Config
	pub, err := fake.PubKey("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	fake.SetDevice(pub, 3478)
	svc := issuer.New(i, cfg.Listen, fake)
	a, err := svc.Add("admin")
	if err != nil {
		t.Fatal(err)
	}
	b, err := svc.Add("phone")
	if err != nil {
		t.Fatal(err)
	}
	field := func(conf, key string) string {
		for _, l := range strings.Split(conf, "\n") {
			if strings.HasPrefix(l, key+" = ") {
				return strings.TrimPrefix(l, key+" = ")
			}
		}
		return ""
	}
	if field(a.Config, "I1") == "" || field(a.Config, "I1") == "<b 0x000100002112a442><r 12>" {
		t.Fatal("automatic personalization missing")
	}
	// Existing STUN personalization selects from a finite SOFTWARE set; two
	// CPS descriptions may coincide. The engine randomizes transaction IDs.
	// Do not change the user's generator just to manufacture string uniqueness.
	if field(a.Config, "PrivateKey") == field(b.Config, "PrivateKey") || field(a.Config, "PresharedKey") == field(b.Config, "PresharedKey") {
		t.Fatal("client keys were reused")
	}
	if profile, ok := issuer.DetectProfile(field(b.Config, "I1")); !ok || profile != issuer.MimicrySTUN {
		t.Fatal("second peer lost automatic STUN signature")
	}
	for _, key := range []string{"I2", "RekeyAfterTime", "RandomTrailers", "DisableCookies", "HeaderProtectionKey", "ContentPaddingAddition"} {
		if field(a.Config, key) == "" {
			t.Fatalf("missing %s", key)
		}
	}
	_, again, err := svc.ConfigFor(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if a.Config != again {
		t.Fatal("repeated export changed the profile")
	}
	if err := bootstrap.Verify(root); err != nil {
		t.Fatalf("peer mutation invalidated install verification: %v", err)
	}
}
