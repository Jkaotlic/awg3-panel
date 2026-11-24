package config

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

func TestServiceLoadRejectsBrokenBcrypt(t *testing.T) {
	t.Setenv("AWG3PANEL_SYSTEMD", "1")
	c := Default()
	c.Auth.Bcrypt = "$2a$12$broken"
	raw, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(file); err == nil || !strings.Contains(err.Error(), "auth.bcrypt") || strings.Contains(err.Error(), c.Auth.Bcrypt) {
		t.Fatalf("expected a redacted bcrypt validation error, got %v", err)
	}
}

func TestServiceBcryptAcceptsGeneratedHash(t *testing.T) {
	h, err := bcrypt.GenerateFromPassword([]byte("test password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"a", "b", "y"} {
		if !validBcrypt("$2" + version + string(h[3:])) {
			t.Errorf("rejected a valid $2%s hash", version)
		}
	}
}

func TestServicePath(t *testing.T) {
	base := t.TempDir()
	// TempDir can be under a system symlink on macOS.
	base, err := filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "managed")
	if err := os.MkdirAll(filepath.Join(root, "usable"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "locked"), 0500); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(base, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"usable", true},
		{"usable/new/deeper", true},
		{"locked/new", false},
		{"escape/new", false},
		{"../managed-other", false},
		{"../managed", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkServicePath(root+"/"+tc.name, root, true)
			if (err == nil) != tc.want {
				t.Fatalf("want acceptance %v, got %v", tc.want, err)
			}
		})
	}
}

func TestValidateRejectsAlternateWildcardAddresses(t *testing.T) {
	for _, addr := range []string{"[0:0:0:0:0:0:0:0]:8081", "[::ffff:0.0.0.0]:8081"} {
		c := Default()
		c.Listen = addr
		c.Auth.Bcrypt = "$2a$12$placeholder"
		if err := c.Validate(); err == nil {
			t.Errorf("accepted wildcard listener %s", addr)
		}
	}
}

func TestListenerMustMatchAssignedAddress(t *testing.T) {
	addrs := []net.Addr{
		&net.IPNet{IP: net.ParseIP("192.0.2.1"), Mask: net.CIDRMask(24, 32)},
		&net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(64, 128)},
	}
	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"192.0.2.1", true},
		{"2001:db8::1", true},
		{"192.0.2.2", false},
		{"2001:db8::2", false},
	} {
		if got := hasLocalAddress(net.ParseIP(tc.ip), addrs); got != tc.want {
			t.Errorf("address %s: got %v; want %v", tc.ip, got, tc.want)
		}
	}
}
