package bootstrap

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/Jkaotlic/awg3-panel/internal/wgconf"
	"os"
	"testing"
)

func TestAdminProfileRequiresBoundPeerAndPreservesRevocation(t *testing.T) {
	o := setupOptions(t)
	if _, err := Prepare(o, rand.Reader); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target(o.Root, AdminPath), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := AdminProfile(o.Root, true); err == nil {
		t.Fatal("accepted empty profile")
	}
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(target(o.Root, ServerPath))
	c, _ := wgconf.Parse(string(raw))
	serverPub, err := publicKey(c.Interface.Get("PrivateKey"))
	if err != nil {
		t.Fatal(err)
	}
	priv := base64.StdEncoding.EncodeToString(k.Bytes())
	pub := base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
	psk := base64.StdEncoding.EncodeToString(make([]byte, 32))
	profile := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.66.0.2/32\n[Peer]\nPublicKey = %s\nPresharedKey = %s\n", priv, serverPub, psk)
	if err := os.WriteFile(target(o.Root, AdminPath), []byte(profile), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := AdminProfile(o.Root, true); err == nil {
		t.Fatal("accepted foreign profile without matching peer")
	}
	changed, err := wgconf.AppendPeer(string(raw), wgconf.PeerSpec{Name: "bootstrap-admin", PublicKey: pub, PresharedKey: psk, AllowedIPs: "10.66.0.2/32"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target(o.Root, ServerPath), []byte(changed), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := AdminProfile(o.Root, true); err != nil {
		t.Fatal(err)
	}
	// Revoking the peer does not revoke ownership of the archived first profile.
	if err := os.WriteFile(target(o.Root, ServerPath), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := AdminProfile(o.Root, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target(o.Root, AdminPath), []byte(profile+"# changed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := AdminProfile(o.Root, true); err == nil {
		t.Fatal("accepted changed recorded profile")
	}
}
