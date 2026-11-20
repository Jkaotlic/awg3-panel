package bootstrap

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/Jkaotlic/awg3-panel/internal/store"
	"github.com/Jkaotlic/awg3-panel/internal/wgconf"
	"os"
)

type adminRecord struct {
	Version int    `json:"version"`
	ID      string `json:"peer_id"`
	SHA256  string `json:"profile_sha256"`
}

func publicKey(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", errors.New("invalid profile key")
	}
	k, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		return "", errors.New("invalid profile key")
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// AdminProfile binds the first profile to an owned server peer before recording
// its hash. Subsequent checks preserve intentional peer revocation or renaming.
// It never prints or stores raw key material outside the existing private files.
func AdminProfile(root string, create bool) (string, error) {
	if err := Verify(root); err != nil {
		return "", err
	}
	if err := privateFile(root, AdminPath); err != nil {
		return "", err
	}
	b, err := os.ReadFile(target(root, AdminPath))
	if err != nil {
		return "", err
	}
	record, err := os.ReadFile(target(root, AdminRecordPath))
	if err == nil {
		var r adminRecord
		if json.Unmarshal(record, &r) != nil || r.Version != 1 || r.ID == "" || r.SHA256 != digest(b) {
			return "", errors.New("bootstrap admin profile does not match ownership record")
		}
		return r.ID, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	if !create {
		return "", errors.New("bootstrap admin ownership record missing")
	}
	client, err := wgconf.Parse(string(b))
	if err != nil || client.Interface == nil || len(client.Peers) != 1 {
		return "", errors.New("invalid bootstrap admin profile")
	}
	pub, err := publicKey(client.Interface.Get("PrivateKey"))
	if err != nil {
		return "", err
	}
	raw, err := os.ReadFile(target(root, ServerPath))
	if err != nil {
		return "", err
	}
	server, err := wgconf.Parse(string(raw))
	if err != nil || server.Interface == nil {
		return "", errors.New("invalid server config")
	}
	serverPub, err := publicKey(server.Interface.Get("PrivateKey"))
	if err != nil {
		return "", err
	}
	found := false
	for _, p := range server.Peers {
		if p.Get("PublicKey") == pub && wgconf.PeerName(p, string(raw)) == "bootstrap-admin" && p.Get("PresharedKey") == client.Peers[0].Get("PresharedKey") && p.Get("AllowedIPs") == client.Interface.Get("Address") && client.Peers[0].Get("PublicKey") == serverPub {
			found = true
		}
	}
	if !found {
		return "", errors.New("bootstrap profile is not bound to this installation's first peer")
	}
	r := adminRecord{Version: 1, ID: store.PeerID(pub), SHA256: digest(b)}
	data, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	if err := newFile(target(root, AdminRecordPath), data); err != nil {
		return "", err
	}
	return r.ID, nil
}
