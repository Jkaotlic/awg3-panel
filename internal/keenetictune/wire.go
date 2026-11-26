package keenetictune

import (
	"crypto/sha256"
	"encoding/json"
	"errors"

	"github.com/Jkaotlic/awg3-panel/internal/issuer"
)

type interfaceSettings struct {
	issuer.Jitter
	wireInterface
}

// wireInterface is the stable, non-junk part of the managed client config.
// PrivateKey and Peer.PresharedKey are intentionally unavailable in GET.
type wireInterface struct {
	Address                string `json:"address"`
	MTU                    int    `json:"mtu"`
	DNS                    string `json:"dns"`
	Qlen                   int    `json:"qlen"`
	S1                     int    `json:"s1"`
	S2                     int    `json:"s2"`
	S3                     int    `json:"s3"`
	S4                     int    `json:"s4"`
	H1                     string `json:"h1"`
	H2                     string `json:"h2"`
	H3                     string `json:"h3"`
	H4                     string `json:"h4"`
	I1                     string `json:"i1"`
	I2                     string `json:"i2"`
	I3                     string `json:"i3"`
	I4                     string `json:"i4"`
	I5                     string `json:"i5"`
	HeaderProtectionKey    string `json:"headerProtectionKey"`
	ContentPaddingAddition string `json:"contentPaddingAddition"`
	RekeyAfterTime         string `json:"rekeyAfterTime"`
	RekeyTimeout           string `json:"rekeyTimeout"`
	RejectAfterTime        string `json:"rejectAfterTime"`
	KeepaliveTimeout       string `json:"keepaliveTimeout"`
	MaxHandshakeAttempts   string `json:"maxHandshakeAttempts"`
	RandomTrailers         bool   `json:"randomTrailers"`
	DisableCookies         bool   `json:"disableCookies"`
}

type peerSettings struct {
	Endpoint            string          `json:"endpoint"`
	PublicKey           string          `json:"publicKey"`
	AllowedIPs          []string        `json:"allowedIPs"`
	PersistentKeepalive json.RawMessage `json:"persistentKeepalive"`
}

func (d tunnelDetails) wireFingerprint() ([32]byte, error) {
	config := struct {
		Interface wireInterface
		Peer      peerSettings
		Route     string
	}{Interface: d.Interface.wireInterface, Peer: *d.Peer, Route: d.ISPInterface}
	encoded, err := json.Marshal(config)
	if err != nil {
		return [32]byte{}, errors.New("не удалось проверить целостность тестового профиля")
	}
	return sha256.Sum256(encoded), nil
}
