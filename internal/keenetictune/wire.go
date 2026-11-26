package keenetictune

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"

	"github.com/Jkaotlic/awg3-panel/internal/issuer"
)

type interfaceSettings struct {
	issuer.Jitter
	wireInterface
	replaySafe bool
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

func (i *interfaceSettings) UnmarshalJSON(body []byte) error {
	type settings interfaceSettings
	if err := json.Unmarshal(body, (*settings)(i)); err != nil {
		return err
	}
	i.replaySafe = completeInterface(body) && validHeaderProtectionKey(i.HeaderProtectionKey)
	return nil
}

// The direct v2.20.6 REST edit replaces the full interface when address is
// present. Only replay the exact known schema from the live detail response.
func completeInterface(body []byte) bool {
	required := []string{"privateKey", "address", "mtu", "qlen", "jc", "jmin", "jmax",
		"s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4"}
	optional := []string{"dns", "i1", "i2", "i3", "i4", "i5", "headerProtectionKey", "contentPaddingAddition",
		"rekeyAfterTime", "rekeyTimeout", "rejectAfterTime", "keepaliveTimeout", "maxHandshakeAttempts",
		"randomTrailers", "disableCookies"}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return false
	}
	seen := make(map[string]bool, len(required)+len(optional))
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] || (!slices.Contains(required, key) && !slices.Contains(optional, key)) {
			return false
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil || string(value) == "null" || (key == "privateKey" && string(value) != `""`) {
			return false
		}
		seen[key] = true
	}
	for _, key := range required {
		if !seen[key] {
			return false
		}
	}
	return true
}

func validHeaderProtectionKey(key string) bool {
	if key == "" {
		return true
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(key)
	return err == nil && len(decoded) == 32 && base64.StdEncoding.EncodeToString(decoded) == key
}

func (w wireInterface) withCPS(cps [5]string) wireInterface {
	w.I1, w.I2, w.I3, w.I4, w.I5 = cps[0], cps[1], cps[2], cps[3], cps[4]
	return w
}

func (d tunnelDetails) wireFingerprint(wire wireInterface) ([32]byte, error) {
	config := struct {
		Interface wireInterface
		Peer      peerSettings
		Route     string
	}{Interface: wire, Peer: *d.Peer, Route: d.ISPInterface}
	encoded, err := json.Marshal(config)
	if err != nil {
		return [32]byte{}, errors.New("не удалось проверить целостность тестового профиля")
	}
	return sha256.Sum256(encoded), nil
}
