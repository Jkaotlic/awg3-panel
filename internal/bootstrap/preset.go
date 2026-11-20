// Package bootstrap prepares new installations. It is not used by the web daemon
// and never edits an existing server Interface.
package bootstrap

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/Jkaotlic/awg3-panel/internal/store"
)

const PresetName = "personal-stun-v1"

// These are protocol templates, not captured session credentials. I1 selects
// STUN; issuer.personalizeI1 still creates each peer's own STUN signature.
const stunSeed = "<b 0x000100002112a442><r 12>"
const dtlsSeed = "<b 0x16fefd00000000000000000082010000760000000000000076fefd><r 32><b 0x00000010c02bc02fc009c013c00ac014002f00350100003cff0100010000170000000a00080006001d00170018000b00020100000d0012001004030804040105030805050108060601000e000700040007000100>"

type Band struct{ Low, High uint32 }
type Preset struct {
	Padding   int
	Headers   [4]Band
	HeaderKey string
}

// Generate implements the measured configuration shape, not a claim that this
// profile bypasses every ISP. New installations never share header keys/bands.
func Generate(rnd io.Reader) (Preset, error) {
	var p Preset
	n, err := rand.Int(rnd, big.NewInt(3))
	if err != nil {
		return p, fmt.Errorf("preset entropy unavailable")
	}
	p.Padding = 27 + int(n.Int64())
	for i := range p.Headers {
		found := false
		for attempt := 0; attempt < 128; attempt++ {
			n, err := rand.Int(rnd, big.NewInt(1<<32-25004))
			if err != nil {
				return Preset{}, fmt.Errorf("preset entropy unavailable")
			}
			b := Band{Low: uint32(n.Uint64() + 5)}
			b.High = b.Low + 24999
			overlap := false
			for j := 0; j < i; j++ {
				if b.Low <= p.Headers[j].High && b.High >= p.Headers[j].Low {
					overlap = true
					break
				}
			}
			if !overlap {
				p.Headers[i] = b
				found = true
				break
			}
		}
		if !found {
			return Preset{}, fmt.Errorf("cannot generate distinct header bands")
		}
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(rnd, key); err != nil {
		return Preset{}, fmt.Errorf("preset entropy unavailable")
	}
	p.HeaderKey = base64.StdEncoding.EncodeToString(key)
	return p, nil
}

func (p Preset) ServerConfig(privateKey, address string) string {
	var s strings.Builder
	fmt.Fprintf(&s, "[Interface]\nAddress = %s\nPrivateKey = %s\nListenPort = 3478\nMTU = 1280\n", address, privateKey)
	for i := 1; i <= 4; i++ {
		fmt.Fprintf(&s, "S%d = %d\n", i, p.Padding)
	}
	for i, b := range p.Headers {
		fmt.Fprintf(&s, "H%d = %d-%d\n", i+1, b.Low, b.High)
	}
	fmt.Fprintf(&s, "HeaderProtectionKey = %s\n", p.HeaderKey)
	s.WriteString("ContentPaddingAddition = 10-100\nRandomTrailers = on\nDisableCookies = on\nRekeyAfterTime = 110-140\nRekeyTimeout = 5-8\nRejectAfterTime = 176-197\nKeepaliveTimeout = 9-14\nMaxHandshakeAttempts = 16-20\n\n")
	return s.String()
}

func (p Preset) Defaults(endpoint string) store.Defaults {
	return store.Defaults{Version: store.DefaultsVersion, Endpoint: endpoint, AllowedIPs: "0.0.0.0/0", Keepalive: "22-30", Jc: 6, Jmin: 48, Jmax: 160, Extra: map[string]string{"I1": stunSeed, "I2": dtlsSeed}}
}
