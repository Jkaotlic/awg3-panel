package bootstrap

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestPersonalPresetMatchesWorkingServers(t *testing.T) {
	for n := 0; n < 40; n++ {
		p, err := Generate(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if p.Padding < 27 || p.Padding > 29 {
			t.Fatalf("padding %d", p.Padding)
		}
		for i, h := range p.Headers {
			if h.Low < 5 || uint64(h.High)-uint64(h.Low)+1 != 25000 {
				t.Fatal("invalid band")
			}
			for j := 0; j < i; j++ {
				if h.Low <= p.Headers[j].High && h.High >= p.Headers[j].Low {
					t.Fatal("overlapping bands")
				}
			}
		}
		key, err := base64.StdEncoding.DecodeString(p.HeaderKey)
		if err != nil || len(key) != 32 {
			t.Fatal("invalid header key")
		}
		conf := p.ServerConfig("TEST_PRIVATE_KEY", "10.66.0.1/24")
		for _, want := range []string{"MTU = 1280", "ListenPort = 3478", "ContentPaddingAddition = 10-100", "RandomTrailers = on", "DisableCookies = on", "RekeyAfterTime = 110-140", "RekeyTimeout = 5-8", "RejectAfterTime = 176-197", "KeepaliveTimeout = 9-14", "MaxHandshakeAttempts = 16-20"} {
			if !strings.Contains(conf, want+"\n") {
				t.Fatalf("missing %s", want)
			}
		}
		d := p.Defaults("203.0.113.10:3478")
		if d.Jc != 6 || d.Jmin != 48 || d.Jmax != 160 || d.Keepalive != "22-30" || d.AllowedIPs != "0.0.0.0/0" || d.DNS != "" {
			t.Fatalf("wrong client defaults: %+v", d)
		}
		if d.Extra["I1"] != "<b 0x000100002112a442><r 12>" {
			t.Fatal("STUN profile missing")
		}
		packet := expandCPS(t, d.Extra["I2"])
		if len(packet) != 143 || hex.EncodeToString(packet[:3]) != "16fefd" {
			t.Fatal("not reference DTLS")
		}
		word := func(i int) int { return int(packet[i])<<8 | int(packet[i+1]) }
		if word(11) != len(packet)-13 || word(15) != len(packet)-25 || word(23) != len(packet)-25 {
			t.Fatal("DTLS record/body/fragment lengths inconsistent")
		}
		if !bytes.Contains(packet, []byte{0x00, 0x0e, 0x00, 0x07}) {
			t.Fatal("use_srtp missing")
		}
	}
}

func TestGenerateSecretsAreIndependentAndErrorsAreSafe(t *testing.T) {
	a, err := Generate(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if a.HeaderKey == b.HeaderKey {
		t.Fatal("reused key")
	}
	if _, err := Generate(bytes.NewReader(nil)); err == nil {
		t.Fatal("accepted missing entropy")
	}
	for _, count := range []int{1, 5, 20, 40} {
		if _, err := Generate(io.LimitReader(rand.Reader, int64(count))); err == nil {
			t.Fatalf("accepted short reader %d", count)
		}
	}
}

func expandCPS(t *testing.T, s string) []byte {
	t.Helper()
	var out []byte
	re := regexp.MustCompile(`<([br]) ([^>]+)>`)
	for _, m := range re.FindAllStringSubmatch(s, -1) {
		if m[1] == "b" {
			b, err := hex.DecodeString(strings.TrimPrefix(m[2], "0x"))
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, b...)
		} else {
			n, err := strconv.Atoi(m[2])
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, make([]byte, n)...)
		}
	}
	return out
}
