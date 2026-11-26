package issuer

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/warpsignature"
	"github.com/Jkaotlic/awg3-panel/internal/wgconf"
)

func TestObfuscationDraftKeepsBothSidesCompatible(t *testing.T) {
	padding := " 00010 - 00100 "
	on := true
	draft, err := GenerateObfuscationDraft(bytes.NewReader(make([]byte, 512)), DraftOptions{
		Profile: "sip", Domains: "voice.example.com", TimingJitter: true,
		ContentPadding: &padding, RandomTrailers: &on, DisableCookies: &on,
	})
	if err != nil {
		t.Fatal(err)
	}
	if draft.Profile != "sip" || draft.Domain != "voice.example.com" || draft.ListenPort != 5060 || draft.Keepalive != "25-35" {
		t.Fatalf("unexpected draft fields: profile %q, domain %q, port %d, keepalive %q",
			draft.Profile, draft.Domain, draft.ListenPort, draft.Keepalive)
	}
	server, client := draftSection(t, draft.ServerBlock), draftSection(t, draft.ClientBlock)
	if server.Get("ListenPort") != "5060" || client.Get("ListenPort") != "" {
		t.Fatal("only the server block should carry the corresponding listen port")
	}
	shared, err := ExtractObfuscation(server)
	if err != nil {
		t.Fatal(err)
	}
	for key, value := range shared {
		if client.Get(key) != value {
			t.Errorf("shared %s: client and server differ", key)
		}
	}
	for key, want := range map[string]string{
		"ContentPaddingAddition": "10-100", "RandomTrailers": "on", "DisableCookies": "on",
		"RekeyAfterTime": "100-120", "RekeyTimeout": "3-7", "RejectAfterTime": "150-180",
		"KeepaliveTimeout": "5-15", "MaxHandshakeAttempts": "15-20",
	} {
		if server.Get(key) != want || client.Get(key) != want {
			t.Errorf("wrong normalized %s", key)
		}
	}
	if server.Get("S1") != "12" || server.Get("S2") != server.Get("S1") ||
		server.Get("S3") != server.Get("S1") || server.Get("S4") != server.Get("S1") {
		t.Error("expected equal padding sufficient for header protection")
	}
	key, err := base64.StdEncoding.DecodeString(server.Get("HeaderProtectionKey"))
	if err != nil || len(key) != 32 {
		t.Fatal("expected a 32-byte header protection key")
	}
	if draft.CPS[0] == "" || draft.CPS[1] == "" ||
		client.Get("I1") != draft.CPS[0] || client.Get("I2") != draft.CPS[1] ||
		server.Get("I1") != "" || server.Get("I2") != "" {
		t.Error("only the client block should carry the generated CPS chain")
	}
	if client.Get("Jc") != "4" || client.Get("Jmin") != "64" || client.Get("Jmax") != "264" ||
		server.Get("Jc") != "" || client.Get("PersistentKeepalive") != "" {
		t.Error("junk belongs to the client block and PersistentKeepalive belongs to the client peer")
	}
}

func TestObfuscationDraftPaddingOffAndNoCPS(t *testing.T) {
	off := false
	padding := ""
	draft, err := GenerateObfuscationDraft(bytes.NewReader(make([]byte, 512)), DraftOptions{
		Profile: "none", ContentPadding: &padding, RandomTrailers: &off, DisableCookies: &off,
	})
	if err != nil {
		t.Fatal(err)
	}
	if draft.Profile != "none" || draft.ListenPort != 51820 || draft.Keepalive != "25" || draft.CPS != ([5]string{}) {
		t.Fatal("unexpected none profile")
	}
	for _, block := range []string{draft.ServerBlock, draft.ClientBlock} {
		section := draftSection(t, block)
		if section.Get("ContentPaddingAddition") != "0" {
			t.Error("expected explicit zero CPA for an AWG 3.0 compatible draft")
		}
		for _, key := range []string{"RandomTrailers", "DisableCookies", "RekeyAfterTime", "I1"} {
			if section.Get(key) != "" {
				t.Errorf("disabled field %s should be omitted", key)
			}
		}
		if _, err := ExtractObfuscation(section); err != nil {
			t.Fatalf("draft cannot be read by the panel: %v", err)
		}
	}
}

func TestObfuscationDraftTrailersAllowOmittingPadding(t *testing.T) {
	on := true
	draft, err := GenerateObfuscationDraft(bytes.NewReader(make([]byte, 512)), DraftOptions{
		Profile: "dtls", Domains: "voice.example.com", RandomTrailers: &on,
	})
	if err != nil {
		t.Fatal(err)
	}
	if draft.Profile != "dtls" || draft.ListenPort != 443 || draft.CPS[0] == "" {
		t.Fatalf("unexpected DTLS profile: profile %q, port %d", draft.Profile, draft.ListenPort)
	}
	for _, block := range []string{draft.ServerBlock, draft.ClientBlock} {
		if strings.Contains(block, "ContentPaddingAddition") || !strings.Contains(block, "RandomTrailers = on\n") {
			t.Fatal("expected trailers enabled and disabled CPA omitted")
		}
		if _, err := ExtractObfuscation(draftSection(t, block)); err != nil {
			t.Fatalf("draft cannot be read by the panel: %v", err)
		}
	}
}

func TestObfuscationDraftRejectsInvalidOptions(t *testing.T) {
	for _, value := range []string{"+10", "-10", "65536", "20-10", "1-2-3", "1\nListenPort = 9", "000001"} {
		t.Run(value, func(t *testing.T) {
			_, err := GenerateObfuscationDraft(bytes.NewReader(make([]byte, 512)), DraftOptions{
				Profile: "none", ContentPadding: &value,
			})
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("expected invalid padding, got %v", err)
			}
		})
	}
	for _, options := range []DraftOptions{
		{Profile: "http"}, {Profile: "dns", HostPreset: "custom"}, {Profile: "stun", Domains: "not a domain"},
	} {
		_, err := GenerateObfuscationDraft(bytes.NewReader(make([]byte, 512)), options)
		if !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("expected invalid signature options, got %v", err)
		}
	}
}

func TestDetectProfileRecognizesWarpScoutSignatures(t *testing.T) {
	for _, tc := range []struct {
		profile string
		want    MimicryProfile
		port    int
	}{
		{"sip", MimicrySIP, 5060},
		{"dtls", MimicryProfile("dtls"), 443},
		{"quic_initial", MimicryQUIC, 443},
		{"dns", MimicryDNS, 53},
		{"stun", MimicrySTUN, 3478},
	} {
		t.Run(tc.profile, func(t *testing.T) {
			signature, err := warpsignature.GenerateWithOptions(tc.profile, warpsignature.GenerateOptions{})
			if err != nil {
				t.Fatal(err)
			}
			got, ok := DetectProfile(signature.Packets.I1)
			if !ok || got != tc.want {
				t.Fatalf("detected %q, want %q", got, tc.want)
			}
			if port, ok := PortForProfile(got); !ok || port != tc.port {
				t.Fatalf("detected canonical port %d, want %d", port, tc.port)
			}
		})
	}
	if got, ok := ProfileForPort(443); !ok || got != MimicryQUIC {
		t.Fatalf("automatic profile for UDP/443 changed: %q", got)
	}
	if _, ok := ValidProfile("dtls"); ok {
		t.Fatal("legacy generation should not expose DTLS as a supported input")
	}
}

func draftSection(t *testing.T, block string) *wgconf.Section {
	t.Helper()
	config, err := wgconf.Parse("[Interface]\n" + block)
	if err != nil {
		t.Fatal(err)
	}
	return config.Interface
}

const draftPeerSource = `[Interface]
PrivateKey = source-private-test-value
Address = 203.0.113.7/32
DNS = 203.0.113.53
MTU = 1280
Jc = 6
Jmin = 35
Jmax = 105
S1 = 24
S2 = 24
S3 = 24
S4 = 24
H1 = 6
H2 = 7
H3 = 8
H4 = 9
HeaderProtectionKey = source-header-test-value
ContentPaddingAddition = 005-013
RekeyAfterTime = 101-119
RekeyTimeout = 05
KeepaliveTimeout = 5-12
RandomTrailers = on
DisableCookies = on
I1 = <r 12>
I2 = <r 22>
I3 = <r 32>
I4 = <r 42>
I5 = <r 52>

[Peer]
PublicKey = source-server-test-value
PresharedKey = source-preshared-test-value
Endpoint = endpoint.example.com:52441
AllowedIPs = 198.51.100.0/24
PersistentKeepalive = 31-39
`

func TestGenerateDraftFromPeerCarriesOnlyReusableSettings(t *testing.T) {
	draft, err := GenerateDraftFromPeer(bytes.NewReader(make([]byte, 512)), draftPeerSource)
	if err != nil {
		t.Fatal(err)
	}
	if draft.Profile != "custom" || draft.Domain != "" || draft.ListenPort != 52441 ||
		draft.Keepalive != "31-39" || draft.Jitter != (Jitter{Jc: 6, Jmin: 35, Jmax: 105}) {
		t.Errorf("wrong copied metadata: profile %q, port %d, keepalive %q, J %+v",
			draft.Profile, draft.ListenPort, draft.Keepalive, draft.Jitter)
	}
	if draft.CPS != ([5]string{"<r 12>", "<r 22>", "<r 32>", "<r 42>", "<r 52>"}) {
		t.Fatal("expected all source CPS slots verbatim")
	}
	server, client := draftSection(t, draft.ServerBlock), draftSection(t, draft.ClientBlock)
	if server.Get("ListenPort") != "52441" || client.Get("ListenPort") != "" ||
		client.Get("I5") != draft.CPS[4] || server.Get("I5") != "" ||
		client.Get("Jc") != "6" || client.Get("Jmin") != "35" || client.Get("Jmax") != "105" || server.Get("Jc") != "" {
		t.Error("the original endpoint port belongs on the server and original J/CPS on the client")
	}
	for _, block := range []string{draft.ServerBlock, draft.ClientBlock} {
		for _, secret := range []string{
			"source-private-test-value", "source-header-test-value",
			"source-server-test-value", "source-preshared-test-value", "endpoint.example.com",
			"203.0.113.7", "203.0.113.53", "198.51.100.0",
		} {
			if strings.Contains(block, secret) {
				t.Fatal("draft leaked a source credential or address")
			}
		}
		section := draftSection(t, block)
		for key, expected := range map[string]string{
			"ContentPaddingAddition": "005-013", "RekeyAfterTime": "101-119",
			"RekeyTimeout": "05", "KeepaliveTimeout": "5-12", "RandomTrailers": "on",
			"DisableCookies": "on", "RejectAfterTime": "",
		} {
			if section.Get(key) != expected {
				t.Errorf("%s not copied verbatim", key)
			}
		}
	}
	generated, err := ExtractObfuscation(server)
	if err != nil {
		t.Fatal(err)
	}
	if server.Get("S1") == "24" || server.Get("H1") == "6" {
		t.Error("expected newly generated S and H")
	}
	for key, val := range generated {
		if client.Get(key) != val {
			t.Errorf("new shared %s differs", key)
		}
	}
}

func TestGenerateDraftFromPeerRetainsDisabledJunkAndCPS(t *testing.T) {
	source := strings.Replace(draftPeerSource, "Jc = 6\nJmin = 35\nJmax = 105\n", "", 1)
	for _, line := range []string{"I1 = <r 12>\n", "I2 = <r 22>\n", "I3 = <r 32>\n", "I4 = <r 42>\n", "I5 = <r 52>\n"} {
		source = strings.Replace(source, line, "", 1)
	}
	source = strings.Replace(source, "PersistentKeepalive = 31-39\n", "PersistentKeepalive = 0\n", 1)
	draft, err := GenerateDraftFromPeer(bytes.NewReader(make([]byte, 512)), source)
	if err != nil {
		t.Fatal(err)
	}
	if draft.Profile != "none" || draft.Keepalive != "0" || draft.CPS != ([5]string{}) ||
		draft.Jitter != (Jitter{}) || strings.Contains(draft.ClientBlock, "Jc =") {
		t.Fatal("disabled jitter, keepalive or CPS was replaced by a default")
	}
}

func TestGenerateDraftFromPeerDoesNotEchoMalformedInput(t *testing.T) {
	const secret = "secret-marker-example"
	for index, source := range []string{
		draftPeerSource + "\n[" + secret + "]\n",
		strings.Replace(draftPeerSource, "52441", secret, 1),
		strings.Replace(draftPeerSource, "<r 12>", secret, 1),
		strings.Replace(draftPeerSource, "101-119", secret, 1),
		strings.Replace(draftPeerSource, "RandomTrailers = on", "RandomTrailers = "+secret, 1),
		draftPeerSource + "\n[Peer]\nEndpoint = 198.51.100.1:443\n",
	} {
		result, err := GenerateDraftFromPeer(bytes.NewReader(make([]byte, 512)), source)
		if !errors.Is(err, ErrInvalidInput) || strings.Contains(err.Error(), secret) || result != (ObfuscationDraft{}) {
			t.Fatalf("case %d should yield a sanitized error and no draft", index)
		}
	}
}

func TestObfuscationDraftUsesExplicitJitter(t *testing.T) {
	for _, j := range []Jitter{{Jc: 3, Jmin: 100, Jmax: 500}, {}} {
		draft, err := GenerateObfuscationDraft(bytes.NewReader(make([]byte, 512)), DraftOptions{Profile: "none", Jitter: &j})
		if err != nil {
			t.Fatal(err)
		}
		if draft.Jitter != j {
			t.Errorf("got J %+v, want %+v", draft.Jitter, j)
		}
		section := draftSection(t, draft.ClientBlock)
		if (section.Get("Jc") == "") != (j == (Jitter{})) {
			t.Error("zero and configured jitter must be distinguished")
		}
	}
	for _, j := range []Jitter{{Jc: 3}, {Jc: 3, Jmin: 1200, Jmax: 1280}} {
		_, err := GenerateObfuscationDraft(bytes.NewReader(make([]byte, 512)), DraftOptions{Profile: "none", Jitter: &j})
		if !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("expected invalid J %+v, got %v", j, err)
		}
	}
}

func TestGenerateDraftFromPeerRecognizesQUICWithoutChangingPort(t *testing.T) {
	i1, err := GenerateSignatureFor(bytes.NewReader(make([]byte, 512)), MimicryQUIC)
	if err != nil {
		t.Fatal(err)
	}
	source := strings.Replace(draftPeerSource, "I1 = <r 12>", "I1 = "+i1, 1)
	draft, err := GenerateDraftFromPeer(bytes.NewReader(make([]byte, 512)), source)
	if err != nil {
		t.Fatal(err)
	}
	if draft.Profile != "quic_initial" || draft.ListenPort != 52441 || draft.CPS[0] != i1 {
		t.Fatal("copied QUIC template should keep its endpoint port and exact CPS")
	}
}
