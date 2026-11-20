package issuer_test

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/issuer"
)

// decodeVPNURI — обратное преобразование формата AmneziaVPN: vpn:// +
// base64url без «=» от qCompress (4 байта длины big-endian + zlib).
func decodeVPNURI(t *testing.T, uri string) []byte {
	t.Helper()
	b64, ok := strings.CutPrefix(uri, "vpn://")
	if !ok {
		t.Fatalf("нет префикса vpn://: %q", uri)
	}
	if strings.Contains(b64, "=") {
		t.Fatalf("в base64url не должно быть «=»: клиент декодирует с OmitTrailingEquals")
	}
	raw, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw[4:]))
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if n := binary.BigEndian.Uint32(raw[:4]); int(n) != len(out) {
		t.Fatalf("префикс длины qCompress %d, фактически %d", n, len(out))
	}
	return out
}

// Эталон из Perl/Python zlib (уровень 6): подтверждает, что decodeVPNURI
// понимает формат так же, как установщик bivlked и клиент AmneziaVPN.
func TestDecodeVPNURIЭталон(t *testing.T) {
	got := decodeVPNURI(t, "vpn://AAAAK3icq1ZKzs8rSczMSy0qVrKKjtVRysgvLvFLzE1VslIytLTQMzXUMzQw0DNUqgUAPjMM5g")
	if string(got) != `{"containers":[],"hostName":"198.51.100.1"}` {
		t.Fatalf("эталон раскодирован в %q", got)
	}
}

type vpnOuter struct {
	Containers []struct {
		Container string `json:"container"`
		Awg       struct {
			IsThirdPartyConfig bool   `json:"isThirdPartyConfig"`
			LastConfig         string `json:"last_config"`
			Port               string `json:"port"`
			ProtocolVersion    string `json:"protocol_version"`
			TransportProto     string `json:"transport_proto"`
		} `json:"awg"`
	} `json:"containers"`
	DefaultContainer string `json:"defaultContainer"`
	Description      string `json:"description"`
	DNS1             string `json:"dns1"`
	HostName         string `json:"hostName"`
}

func renderVPN(t *testing.T, p issuer.ClientParams) (vpnOuter, map[string]any) {
	t.Helper()
	uri, err := issuer.RenderVPNURI(p, "телефон")
	if err != nil {
		t.Fatal(err)
	}
	var o vpnOuter
	if err := json.Unmarshal(decodeVPNURI(t, uri), &o); err != nil {
		t.Fatal(err)
	}
	if len(o.Containers) != 1 {
		t.Fatalf("ожидался один контейнер, получено %d", len(o.Containers))
	}
	var in map[string]any
	if err := json.Unmarshal([]byte(o.Containers[0].Awg.LastConfig), &in); err != nil {
		t.Fatal(err)
	}
	return o, in
}

// Спека 2026-10-29, раздел 6: AmneziaVPN строит туннель из JSON-ключей, а
// не из текста config, — каждое поле обязано лечь ключом и нужного типа:
// port в last_config — число, остальное — строки (toString() у числа пуст).
func TestRenderVPNURIКлючиИТипы(t *testing.T) {
	p := params(t)
	p.Endpoint = "198.51.100.7:51772"
	p.Jc, p.Jmin, p.Jmax = 6, 48, 160
	p.DNS = "1.1.1.1, 8.8.8.8"
	p.Extra = map[string]string{"I1": "<b 0x000100002112a442><r 12>"}
	o, in := renderVPN(t, p)

	c := o.Containers[0]
	if c.Container != "amnezia-awg" || o.DefaultContainer != "amnezia-awg" || !c.Awg.IsThirdPartyConfig ||
		c.Awg.Port != "51772" || c.Awg.ProtocolVersion != "2" || c.Awg.TransportProto != "udp" {
		t.Fatalf("внешний объект: %+v", o)
	}
	if o.HostName != "198.51.100.7" || o.Description != "телефон" || o.DNS1 != "1.1.1.1" {
		t.Fatalf("hostName/description/dns1: %+v", o)
	}
	wantStr := map[string]string{
		"Jc": "6", "Jmin": "48", "Jmax": "160", "S1": "17", "S4": "12", "H1": "1633177",
		"HeaderProtectionKey": p.Obfuscation["HeaderProtectionKey"], "ContentPaddingAddition": "0-96",
		"I1": "<b 0x000100002112a442><r 12>", "client_ip": "10.11.0.4",
		"client_priv_key": p.PrivateKey, "psk_key": p.PresharedKey, "server_pub_key": p.ServerPublicKey,
		"hostName": "198.51.100.7", "mtu": "1280", "persistent_keep_alive": "22-30",
	}
	for k, v := range wantStr {
		if got, ok := in[k].(string); !ok || got != v {
			t.Errorf("last_config.%s = %#v, ожидалась строка %q", k, in[k], v)
		}
	}
	if port, ok := in["port"].(float64); !ok || port != 51772 {
		t.Errorf("last_config.port = %#v, ожидалось число 51772", in["port"])
	}
	if ips, ok := in["allowed_ips"].([]any); !ok || len(ips) != 1 || ips[0] != "0.0.0.0/0" {
		t.Errorf("allowed_ips = %#v, ожидался массив [0.0.0.0/0]", in["allowed_ips"])
	}
	body, _ := issuer.RenderClientConfig(p)
	if in["config"] != body {
		t.Error("config обязан совпадать с выдаваемым .conf")
	}
	if _, ok := in["RandomTrailers"]; ok {
		t.Error("RandomTrailers выключен на сервере — ключа быть не должно")
	}
}

func TestRenderVPNURIПереноситПоля31(t *testing.T) {
	p := params(t)
	p.Obfuscation["RandomTrailers"] = "on"
	p.Obfuscation["DisableCookies"] = "on"
	p.Obfuscation["RekeyAfterTime"] = "110-140"
	_, in := renderVPN(t, p)
	for k, v := range map[string]string{"RandomTrailers": "on", "DisableCookies": "on", "RekeyAfterTime": "110-140"} {
		if in[k] != v {
			t.Errorf("%s = %#v, ожидалось %q — без ключа AmneziaVPN молча выбросит поле", k, in[k], v)
		}
	}
}

func TestRenderVPNURIТолькоIPv4ВClientIP(t *testing.T) {
	p := params(t)
	p.Address = "10.11.0.4/32, fd00::4/128"
	_, in := renderVPN(t, p)
	if in["client_ip"] != "10.11.0.4" {
		t.Fatalf("client_ip = %#v: IPv6 ломает десктопный клиент, отдаём только IPv4", in["client_ip"])
	}
}

func TestRenderVPNURIОтказБезПорта(t *testing.T) {
	p := params(t)
	p.Endpoint = "198.51.100.7"
	if _, err := issuer.RenderVPNURI(p, "x"); err == nil {
		t.Fatal("endpoint без порта: ожидался отказ")
	}
}

func TestServiceVPNURIForСовпадаетСConf(t *testing.T) {
	env := newServiceEnv(t)
	issued, err := env.svc.Add("телефон")
	if err != nil {
		t.Fatal(err)
	}
	uri, err := env.svc.VPNURIFor(issued.ID)
	if err != nil {
		t.Fatal(err)
	}
	var o vpnOuter
	if err := json.Unmarshal(decodeVPNURI(t, uri), &o); err != nil {
		t.Fatal(err)
	}
	var in map[string]any
	json.Unmarshal([]byte(o.Containers[0].Awg.LastConfig), &in)
	_, body, _ := env.svc.ConfigFor(issued.ID)
	if in["config"] != body || o.Description != "телефон" {
		t.Fatalf("vpn:// обязан нести тот же конфиг, что и .conf, и имя пира: description=%q", o.Description)
	}
	if png, err := env.svc.VPNQRFor(issued.ID); err != nil || len(png) == 0 {
		t.Fatalf("VPNQRFor: %v", err)
	}
}

// Ревью фазы 2, п.3: без IPv4 ссылка импортировалась бы в нерабочий туннель.
func TestRenderVPNURIОтказБезIPv4(t *testing.T) {
	p := params(t)
	p.Address = "fd00::4/128"
	if _, err := issuer.RenderVPNURI(p, "x"); !errors.Is(err, issuer.ErrInvalidInput) {
		t.Fatalf("адрес без IPv4: ожидался ErrInvalidInput, получено %v", err)
	}
}
