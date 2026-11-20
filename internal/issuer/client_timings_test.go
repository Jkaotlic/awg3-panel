package issuer_test

import (
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/issuer"
)

// Боевой сервер AWG задаёт тайминги диапазонами — это третий механизм 3.0
// (после header protection и content padding). Значения ниже сняты с живого
// awg31 на main.
const serverConfTimings = `[Interface]
Address = 10.16.0.1/24
ListenPort = 52441
PrivateKey = c2VydmVyLXByaXZhdGUta2V5LWZha2UtMDAwMDAwMDAwMDA9
MTU = 1280
S1 = 18
S2 = 24
S3 = 19
S4 = 15
H1 = 1345789
H2 = 2211457
H3 = 1073291
H4 = 1789633
HeaderProtectionKey = aGVhZGVyLXByb3RlY3Rpb24ta2V5LWZha2UtMDAwMDAwMD0=
RandomTrailers = on
DisableCookies = on
RekeyAfterTime = 105-135
RekeyTimeout = 4-7
RejectAfterTime = 165-195
KeepaliveTimeout = 8-12
MaxHandshakeAttempts = 16-20
`

// Тайминги — параметры ПРОТОКОЛА, а не украшение серверного файла: сервер с
// `RejectAfterTime = 165-195` ждёт от клиента другого поведения, чем от
// клиента с дефолтными 180. Выданный панелью конфиг обязан нести их так же,
// как их несут конфиги, выпущенные руками, — иначе панель молча выдаёт файл,
// отличающийся от рабочего образца.
func TestExtractObfuscationCarriesServerTimings(t *testing.T) {
	got, err := issuer.ExtractObfuscation(serverIface(t, serverConfTimings))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"RekeyAfterTime":       "105-135",
		"RekeyTimeout":         "4-7",
		"RejectAfterTime":      "165-195",
		"KeepaliveTimeout":     "8-12",
		"MaxHandshakeAttempts": "16-20",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("тайминг %s не перенесён: получено %q, ожидалось %q", k, got[k], v)
		}
	}
}

func TestRenderClientConfigPrintsServerTimings(t *testing.T) {
	obf, err := issuer.ExtractObfuscation(serverIface(t, serverConfTimings))
	if err != nil {
		t.Fatal(err)
	}
	p := params(t)
	p.Obfuscation = obf

	text, err := issuer.RenderClientConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"RekeyAfterTime = 105-135",
		"RekeyTimeout = 4-7",
		"RejectAfterTime = 165-195",
		"KeepaliveTimeout = 8-12",
		"MaxHandshakeAttempts = 16-20",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("в клиентском конфиге нет строки %q:\n%s", want, text)
		}
	}
}

// Обратный случай: сервер таймингов не задаёт (обычная раскладка 3.0). Тогда
// в клиентском файле их быть не должно — выдумывать значения за протокол
// нельзя, дефолты клиента и сервера в этом случае совпадают по определению.
func TestRenderClientConfigOmitsAbsentTimings(t *testing.T) {
	obf, err := issuer.ExtractObfuscation(serverIface(t, serverConf))
	if err != nil {
		t.Fatal(err)
	}
	p := params(t)
	p.Obfuscation = obf

	text, err := issuer.RenderClientConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, unwanted := range []string{
		"RekeyAfterTime", "RekeyTimeout", "RejectAfterTime",
		"KeepaliveTimeout", "MaxHandshakeAttempts",
	} {
		if strings.Contains(text, unwanted) {
			t.Errorf("тайминг %s взялся из ниоткуда — сервер его не задаёт:\n%s", unwanted, text)
		}
	}
}

// Главный тест паритета: набор полей выданного конфига должен совпадать с
// конфигом, выпущенным руками для того же сервера. Именно расхождение этого
// набора 24.08.2026 сделало выданные панелью конфиги непохожими на рабочие:
// сервер нёс тайминги, а панель их теряла.
func TestIssuedConfigMatchesHandWrittenFieldSet(t *testing.T) {
	obf, err := issuer.ExtractObfuscation(serverIface(t, serverConfTimings))
	if err != nil {
		t.Fatal(err)
	}
	p := params(t)
	p.Obfuscation = obf
	p.Jc, p.Jmin, p.Jmax = 4, 70, 850

	text, err := issuer.RenderClientConfig(p)
	if err != nil {
		t.Fatal(err)
	}

	// Ровно те ключи, что есть в рабочем ручном конфиге awg31 (см. образец
	// awg31-main-keenetic.conf), кроме ContentPaddingAddition — сервер с
	// включённым RandomTrailers его не задаёт.
	for _, want := range []string{
		"PrivateKey", "Address", "MTU",
		"Jc", "Jmin", "Jmax",
		"S1", "S2", "S3", "S4",
		"H1", "H2", "H3", "H4",
		"HeaderProtectionKey",
		"RandomTrailers", "DisableCookies",
		"RekeyAfterTime", "RekeyTimeout", "RejectAfterTime",
		"KeepaliveTimeout", "MaxHandshakeAttempts",
		"PublicKey", "PresharedKey", "AllowedIPs", "Endpoint", "PersistentKeepalive",
	} {
		if !strings.Contains(text, want+" = ") {
			t.Errorf("в выданном конфиге нет поля %s, а в ручном оно есть:\n%s", want, text)
		}
	}
}
