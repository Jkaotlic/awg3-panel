package issuer_test

import (
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/issuer"
)

// Сервер AWG 3.1 с включённым RandomTrailers намеренно НЕ задаёт
// ContentPaddingAddition: на транспорте второй перебивает первый, поэтому
// одновременно они не задаются. Такая конфигурация — не поломка и не
// недосмотр оператора, а рабочая раскладка боевого туннеля awg31.
const serverConf31 = `[Interface]
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
`

// Бинарь AmneziaWG 3.1 печатает поля 3.1 в awg showconf ВСЕГДА — в том
// числе выключенными. Такой сервер ведёт себя ровно как 3.0, и клиентский
// конфиг обязан остаться совместимым со старыми клиентами.
const serverConf31Off = `[Interface]
Address = 10.11.0.1/24
ListenPort = 51772
PrivateKey = c2VydmVyLXByaXZhdGUta2V5LWZha2UtMDAwMDAwMDAwMDA9
MTU = 1280
S1 = 17
S2 = 21
S3 = 16
S4 = 12
H1 = 1633177
H2 = 2114993
H3 = 1287653
H4 = 1955441
HeaderProtectionKey = aGVhZGVyLXByb3RlY3Rpb24ta2V5LWZha2UtMDAwMDAwMD0=
ContentPaddingAddition = 0-96
RandomTrailers = off
DisableCookies = off
`

// Главный тест этой правки: до неё панель отказывалась выпускать пиров на
// боевом awg31 с текстом «нет обязательных полей AWG 3.0:
// ContentPaddingAddition», хотя сервер полностью исправен.
func TestExtractObfuscationAcceptsRandomTrailersWithoutPadding(t *testing.T) {
	got, err := issuer.ExtractObfuscation(serverIface(t, serverConf31))
	if err != nil {
		t.Fatalf("сервер с RandomTrailers = on исправен, отказ недопустим: %v", err)
	}
	if got["RandomTrailers"] != "on" {
		t.Errorf("RandomTrailers не перенесён клиенту: %q", got["RandomTrailers"])
	}
	if got["DisableCookies"] != "on" {
		t.Errorf("DisableCookies не перенесён клиенту: %q", got["DisableCookies"])
	}
	if got["ContentPaddingAddition"] != "" {
		t.Errorf("ContentPaddingAddition взялся из ниоткуда: %q", got["ContentPaddingAddition"])
	}
}

// RandomTrailers — параметр ДВУСТОРОННИЙ: сервер с ним включённым шлёт
// случайные хвосты, и клиент без этой строки их не разберёт. Значит поле
// обязано доехать до выданного .conf, а не остаться только на сервере.
func TestRenderClientConfigCarriesRandomTrailers(t *testing.T) {
	obf, err := issuer.ExtractObfuscation(serverIface(t, serverConf31))
	if err != nil {
		t.Fatal(err)
	}
	p := params(t)
	p.Obfuscation = obf

	text, err := issuer.RenderClientConfig(p)
	if err != nil {
		t.Fatalf("выпуск конфига для исправного сервера 3.1 отказал: %v", err)
	}
	for _, want := range []string{"RandomTrailers = on", "DisableCookies = on"} {
		if !strings.Contains(text, want) {
			t.Errorf("в клиентском конфиге нет строки %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "ContentPaddingAddition") {
		t.Errorf("ContentPaddingAddition попал в конфиг, где его быть не должно:\n%s", text)
	}
}

// Обратный случай: поля 3.1 выключены. Строка «RandomTrailers = off» в
// клиентском файле не несёт смысла (это и есть поведение по умолчанию), но
// ломает разбор у клиентов версии 3.0 — печатать её нельзя.
func TestRenderClientConfigOmitsDisabled31Fields(t *testing.T) {
	obf, err := issuer.ExtractObfuscation(serverIface(t, serverConf31Off))
	if err != nil {
		t.Fatal(err)
	}
	p := params(t)
	p.Obfuscation = obf

	text, err := issuer.RenderClientConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, unwanted := range []string{"RandomTrailers", "DisableCookies"} {
		if strings.Contains(text, unwanted) {
			t.Errorf("выключенное поле %s попало в клиентский конфиг:\n%s", unwanted, text)
		}
	}
	if !strings.Contains(text, "ContentPaddingAddition = 0-96") {
		t.Errorf("ContentPaddingAddition потерян, хотя сервер его задаёт:\n%s", text)
	}
}

// Предыдущий тест проверяет рендер лишь косвенно: выключенных полей в карте
// нет вовсе, поэтому строка не печатается из-за пустого значения, а не из-за
// проверки в самом рендере (вскрыто порчей кода — снятие проверки тот тест
// не уронило). Здесь карта собрана в обход ExtractObfuscation и НЕСЁТ
// выключенные значения: так проверяется именно рубеж RenderClientConfig,
// последний перед выдачей файла пользователю.
func TestRenderClientConfigOmitsOffTrailersFromHandmadeMap(t *testing.T) {
	obf, err := issuer.ExtractObfuscation(serverIface(t, serverConf31Off))
	if err != nil {
		t.Fatal(err)
	}
	obf["RandomTrailers"] = "off"
	obf["DisableCookies"] = "off"

	p := params(t)
	p.Obfuscation = obf

	text, err := issuer.RenderClientConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, unwanted := range []string{"RandomTrailers", "DisableCookies"} {
		if strings.Contains(text, unwanted) {
			t.Errorf("выключенное поле %s напечатано в клиентском конфиге:\n%s", unwanted, text)
		}
	}
}

// Послабление не должно стать дырой: RandomTrailers = off не оправдывает
// отсутствие ContentPaddingAddition — такой сервер это обычный 3.0 без
// обязательного поля, и клиент с ним молча не подключится.
func TestExtractObfuscationStillRequiresPaddingWhenTrailersOff(t *testing.T) {
	body := strings.Replace(serverConf31Off, "ContentPaddingAddition = 0-96\n", "", 1)
	_, err := issuer.ExtractObfuscation(serverIface(t, body))
	if err == nil {
		t.Fatal("ожидалась ошибка: RandomTrailers = off не заменяет ContentPaddingAddition")
	}
	if !strings.Contains(err.Error(), "ContentPaddingAddition") {
		t.Errorf("ошибка не называет недостающее поле: %v", err)
	}
}

// RenderClientConfig — последний рубеж перед выдачей файла, и он обязан
// держать тот же инвариант самостоятельно: карта, собранная в обход
// ExtractObfuscation и лишённая и ContentPaddingAddition, и RandomTrailers,
// не имеет права превратиться в файл.
func TestRenderClientConfigRejectsPaddinglessMapWithoutTrailers(t *testing.T) {
	obf, err := issuer.ExtractObfuscation(serverIface(t, serverConf31))
	if err != nil {
		t.Fatal(err)
	}
	delete(obf, "RandomTrailers")
	delete(obf, "DisableCookies")

	p := params(t)
	p.Obfuscation = obf
	if _, err := issuer.RenderClientConfig(p); err == nil {
		t.Fatal("ожидался отказ: ни ContentPaddingAddition, ни RandomTrailers")
	}
}
