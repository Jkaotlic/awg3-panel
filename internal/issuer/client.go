package issuer

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Jkaotlic/awg3-panel/internal/wgconf"
	"github.com/skip2/go-qrcode"
)

// RequiredObfuscationKeys — поля, без любого из которых клиент AWG 3.0
// молча не подключится (симптом: 0 B received). Проверяются на выпуске,
// а не при жалобе пользователя.
var RequiredObfuscationKeys = []string{
	"S1", "S2", "S3", "S4",
	"H1", "H2", "H3", "H4",
	"HeaderProtectionKey", "ContentPaddingAddition",
}

// TrailerKeys — поля AmneziaWG 3.1. В отличие от списка выше они
// необязательны: сервер без них ведёт себя ровно как 3.0.
//
// RandomTrailers ДВУСТОРОННИЙ — сервер с включённым флагом дописывает
// случайные хвосты, и клиент без этой же строки их не разберёт, поэтому
// поле обязано доехать до выданного .conf, а не остаться на сервере.
//
// Клиенту переносится только ВКЛЮЧЁННОЕ значение: бинарь 3.1 печатает эти
// поля в awg showconf всегда, в том числе как off, а строка
// «RandomTrailers = off» в клиентском файле не несёт смысла (это и есть
// поведение по умолчанию) и при этом ломает разбор у клиентов версии 3.0.
var TrailerKeys = []string{"RandomTrailers", "DisableCookies"}

// TimingKeys — рандомизированные тайминги AmneziaWG 3.0, третий её механизм
// наряду с header protection и content padding. Они ОДНОСТОРОННИЕ: каждая
// сторона живёт по своим таймерам, и совпадать с сервером клиент не обязан
// (сверка с исходниками amneziawg-go 18.09.2026). Переносятся ради
// одинакового поведения сторон и паритета с конфигом, выпущенным руками, —
// не потому, что без них клиент не подключится.
//
// Переносятся только заданные: сервер без этих полей работает на дефолтах
// протокола, и клиент обязан остаться на тех же — выдумать значение здесь
// значило бы развести стороны там, где они совпадали.
//
// Найдено 24.08.2026 сравнением выданного конфига с рабочим, выпущенным
// руками: сервер нёс все пять полей, панель теряла их все.
var TimingKeys = []string{
	"RekeyAfterTime", "RekeyTimeout", "RejectAfterTime",
	"KeepaliveTimeout", "MaxHandshakeAttempts",
}

// isOn трактует значение флага AmneziaWG. Пустое, off, 0 и false — это
// «выключено», всё остальное считается включённым. Нарочно широко: цена
// ошибки несимметрична. Принять неизвестное значение за включённое значит
// перенести клиенту лишнюю строку; принять его за выключенное — молча
// выпустить конфиг, который не сойдётся с сервером.
func isOn(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "off", "0", "false":
		return false
	}
	return true
}

// ClientParams описывает содержимое клиентского конфига AmneziaWG 3.0,
// который RenderClientConfig превращает в текст .conf-файла — тот самый,
// который пользователь импортирует в клиент на телефоне или роутере.
// Это последний набор данных перед тем, как файл уедет с сервера:
// RenderClientConfig проверяет два инварианта этой структуры (полноту
// Obfuscation и согласованность тройки Jc/Jmin/Jmax — см. комментарии к
// полям ниже) и откажет, если они нарушены. Нарушение здесь — не «конфиг
// похуже»: это файл, который настоящий клиент AmneziaWG примет молча и
// либо не подключится с ним вовсе, либо использует не так, как ожидает
// оператор, — без единого признака причины на стороне пользователя.
type ClientParams struct {
	PrivateKey      string
	Address         string
	ServerPublicKey string
	PresharedKey    string
	Endpoint        string
	AllowedIPs      string
	Keepalive       string
	DNS             string
	MTU             string

	// Obfuscation обязана содержать ВСЕ ключи из RequiredObfuscationKeys —
	// как правило, это прямой результат ExtractObfuscation по живому
	// серверному [Interface]. Карта, собранная в обход ExtractObfuscation
	// (вручную, из кэша, из повреждённого состояния) и оказавшаяся неполной
	// или nil, — не «немного хуже»: это конфиг, который клиент AmneziaWG
	// молча примет и с которым не подключится (симптом: 0 B received при
	// растущем sent, без единого признака причины). RenderClientConfig
	// проверяет это самостоятельно — не потому, что ExtractObfuscation уже
	// не проверяет, а потому что вызов ExtractObfuscation можно обойти, а
	// RenderClientConfig — последний рубеж перед выдачей файла пользователю.
	Obfuscation map[string]string

	// Jc, Jmin, Jmax — параметры джиттера (junk-пакетов) AmneziaWG.
	// RenderClientConfig отвергает: отрицательное значение любого из трёх;
	// тройку, заданную частично (не все три строго больше нуля — то же
	// понятие «задано», что и в рендере строк конфига, иначе отрицательное
	// число проходит проверку «все ненулевые», но не печатается); и
	// Jmin >= Jmax при полностью заданной тройке — реальный протокол AmneziaWG
	// требует Jmin строго меньше Jmax, и перевёрнутый или нулевой по ширине
	// диапазон клиент не сможет использовать так, как рассчитывает оператор.
	// Полностью нулевая тройка (джиттер выключен) — валидный и принятый по
	// умолчанию случай (раздел 7.3 спеки).
	Jc, Jmin, Jmax int

	// Extra — дополнительные client-side поля секции [Interface] (например,
	// I1..I20 у некоторых сборок AmneziaWG), не имеющие отдельного поля в
	// этой структуре. Печатаются в порядке sort.Strings по имени ключа: один
	// и тот же набор полей обязан давать один и тот же текст конфига и,
	// значит, один и тот же QR при каждой выдаче, а порядок обхода map в Go
	// не детерминирован. RenderClientConfig прогоняет карту через
	// ValidateExtra перед печатью — тот же «последний рубеж», что и у
	// Obfuscation: карта может быть собрана в обход Effective.
	Extra map[string]string
}

// missingObfuscationKeys возвращает ключи из RequiredObfuscationKeys, для
// которых в m нет значения (в том числе если m == nil — чтение из nil-карты
// в Go безопасно и просто всегда даёт пустую строку). Это ОДНА проверка
// одного инварианта: ошибка в самой функции уронит оба места, откуда она
// вызывается, разом. Вызывается из двух точек — ExtractObfuscation (при
// чтении серверного конфига) и RenderClientConfig (при выдаче клиенту) — не
// ради независимости корректности, а ради устойчивости к обходу по пути
// вызова: код, который соберёт Obfuscation мимо ExtractObfuscation, всё
// равно упрётся в ту же проверку внутри RenderClientConfig.
func missingObfuscationKeys(m map[string]string) []string {
	// Единственное послабление: при включённом RandomTrailers сервер
	// ВПРАВЕ не задавать ContentPaddingAddition — трейлеры сами дают
	// случайный хвост транспорту. Задавать оба вместе тоже штатно (дефолт
	// вендора 10-100 + on/on; в send.go приоритет: ContentPaddingAddition →
	// иначе RandomTrailers → иначе выравнивание 16) — уточнение 04.09.2026,
	// прежняя формулировка «вместе не задаются» была неверна. Требовать поле
	// здесь значило бы объявить исправный сервер 3.1 сломанным.
	//
	// Но «подключится» не значит «будет работать быстро»: без CPA паддинг
	// при хвостах берётся из растущего udpWindow (send.go:607-612), и
	// скорость падает примерно в сто раз. Выдачу это не блокирует — сервер
	// правится руками, панель его не чинит (правило 2), — а сводка
	// предупреждает (interfaceWarnings, спека 2026-10-29, раздел 3).
	//
	// Послабление узкое: RandomTrailers = off его НЕ включает. Такой
	// сервер — обычный 3.0, и без ContentPaddingAddition клиент к нему
	// молча не подключится.
	trailers := isOn(m["RandomTrailers"])
	var missing []string
	for _, k := range RequiredObfuscationKeys {
		if k == "ContentPaddingAddition" && trailers {
			continue
		}
		if m[k] == "" {
			missing = append(missing, k)
		}
	}
	return missing
}

// ExtractObfuscation забирает v3-поля из живого серверного [Interface].
// Значения не хардкодятся: смена обфускации на сервере автоматически
// отражается в новых конфигах (раздел 7.3 спеки). Ошибка называет СРАЗУ ВСЕ
// недостающие поля, а не первое встреченное: иначе оператор чинил бы
// конфиг по одному полю за прогон.
func ExtractObfuscation(iface *wgconf.Section) (map[string]string, error) {
	out := make(map[string]string, len(RequiredObfuscationKeys)+len(TrailerKeys))
	// Поля 3.1 читаются ПЕРВЫМИ: от того, включён ли RandomTrailers,
	// зависит, обязателен ли ContentPaddingAddition в проверке ниже.
	// В карту попадают только включённые — см. комментарий к TrailerKeys.
	for _, k := range TrailerKeys {
		if v := iface.Get(k); isOn(v) {
			out[k] = v
		}
	}
	// Тайминги — как есть, без трактовки значения: диапазон «105-135» и
	// одиночное «120» одинаково валидны, и решать за протокол здесь нечего.
	for _, k := range TimingKeys {
		if v := iface.Get(k); v != "" {
			out[k] = v
		}
	}
	for _, k := range RequiredObfuscationKeys {
		out[k] = iface.Get(k)
	}
	if missing := missingObfuscationKeys(out); len(missing) > 0 {
		return nil, fmt.Errorf("в серверном [Interface] нет обязательных полей AWG 3.0: %s — "+
			"выданный конфиг молча не подключился бы", strings.Join(missing, ", "))
	}
	return out, nil
}

// jitterTripleErr проверяет инвариант «Jc/Jmin/Jmax заданы либо все втроём в
// допустимом виде, либо не заданы вовсе»: см. комментарий к полям
// ClientParams. Понятие «задано» здесь — v > 0, то же самое, что использует
// num() в RenderClientConfig при решении, печатать ли строку. Если бы здесь
// стояло v != 0, отрицательное значение проходило бы эту проверку (все три
// «ненулевые»), но не печаталось бы рендером (num печатает только v > 0) —
// в файл ушла бы частичная тройка без единой ошибки. Поэтому отрицательные
// значения отвергаются явно, раньше, чем до этого расхождения дойдёт дело.
func jitterTripleErr(jc, jmin, jmax int) error {
	if jc < 0 || jmin < 0 || jmax < 0 {
		return fmt.Errorf("параметры джиттера не могут быть отрицательными: Jc=%d, Jmin=%d, Jmax=%d",
			jc, jmin, jmax)
	}
	anySet := jc > 0 || jmin > 0 || jmax > 0
	allSet := jc > 0 && jmin > 0 && jmax > 0
	if anySet && !allSet {
		return fmt.Errorf("параметры джиттера заданы частично: Jc=%d, Jmin=%d, Jmax=%d — "+
			"AmneziaWG требует Jc/Jmin/Jmax либо все вместе, либо ни одного", jc, jmin, jmax)
	}
	if allSet && jmin >= jmax {
		return fmt.Errorf("Jmin (%d) должен быть строго меньше Jmax (%d): таким диапазоном размеров "+
			"junk-пакетов настоящий клиент AmneziaWG не воспользуется осмысленно", jmin, jmax)
	}
	return nil
}

// batchOverflowErr — пачка «I-пакеты + Jc junk + init» не больше goBatchSize
// (см. константы в params.go). Проверяется по слитым значениям: Jc из
// умолчаний и I-пакеты из оверрайда пира по отдельности могут быть законны,
// а вместе — нет.
func batchOverflowErr(jc, iCount int) error {
	if jc > 0 && jc+iCount+1 > goBatchSize {
		return fmt.Errorf("Jc (%d) + I-пакеты (%d) + init = %d датаграмм в одной пачке, а amneziawg-go "+
			"вмещает %d — клиент упадёт на первом рукопожатии", jc, iCount, jc+iCount+1, goBatchSize)
	}
	return nil
}

// RenderClientConfig собирает текст клиентского .conf. Это последний рубеж
// перед тем, как байты уедут пользователю, поэтому функция обязана отказать
// — а не выдать усечённый или внутренне противоречивый конфиг — если
// Obfuscation неполна (см. ClientParams.Obfuscation), тройка Jc/Jmin/Jmax
// нарушает любое из условий: отрицательное значение, частичная тройка,
// Jmin >= Jmax при полностью заданной тройке (см. ClientParams.Jc), либо
// Extra не проходит ValidateExtra (см. ClientParams.Extra). Все эти случаи
// иначе доходят до жалобы пользователя через неделю, а не до отказа на
// этапе выпуска.
func RenderClientConfig(p ClientParams) (string, error) {
	if missing := missingObfuscationKeys(p.Obfuscation); len(missing) > 0 {
		return "", fmt.Errorf("нельзя выпустить клиентский конфиг: в Obfuscation нет обязательных полей AWG 3.0: %s — "+
			"клиент получил бы файл, который молча не подключится", strings.Join(missing, ", "))
	}
	if err := validateClientFields(p.Endpoint, p.AllowedIPs, p.Keepalive, p.DNS, p.MTU); err != nil {
		return "", fmt.Errorf("нельзя выпустить клиентский конфиг: %w", err)
	}
	for _, field := range []struct{ name, value string }{
		{"PrivateKey", p.PrivateKey}, {"Address", p.Address},
		{"PublicKey", p.ServerPublicKey}, {"PresharedKey", p.PresharedKey},
	} {
		if err := rejectInjection(field.name, field.value); err != nil {
			return "", fmt.Errorf("нельзя выпустить клиентский конфиг: %w", err)
		}
	}
	for key, value := range p.Obfuscation {
		if err := rejectInjection(key, value); err != nil {
			return "", fmt.Errorf("нельзя выпустить клиентский конфиг: %w", err)
		}
	}
	if err := jitterTripleErr(p.Jc, p.Jmin, p.Jmax); err != nil {
		return "", err
	}
	if err := batchOverflowErr(p.Jc, countIPackets(p.Extra)); err != nil {
		return "", fmt.Errorf("нельзя выпустить клиентский конфиг: %w", err)
	}
	// Без потолка N: на выдаче отвергается только то, что ломает протокол
	// (спека 2026-10-29, раздел 1) — потолок 1000 действует на вводе.
	if err := validateExtra(p.Extra, 0); err != nil {
		return "", fmt.Errorf("нельзя выпустить клиентский конфиг: %w", err)
	}

	var b strings.Builder
	line := func(k, v string) {
		if v != "" {
			b.WriteString(k + " = " + v + "\n")
		}
	}
	num := func(k string, v int) {
		if v > 0 {
			b.WriteString(k + " = " + strconv.Itoa(v) + "\n")
		}
	}

	b.WriteString("[Interface]\n")
	line("PrivateKey", p.PrivateKey)
	line("Address", p.Address)
	line("MTU", p.MTU)
	line("DNS", p.DNS) // пусто по умолчанию — не конфликтуем с AGH
	num("Jc", p.Jc)
	num("Jmin", p.Jmin)
	num("Jmax", p.Jmax)
	for _, k := range RequiredObfuscationKeys {
		line(k, p.Obfuscation[k])
	}
	// Поля 3.1 печатаются только включёнными — даже если выключенное
	// значение попало в карту в обход ExtractObfuscation: строка
	// «RandomTrailers = off» смысла не несёт, а разбор у клиента 3.0 ломает.
	for _, k := range TrailerKeys {
		if v := p.Obfuscation[k]; isOn(v) {
			line(k, v)
		}
	}
	// Порядок фиксирован списком, а не обходом карты: один и тот же сервер
	// обязан давать один и тот же текст конфига, иначе diff двух выдач
	// показывает мусор вместо изменений.
	for _, k := range TimingKeys {
		line(k, p.Obfuscation[k])
	}
	extraKeys := make([]string, 0, len(p.Extra))
	for k := range p.Extra {
		extraKeys = append(extraKeys, k)
	}
	sort.Strings(extraKeys)
	for _, k := range extraKeys {
		line(k, p.Extra[k])
	}

	b.WriteString("\n[Peer]\n")
	line("PublicKey", p.ServerPublicKey)
	line("PresharedKey", p.PresharedKey)
	line("AllowedIPs", p.AllowedIPs)
	line("Endpoint", p.Endpoint)
	line("PersistentKeepalive", p.Keepalive)
	return b.String(), nil
}

func QRPNG(text string) ([]byte, error) {
	return qrcode.Encode(text, qrcode.Medium, 512)
}
