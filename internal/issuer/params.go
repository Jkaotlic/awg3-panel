package issuer

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/Jkaotlic/awg3-panel/internal/store"
)

// EffectiveClient — итоговый набор клиентских параметров одного пира после
// слияния умолчаний интерфейса (store.Defaults) с его персональными
// оверрайдами (store.Overrides). Это вход для сборки ClientParams в
// RenderClientConfig, а не отдельный источник правды: конфиг всегда
// собирается заново из Effective(...), файла с застывшим результатом нет
// (раздел 5.2 спеки).
type EffectiveClient struct {
	Endpoint       string
	AllowedIPs     string
	Keepalive      string
	DNS            string
	MTU            string
	Jc, Jmin, Jmax int
	Extra          map[string]string
}

// Effective накладывает персональные оверрайды пира на умолчания интерфейса.
// MTU по умолчанию берётся у сервера: клиент, чей MTU больше серверного,
// молча теряет крупные пакеты, и заметно это становится не на ping, а на
// загрузке страниц.
func Effective(d store.Defaults, o *store.Overrides, serverMTU string) EffectiveClient {
	e := EffectiveClient{
		Endpoint: d.Endpoint, AllowedIPs: d.AllowedIPs, Keepalive: d.Keepalive,
		DNS: d.DNS, MTU: serverMTU, Jc: d.Jc, Jmin: d.Jmin, Jmax: d.Jmax,
		Extra: map[string]string{},
	}
	for k, v := range d.Extra {
		e.Extra[k] = v
	}
	if o == nil {
		return e
	}
	setStr(&e.Endpoint, o.Endpoint)
	setStr(&e.AllowedIPs, o.AllowedIPs)
	setStr(&e.Keepalive, o.Keepalive)
	setStr(&e.DNS, o.DNS)
	setStr(&e.MTU, o.MTU)
	setInt(&e.Jc, o.Jc)
	setInt(&e.Jmin, o.Jmin)
	setInt(&e.Jmax, o.Jmax)
	// Extra пира заменяет карту умолчаний ЦЕЛИКОМ, а не сливается по ключам:
	// частичное слияние оставило бы пиру поле, которое оператор снял в
	// умолчаниях, и объяснить такое поведение в UI невозможно.
	if o.Extra != nil {
		e.Extra = map[string]string{}
		for k, v := range o.Extra {
			e.Extra[k] = v
		}
	}
	if o.CPS != nil {
		replaceCPS(e.Extra, *o.CPS)
	}
	return e
}

var cpsKeys = [...]string{"I1", "I2", "I3", "I4", "I5"}

func replaceCPS(extra map[string]string, cps [5]string) {
	for key := range extra {
		if isIKey(key) {
			delete(extra, key)
		}
	}
	for i, value := range cps {
		if value != "" {
			extra[cpsKeys[i]] = value
		}
	}
}

func validateCPSOverride(cps *[5]string) error {
	if cps == nil {
		return nil
	}
	extra := make(map[string]string, len(cps))
	for i, value := range cps {
		if value != "" {
			extra[cpsKeys[i]] = value
		}
	}
	return ValidateExtra(extra)
}

func setStr(dst *string, src *string) {
	if src != nil {
		*dst = *src
	}
}

func setInt(dst *int, src *int) {
	if src != nil {
		*dst = *src
	}
}

// knownClientKeys — поля, у которых в конфиге есть своё место. Их дубль в
// extra дал бы две строки одного ключа с неопределённым приоритетом у
// клиента, поэтому отвергается.
var knownClientKeys = func() map[string]bool {
	keys := map[string]bool{
		"privatekey": true, "address": true, "dns": true, "mtu": true,
		"publickey": true, "presharedkey": true, "endpoint": true,
		"allowedips": true, "persistentkeepalive": true,
		"jc": true, "jmin": true, "jmax": true,
		"s1": true, "s2": true, "s3": true, "s4": true,
		"h1": true, "h2": true, "h3": true, "h4": true,
		"preup": true, "postup": true, "predown": true, "postdown": true,
	}
	for _, group := range [][]string{RequiredObfuscationKeys, TrailerKeys, TimingKeys} {
		for _, key := range group {
			keys[strings.ToLower(key)] = true
		}
	}
	return keys
}()

// ValidateExtra проверяет карту дополнительных client-side полей. Её
// содержимое печатается прямо в файл конфига, поэтому проверка отвергает, а
// не экранирует: экранировать в ini-подобном формате нечего, а перевод
// строки в значении — это дописанная строка в чужой секции.
//
// I1..I5 дополнительно проходят грамматику I-пакетов (validateCPS) с
// потолком N = maxRandomTagLen — спека 2026-10-29, раздел 1.
func ValidateExtra(m map[string]string) error {
	return validateExtra(m, maxRandomTagLen)
}

// validateExtra — общее тело ValidateExtra. maxN передаётся в validateCPS:
// ввод зовёт с maxRandomTagLen, выдача (RenderClientConfig) — с 0, чтобы
// законные для протокола ранее сохранённые значения продолжали выдаваться.
func validateExtra(m map[string]string, maxN int) error {
	seen := make(map[string]bool, len(m))
	for k, v := range m {
		if !extraKeyRe.MatchString(k) {
			return fmt.Errorf("%w: имя поля %q недопустимо: ожидается буква, затем до 15 букв и цифр",
				ErrInvalidInput, k)
		}
		key := strings.ToLower(k)
		if knownClientKeys[key] {
			return fmt.Errorf("%w: поле %s задаётся отдельным параметром, а не через extra",
				ErrInvalidInput, k)
		}
		if seen[key] {
			return fmt.Errorf("%w: поле %s повторяется с другим регистром", ErrInvalidInput, key)
		}
		seen[key] = true
		if err := rejectInjection(k, v); err != nil {
			return err
		}
		if strings.TrimSpace(v) != v {
			return fmt.Errorf("%w: значение поля %s содержит пробелы по краям", ErrInvalidInput, k)
		}
		if v == "" {
			return fmt.Errorf("%w: значение поля %s пусто — уберите поле вместо пустого значения",
				ErrInvalidInput, k)
		}
		if isIKey(k) {
			if err := validateCPS(k, v, maxN); err != nil {
				return err
			}
		}
	}
	return nil
}

// rejectInjection проверяет значения, печатаемые одной строкой в .conf.
func rejectInjection(field, v string) error {
	if strings.ContainsAny(v, "\x00\r\n[]") {
		return fmt.Errorf("%w: значение поля %s содержит управляющий символ или скобки", ErrInvalidInput, field)
	}
	return nil
}

var extraKeyRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,15}$`)

func validateEndpoint(v string) error {
	if v == "" {
		return fmt.Errorf("%w: endpoint не задан", ErrInvalidInput)
	}
	host, port, err := net.SplitHostPort(v)
	if err != nil || host == "" || strings.ContainsAny(host, "[]/#=@\\?\x00") ||
		strings.ContainsFunc(host, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return fmt.Errorf("%w: endpoint должен содержать адрес и порт", ErrInvalidInput)
	}
	if strings.HasPrefix(v, "[") {
		addr, err := netip.ParseAddr(host)
		if err != nil || !addr.Is6() {
			return fmt.Errorf("%w: в скобках endpoint ожидается IPv6-адрес", ErrInvalidInput)
		}
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return fmt.Errorf("%w: порт endpoint должен быть числом 1..65535", ErrInvalidInput)
	}
	return nil
}

func validateAllowedIPs(v string) error {
	if err := rejectInjection("allowed_ips", v); err != nil {
		return err
	}
	for _, item := range strings.Split(v, ",") {
		item = strings.TrimSpace(item)
		if _, err := netip.ParsePrefix(item); err == nil {
			continue
		}
		if addr, err := netip.ParseAddr(item); err != nil || addr.Zone() != "" {
			return fmt.Errorf("%w: allowed_ips должен содержать список IPv4/IPv6-адресов или сетей", ErrInvalidInput)
		}
	}
	return nil
}

func validateKeepalive(v string) error {
	if v == "" {
		return nil
	}
	if err := rejectInjection("keepalive", v); err != nil {
		return err
	}
	start, end, rangeSet := strings.Cut(v, "-")
	lo, lowErr := strconv.ParseUint(start, 10, 16)
	if rangeSet {
		hi, highErr := strconv.ParseUint(end, 10, 16)
		if highErr != nil || lo > hi {
			return fmt.Errorf("%w: keepalive должен содержать возрастающий диапазон 0..65535", ErrInvalidInput)
		}
	}
	if lowErr != nil {
		return fmt.Errorf("%w: keepalive должен содержать число или диапазон 0..65535", ErrInvalidInput)
	}
	return nil
}

// ValidateOverrides проверяет явно заданные поля. Тройка джиттера
// проверяется целиком после слияния с умолчаниями.
func ValidateOverrides(o *store.Overrides) error {
	if o == nil {
		return nil
	}
	if err := ValidateExtra(o.Extra); err != nil {
		return err
	}
	if err := validateCPSOverride(o.CPS); err != nil {
		return err
	}
	for _, field := range []struct {
		value *string
		check func(string) error
	}{
		{o.DNS, func(v string) error { return rejectInjection("dns", v) }},
		{o.AllowedIPs, validateAllowedIPs}, {o.Keepalive, validateKeepalive},
		{o.Endpoint, validateEndpoint}, {o.MTU, validateMTU},
	} {
		if field.value != nil {
			if err := field.check(*field.value); err != nil {
				return err
			}
		}
	}
	return validateNonNegativeJitter(o.Jc, o.Jmin, o.Jmax)
}

// validateMTU проверяет MTU как строку из store: конфиг печатает MTU
// текстом, но допустимость определяется числовым диапазоном. 576 — минимум
// IPv4 согласно RFC 791, ниже которого гарантий доставки без фрагментации
// нет; 9000 — верхняя граница распространённых jumbo-кадров. Вне диапазона
// интерфейс с таким MTU либо не поднимется, либо будет фрагментировать
// пакеты в противоречии с самим смыслом настройки этого поля.
func validateMTU(s string) error {
	n, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("%w: mtu %q не является целым числом", ErrInvalidInput, s)
	}
	if n < 576 || n > 9000 {
		return fmt.Errorf("%w: mtu %d вне диапазона 576..9000", ErrInvalidInput, n)
	}
	return nil
}

// Потолки джиттера — спека 2026-10-29, раздел 2.
//
// goBatchSize: amneziawg-go шлёт I-пакеты, затем Jc junk-пакетов, затем init
// ОДНИМ вызовом SendBuffers (device/send.go), а StdNetBind держит массив
// сообщений фиксированного размера conn.IdealBatchSize = 128
// (conn/bind_std.go) — больше датаграмм в пачке значит index out of range и
// клиент, падающий на первом же рукопожатии (amneziawg-go#111, PR#202 не
// влит на 29.10.2026). maxJc = 128 − 5 (I1..I5) − 1 (init): с таким Jc пачка
// влезает при любом наборе I. maxJmax: junk больше туннельного MTU
// фрагментируется и выглядит неправдоподобно.
const (
	goBatchSize = 128
	maxJc       = 122
	maxJmax     = 1280
)

// validateNonNegativeJitter отвергает отрицательные параметры джиттера по
// отдельности, не требуя полноты тройки, — см. комментарий к ValidateOverrides.
// Заодно — потолки Jc и Jmax (см. константы выше).
func validateNonNegativeJitter(jc, jmin, jmax *int) error {
	if jc != nil && *jc > maxJc {
		return fmt.Errorf("%w: jc = %d больше %d — клиент на amneziawg-go не пройдёт первое рукопожатие",
			ErrInvalidInput, *jc, maxJc)
	}
	if jmax != nil && *jmax > maxJmax {
		return fmt.Errorf("%w: jmax = %d больше %d — junk-пакет не должен быть больше туннельного MTU",
			ErrInvalidInput, *jmax, maxJmax)
	}
	if jc != nil && *jc < 0 {
		return fmt.Errorf("%w: jc не может быть отрицательным: %d", ErrInvalidInput, *jc)
	}
	if jmin != nil && *jmin < 0 {
		return fmt.Errorf("%w: jmin не может быть отрицательным: %d", ErrInvalidInput, *jmin)
	}
	if jmax != nil && *jmax < 0 {
		return fmt.Errorf("%w: jmax не может быть отрицательным: %d", ErrInvalidInput, *jmax)
	}
	return nil
}

// ValidateDefaults проверяет самостоятельный набор умолчаний целиком.
func ValidateDefaults(d store.Defaults) error {
	if err := ValidateExtra(d.Extra); err != nil {
		return err
	}
	if err := validateClientFields(d.Endpoint, d.AllowedIPs, d.Keepalive, d.DNS, ""); err != nil {
		return err
	}
	return validateEffectiveJitter(d.Jc, d.Jmin, d.Jmax, "")
}

func validateClientFields(endpoint, allowedIPs, keepalive, dns, mtu string) error {
	if err := validateEndpoint(endpoint); err != nil {
		return err
	}
	if err := validateAllowedIPs(allowedIPs); err != nil {
		return err
	}
	if err := validateKeepalive(keepalive); err != nil {
		return err
	}
	if err := rejectInjection("dns", dns); err != nil {
		return err
	}
	if mtu != "" {
		return validateMTU(mtu)
	}
	return nil
}

func validateEffectiveJitter(jc, jmin, jmax int, mtu string) error {
	if err := validateNonNegativeJitter(&jc, &jmin, &jmax); err != nil {
		return err
	}
	if err := jitterTripleErr(jc, jmin, jmax); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	return validateJunkMTU(jmax, mtu)
}

func validateJunkMTU(jmax int, mtu string) error {
	if n, err := strconv.Atoi(mtu); err == nil && jmax >= n {
		return fmt.Errorf("%w: jmax (%d) должен быть меньше MTU (%d)", ErrInvalidInput, jmax, n)
	}
	return nil
}
