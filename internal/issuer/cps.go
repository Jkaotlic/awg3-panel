package issuer

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Проверка I-пакетов I1..I5 — спека 2026-10-29, раздел «1. Валидатор
// I-пакетов». Значение печатается в клиентский конфиг как есть и разбирается
// amneziawg-go (device/obf.go): опечатка или несуществующий тег там означает,
// что клиент не поднимет интерфейс, а умолчания интерфейса получают ВСЕ его
// клиенты разом. Поэтому проверка отвергает, а не чинит.
//
// Белый список тегов — только те, что эталон и разбирает, и реально шлёт:
// <b 0xHEX>, <r N>, <rc N>, <rd N>, <t>. <c> и <wt> не существуют вовсе.
//
// Два уровня строгости (финальное ревью ветки, I1):
//   - ВВОД (maxN > 0) — каноническая форма, которую пишут наши генераторы:
//     теги вплотную, ровно один пробел между именем и аргументом, без <d>,
//     <ds>, <dz N> (эталон их разбирает, но в тракт отправки I-пакетов не
//     заводит — заготовка под AWG 4.0, пакет ушёл бы не таким, каким задуман);
//   - ВЫДАЧА (maxN <= 0) — не строже самого эталона (device/obf.go,
//     newObfChain): текст и пробелы вне тегов он пропускает, тело тега делит
//     strings.Fields, d/ds/dz разбирает. Так ранее сохранённое и законное для
//     протокола значение продолжает выдаваться.
// `#` отвергается всегда: amneziawg-tools режет по нему строку конфига, и
// значение доехало бы до клиента обрезанным.

// Без учёта регистра: amneziawg-tools разбирает имена ключей так же, и «i1»
// в Extra иначе обошёл бы проверку, а в конфиг лёг бы как I1.
var iKeyRe = regexp.MustCompile(`^[Ii][1-5]$`)

// isIKey — ключ Extra, к которому применяется грамматика I-пакетов.
func isIKey(k string) bool { return iKeyRe.MatchString(k) }

// countIPackets — число непустых I1..I5: каждый из них клиент шлёт отдельной
// датаграммой в одной пачке с junk-пакетами и init (см. batchOverflowErr).
func countIPackets(extra map[string]string) int {
	n := 0
	for k, v := range extra {
		if isIKey(k) && v != "" {
			n++
		}
	}
	return n
}

// validateCPS проверяет значение I-пакета. maxN — потолок N в тегах
// <r|rc|rd N>; maxN <= 0 значит «без потолка». Потолок — наш выбор ради
// переносимости (maxRandomTagLen), протокол его не требует, поэтому на ВВОДЕ
// он действует, а на ВЫДАЧЕ ранее сохранённых значений — нет.
func validateCPS(key, v string, maxN int) error {
	strict := maxN > 0
	if v == "" {
		return fmt.Errorf("%w: %s пуст", ErrInvalidInput, key)
	}
	bad := func(pos int, why string) error {
		return fmt.Errorf("%w: %s, позиция %d: %s", ErrInvalidInput, key, pos, why)
	}
	if i := strings.IndexByte(v, '#'); i >= 0 {
		return bad(i, "«#» режет строку конфига у amneziawg-tools")
	}
	for pos := 0; pos < len(v); {
		if v[pos] != '<' {
			if strict {
				return bad(pos, "ожидался тег, начинающийся с «<» (между тегами ничего не допускается)")
			}
			pos++ // эталон текст вне тегов пропускает
			continue
		}
		end := strings.IndexByte(v[pos:], '>')
		if end < 0 {
			return bad(pos, "тег не закрыт «>»")
		}
		body := v[pos+1 : pos+end]
		fields := strings.Fields(body)
		if len(fields) == 0 {
			return bad(pos, "пустой тег")
		}
		if strict && strings.Join(fields, " ") != body {
			return bad(pos, "лишние пробелы в теге: каноническая форма <имя аргумент>")
		}
		if why := validateTag(fields[0], fields[1:], strict, maxN); why != "" {
			return bad(pos, why)
		}
		pos += end + 1
	}
	return nil
}

// validateTag проверяет один тег (имя и аргументы) и возвращает причину
// отказа или "".
func validateTag(name string, args []string, strict bool, maxN int) string {
	unsupported := fmt.Sprintf("тег <%s> не поддерживается (допустимы b, r, rc, rd, t)", name)
	n := func() string {
		if len(args) != 1 || args[0][0] < '1' || args[0][0] > '9' {
			return fmt.Sprintf("в <%s N> N — одно целое от 1 без ведущих нулей и знака", name)
		}
		v, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Sprintf("в <%s N> N — одно целое от 1 без ведущих нулей и знака", name)
		}
		if maxN > 0 && v > maxN {
			return fmt.Sprintf("в <%s N> N = %d больше %d", name, v, maxN)
		}
		return ""
	}
	switch name {
	case "t":
		if len(args) != 0 {
			return "у <t> нет аргументов"
		}
		return ""
	case "d", "ds":
		if strict {
			return unsupported
		}
		if len(args) != 0 {
			return fmt.Sprintf("у <%s> нет аргументов", name)
		}
		return ""
	case "dz":
		if strict {
			return unsupported
		}
		return n()
	case "r", "rc", "rd":
		return n()
	case "b":
		if len(args) != 1 {
			return "в <b …> ожидается один аргумент 0xHEX"
		}
		hex, ok := strings.CutPrefix(args[0], "0x")
		if !ok || hex == "" || len(hex)%2 != 0 {
			return "в <b …> ожидается 0x и непустое чётное число hex-символов"
		}
		for i := 0; i < len(hex); i++ {
			if !isHexDigit(hex[i]) {
				return fmt.Sprintf("в <b …> символ %q не hex", hex[i])
			}
		}
		return ""
	default:
		return unsupported
	}
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}
