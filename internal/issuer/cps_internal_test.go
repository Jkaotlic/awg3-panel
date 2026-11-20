package issuer

import (
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
)

// Грамматика I-пакетов — спека 2026-10-29, раздел «1. Валидатор I-пакетов».
func TestValidateCPSГрамматика(t *testing.T) {
	ok := []string{
		"<b 0x000100002112a442><r 12>",
		"<t>",
		"<b 0xAbCd><rc 5><rd 1000><t>",
	}
	for _, v := range ok {
		if err := validateCPS("I1", v, maxRandomTagLen); err != nil {
			t.Errorf("%q: ожидался успех, получено %v", v, err)
		}
	}
	bad := []string{
		"", "<c>", "<wt>", "<d>", "<ds>", "<dz 4>",
		"<b 0xabc>", "<b 0x>", "<b 0xzz>",
		"<r 0>", "<r 012>", "<r -1>", "<r +5>", "<r 1001>",
		"<r 12> <t>", "<r 12>x", "<r 12", "<b 0x00>#", "<>", "<r>", "<r 12 >",
	}
	for _, v := range bad {
		if err := validateCPS("I1", v, maxRandomTagLen); err == nil {
			t.Errorf("%q: ожидался отказ", v)
		}
	}
}

func TestValidateCPSБезПотолкаНаВыдаче(t *testing.T) {
	if err := validateCPS("I1", "<r 1177>", 0); err != nil {
		t.Fatalf("без потолка <r 1177> законен для протокола: %v", err)
	}
	if err := validateCPS("I1", "<r 1177>", maxRandomTagLen); err == nil {
		t.Fatal("на вводе <r 1177> должен отвергаться потолком 1000")
	}
}

func TestValidateCPSОшибкаНазываетПолеИПозицию(t *testing.T) {
	err := validateCPS("I2", "<r 12><c>", maxRandomTagLen)
	if err == nil || !strings.Contains(err.Error(), "I2") || !strings.Contains(err.Error(), "6") {
		t.Fatalf("ошибка должна называть поле I2 и позицию 6, получено %v", err)
	}
}

// Сторож: панель не имеет права отвергнуть собственный сев (Review Focus 2).
func TestГенераторыI1ПроходятВалидатор(t *testing.T) {
	for _, p := range []MimicryProfile{MimicryQUIC, MimicryDNS, MimicrySTUN} {
		port, _ := PortForProfile(p)
		for i := 0; i < 200; i++ {
			v, err := GenerateSignatureFor(rand.Reader, p)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateCPS("I1", v, maxRandomTagLen); err != nil {
				t.Fatalf("%s: генератор дал негодный I1: %v", p, err)
			}
			pv, ok := personalSignature(fmt.Sprintf("peer-%d", i), fmt.Sprintf("pub-%d", i), v, port)
			if !ok {
				t.Fatalf("%s: личный I1 не выведен", p)
			}
			if err := validateCPS("I1", pv, maxRandomTagLen); err != nil {
				t.Fatalf("%s: личный I1 негоден: %v", p, err)
			}
		}
	}
}

// Финальное ревью, I1: на выдаче грамматика не строже amneziawg-go
// (device/obf.go newObfChain): пробелы и текст вне тегов пропускаются,
// тело тега делится strings.Fields, d/ds/dz разбираются. Отвергается только
// то, что эталон не разберёт (неизвестный/незакрытый тег, негодный аргумент),
// и `#` — он режет строку конфига у amneziawg-tools.
func TestValidateCPSНаВыдачеПоПротоколу(t *testing.T) {
	for _, v := range []string{"<r 12> <t>", "<b  0x01>", "<r 10 >", "<d>", "<ds>", "<dz 4>", "x<t>"} {
		if err := validateCPS("I1", v, 0); err != nil {
			t.Errorf("%q: законно для протокола, на выдаче отвергнуто: %v", v, err)
		}
		if err := validateCPS("I1", v, maxRandomTagLen); err == nil {
			t.Errorf("%q: на вводе ожидался отказ (строгая форма)", v)
		}
	}
	for _, v := range []string{"<c>", "<wt>", "<r 12", "<r 0>", "<b 0xabc>", "<t>#x", "<r>", "<dz>"} {
		if err := validateCPS("I1", v, 0); err == nil {
			t.Errorf("%q: эталон не разберёт или строка обрежется — на выдаче ожидался отказ", v)
		}
	}
}

// Ревью фазы 2: amneziawg-tools разбирает имена ключей без учёта регистра —
// «i1» тоже I-пакет и обязан проходить ту же проверку.
func TestIsIKeyБезУчётаРегистра(t *testing.T) {
	if !isIKey("i1") || !isIKey("I5") || isIKey("i6") {
		t.Fatal("isIKey обязан узнавать i1..i5 в любом регистре и не трогать i6")
	}
	if err := ValidateExtra(map[string]string{"i1": "<c>"}); err == nil {
		t.Fatal("i1=<c> обошёл грамматику I-пакетов")
	}
}
