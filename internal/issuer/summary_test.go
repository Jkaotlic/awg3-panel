package issuer_test

import (
	"crypto/rand"
	"fmt"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/store"
)

// Сводка обязана считать по ЖИВОМУ серверу, ровно как список пиров:
// снесённого вручную пира в ней нет, а не «есть, но с нулями».
func TestServiceSummaryПоЖивомуСерверу(t *testing.T) {
	svc, fake, cfg := service(t)
	fake.SetDevice("PUBSERVER=", 51772)

	if _, err := svc.Add("ноут"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	sum, err := svc.Summary()
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	// service(t) сеет liveConf с ДВУМЯ уже существующими пирами (me, papa —
	// см. internal/issuer/apply_test.go), Add добавляет третьего: итог 3, а
	// не 1. Брифовый тест предполагал пустой сервер — см. отчёт задачи 3.
	if sum.PeersTotal != 3 {
		t.Errorf("PeersTotal = %d, ожидалось 3", sum.PeersTotal)
	}
	if sum.ListenPort != 51772 || sum.PublicKey != "PUBSERVER=" {
		t.Errorf("поля устройства не доехали: %+v", sum)
	}
	if sum.Interface != cfg.Interfaces[0].Interface {
		t.Errorf("Interface = %q, ожидалось %q", sum.Interface, cfg.Interfaces[0].Interface)
	}
	var _ issuer.IfaceSummary = sum
}

// Версия бинаря не меняется без рестарта сервиса, а сводка опрашивается
// консолью каждые 10 секунд — второй и все последующие вызовы обязаны
// брать версию из кэша Service, а не дёргать Runner заново.
func TestServiceSummaryВерсияКэшируетсяПослеПервогоВызова(t *testing.T) {
	svc, fake, _ := service(t)
	fake.SetDevice("PUBSERVER=", 51772)
	fake.FakeVersion = "amneziawg-go 0.0.20250522"

	if _, err := svc.Summary(); err != nil {
		t.Fatalf("первый Summary: %v", err)
	}
	sum, err := svc.Summary()
	if err != nil {
		t.Fatalf("второй Summary: %v", err)
	}
	if sum.Version != "amneziawg-go 0.0.20250522" {
		t.Errorf("Version = %q, ожидалось %q", sum.Version, "amneziawg-go 0.0.20250522")
	}
	if fake.VersionCalls != 1 {
		t.Errorf("Version у Runner вызван %d раз, ожидался ровно 1 (кэш)", fake.VersionCalls)
	}
}

// Ошибка чтения версии не роняет сводку целиком: это единственный НОВЫЙ
// вызов к серверу во всей задаче (см. брифинг), и его отказ обязан быть
// настолько же безобидным, насколько бесполезно само поле, — пустая строка,
// а не сорванный запрос сводки.
func TestServiceSummaryВерсияОшибкаНеРоняетСводку(t *testing.T) {
	svc, fake, _ := service(t)
	fake.SetDevice("PUBSERVER=", 51772)
	fake.FakeVersionErr = fmt.Errorf("amneziawg-go --version: exit status 127")

	sum, err := svc.Summary()
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if sum.Version != "" {
		t.Errorf("Version = %q, ожидалась пустая строка при ошибке чтения версии", sum.Version)
	}
}

// --- Задача 4 (спека 2026-08-25, раздел 5.6): предупреждение о несоответствии профиля I1 порту ---

// TestServiceSummaryMismatchНепустойПриНесогласованномПорте — в умолчаниях
// лежит DNS-пакет (канонический порт 53), а живой интерфейс слушает 443
// (канонический порт QUIC) — несоответствие обязано быть видно оператору.
func TestServiceSummaryMismatchНепустойПриНесогласованномПорте(t *testing.T) {
	svc, fake, cfg := service(t)
	fake.SetDevice("PUBSERVER=", 443)

	dnsI1, err := issuer.GenerateSignatureFor(rand.Reader, issuer.MimicryDNS)
	if err != nil {
		t.Fatal(err)
	}
	d := store.Defaults{Extra: map[string]string{"I1": dnsI1}}
	if err := d.Save(cfg.Interfaces[0].DefaultsPath()); err != nil {
		t.Fatal(err)
	}

	sum, err := svc.Summary()
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if sum.MimicryMismatch == "" {
		t.Fatal("MimicryMismatch пуст при несогласованных порте (443) и профиле I1 (dns, канонический порт 53)")
	}
	// Текст обязан называть и порт, и профиль, и куда смотреть (образец из
	// раздела 5.6 спеки) — оператору нужно понять проблему без похода в код.
	for _, want := range []string{"443", "dns", "53"} {
		if !strings.Contains(sum.MimicryMismatch, want) {
			t.Errorf("MimicryMismatch = %q, не содержит %q", sum.MimicryMismatch, want)
		}
	}
}

// TestServiceSummaryMismatchПустПриСогласованнойПаре — I1 задан, но его
// профиль совпадает с портом интерфейса: предупреждать не о чем.
func TestServiceSummaryMismatchПустПриСогласованнойПаре(t *testing.T) {
	svc, fake, cfg := service(t)
	fake.SetDevice("PUBSERVER=", 53) // канонический порт DNS.

	dnsI1, err := issuer.GenerateSignatureFor(rand.Reader, issuer.MimicryDNS)
	if err != nil {
		t.Fatal(err)
	}
	d := store.Defaults{Extra: map[string]string{"I1": dnsI1}}
	if err := d.Save(cfg.Interfaces[0].DefaultsPath()); err != nil {
		t.Fatal(err)
	}

	sum, err := svc.Summary()
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if sum.MimicryMismatch != "" {
		t.Errorf("MimicryMismatch = %q, ожидалась пустая строка при согласованной паре порт/профиль", sum.MimicryMismatch)
	}
}

// TestServiceSummaryMismatchПустБезI1 — defaults.json ещё не существует (I1
// вовсе нет ни в каком виде): сравнивать не с чем, предупреждения нет. Заодно
// проверяет побочный эффект: Summary() не обязана создавать defaults.json —
// это read-путь, доступный и в read-only сборке (PeerLister.Summary), и
// сеять I1 через crypto/rand ей не пристало (см. комментарий у
// Service.currentSignature в summary.go).
func TestServiceSummaryMismatchПустБезI1(t *testing.T) {
	svc, fake, _ := service(t)
	fake.SetDevice("PUBSERVER=", 443)

	sum, err := svc.Summary()
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if sum.MimicryMismatch != "" {
		t.Errorf("MimicryMismatch = %q, ожидалась пустая строка — I1 в умолчаниях нет вовсе", sum.MimicryMismatch)
	}
}

// Спека 2026-10-29, раздел 3: сводка несёт предупреждения по живому [Interface].
func TestServiceSummaryConfigWarnings(t *testing.T) {
	bad := strings.Replace(liveConf, "ContentPaddingAddition = 0-96\n", "RandomTrailers = on\n", 1)
	svc, _, _ := serviceWithConf(t, bad)
	sum, err := svc.Summary()
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if len(sum.ConfigWarnings) == 0 {
		t.Fatal("хвосты без ContentPaddingAddition и с разными S — ожидались предупреждения")
	}
	svc, _, _ = service(t)
	if sum, _ = svc.Summary(); sum.ConfigWarnings != nil {
		t.Fatalf("сервер 3.0 без нарушений — предупреждений быть не должно, получено %q", sum.ConfigWarnings)
	}
}
