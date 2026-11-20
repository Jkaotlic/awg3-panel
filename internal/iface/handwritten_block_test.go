package iface_test

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/Jkaotlic/awg3-panel/internal/iface"
)

// Сторож паритета блока, который пишет attach, с блоком, написанным руками.
//
// Заведён по образцу TestIssuedConfigMatchesHandWrittenFieldSet
// (internal/issuer): тот ловит расхождение ВЫДАННОГО КЛИЕНТСКОГО конфига с
// конфигом, выписанным руками для того же сервера, и заведён после ровно
// такой же отладки — файл выглядел правдоподобно и при этом не подключался.
// Здесь — та же болезнь этажом выше: блок config.yaml, собранный
// PlanAttach, был БЕДНЕЕ рукописного (ни jc/jmin/jmax, ни
// persistent_keepalive), ошибки не возникало, туннель вставал — и
// подключённый интерфейс молча выдавал клиентские конфиги без джиттера и
// без keepalive, тише рукописных, причём сказать об этом оператору было
// некому.
//
// Почему «обычный механизм первого обращения» этого НЕ чинит (посылка
// раздела 6А.3 спеки 2026-08-25, исправленная тем же кругом ревью):
// issuer.Service.defaults() сеет defaults.json из s.iface.Client — то есть
// из ТОГО ЖЕ блока, который пишет attach. Пустой блок сеет пустые
// умолчания: store.LoadDefaults нули не нормализует, а RenderClientConfig
// при нулевой тройке просто не печатает Jc/Jmin/Jmax.

// handWrittenBlock читает первый элемент interfaces: из
// deploy/config.example.yaml — того самого файла, который install.sh
// копирует на боевой хост дословно. Образец берётся ИЗ РЕПОЗИТОРИЯ, а не
// переписывается в тест константой: копия разошлась бы с оригиналом ровно
// так же, как разошёлся с ним PlanAttach.
func handWrittenBlock(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "config.example.yaml"))
	if err != nil {
		t.Fatalf("рукописный образец не прочитан: %v", err)
	}
	var doc struct {
		Interfaces []map[string]any `yaml:"interfaces"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("рукописный образец не разбирается: %v", err)
	}
	if len(doc.Interfaces) == 0 {
		t.Fatal("в рукописном образце нет ни одного интерфейса")
	}
	return doc.Interfaces[0]
}

// renderedAttachBlock прогоняет блок, выведенный PlanAttach, через тот же
// RenderInterfaceBlock, каким его запишет исполнитель, и разбирает
// результат обратно — сравнивается то, что реально ляжет в config.yaml, а
// не структура в памяти.
func renderedAttachBlock(t *testing.T) map[string]any {
	t.Helper()
	p, err := iface.PlanAttach(iface.AttachInput{
		ID: "awg2", Title: "awg2 (2.0)", ConfName: "awg2.conf",
	}, planEnv(t))
	if err != nil {
		t.Fatal(err)
	}
	text, err := iface.RenderInterfaceBlock(p.Block)
	if err != nil {
		t.Fatal(err)
	}
	var items []map[string]any
	if err := yaml.Unmarshal([]byte(text), &items); err != nil {
		t.Fatalf("нарисованный блок не разбирается: %v\n%s", err, text)
	}
	if len(items) != 1 {
		t.Fatalf("нарисован не один элемент, а %d:\n%s", len(items), text)
	}
	return items[0]
}

func keysOf(m map[string]any) map[string]bool {
	out := map[string]bool{}
	for k := range m {
		out[k] = true
	}
	return out
}

// filled — «поле заполнено осмысленным значением». Пустая строка и ноль
// значат для панели одно и то же: RenderClientConfig такое поле в
// клиентский конфиг просто не печатает.
func filled(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case string:
		return t != ""
	case int:
		return t != 0
	default:
		return true
	}
}

func submap(t *testing.T, m map[string]any, key string) map[string]any {
	t.Helper()
	v, ok := m[key].(map[string]any)
	if !ok {
		t.Fatalf("секция %q не мапа: %#v", key, m[key])
	}
	return v
}

// TestAttachBlockMatchesHandWrittenFieldSet — набор ключей, которые пишет
// attach, обязан совпадать с набором ключей рукописного блока, и каждое
// поле, заполненное в рукописном, обязано быть заполнено и здесь.
func TestAttachBlockMatchesHandWrittenFieldSet(t *testing.T) {
	hand, got := handWrittenBlock(t), renderedAttachBlock(t)

	handKeys, gotKeys := keysOf(hand), keysOf(got)
	for k := range handKeys {
		if !gotKeys[k] {
			t.Errorf("attach не пишет ключ %q, который есть в рукописном блоке", k)
		}
	}
	for k := range gotKeys {
		if !handKeys[k] {
			t.Errorf("attach пишет ключ %q, которого нет в рукописном блоке", k)
		}
	}

	handClient, gotClient := submap(t, hand, "client"), submap(t, got, "client")
	for k, v := range handClient {
		if _, ok := gotClient[k]; !ok {
			t.Errorf("client: attach не пишет ключ %q", k)
			continue
		}
		// dns в рукописном образце пуст сознательно («свой DNS конфликтует
		// с AdGuard Home в домашней сети») — требовать его заполнения
		// значило бы требовать выдумать значение, которого оператор не
		// задавал. Правило поэтому одностороннее: заполненное в образце
		// обязано быть заполнено и здесь, пустое — свободно.
		if filled(v) && !filled(gotClient[k]) {
			t.Errorf("client.%s: в рукописном блоке %v, attach пишет пустое (%v) — "+
				"подключённый интерфейс тише рукописного, и сказать об этом оператору некому",
				k, v, gotClient[k])
		}
	}
	for k := range gotClient {
		if _, ok := handClient[k]; !ok {
			t.Errorf("client: attach пишет ключ %q, которого нет в рукописном блоке", k)
		}
	}

	handStorage, gotStorage := submap(t, hand, "storage"), submap(t, got, "storage")
	for k, v := range handStorage {
		if _, ok := gotStorage[k]; !ok {
			t.Errorf("storage: attach не пишет ключ %q", k)
			continue
		}
		// client_configs — единственное исключение, и оно названное:
		// легаси-каталог выданных .conf, нужный ТОЛЬКО миграции ключей со
		// старой одноинтерфейсной установки. У взятого под управление
		// интерфейса его нет и быть не может — панель им никогда не
		// управляла, переносить ключи неоткуда. Второй, рукописный же блок
		// того же образца (awg31) поле не задаёт по той же причине.
		if k == "client_configs" {
			continue
		}
		if filled(v) && !filled(gotStorage[k]) {
			t.Errorf("storage.%s: в рукописном блоке %v, attach пишет пустое (%v)", k, v, gotStorage[k])
		}
	}
	for k := range gotStorage {
		if _, ok := handStorage[k]; !ok {
			t.Errorf("storage: attach пишет ключ %q, которого нет в рукописном блоке", k)
		}
	}
}
