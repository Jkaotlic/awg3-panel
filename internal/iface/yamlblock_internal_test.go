package iface

import "testing"

// Тесты этого файла — внутренние (package iface, без _test-суффикса в имени
// пакета) намеренно: blockPresent не экспортирована и экспортироваться не
// должна — она существует только ради постусловия шага 6 раздела 6А.5 спеки
// 2026-08-25. При этом снаружи её поведение на подписанном комментарием id
// НЕДОСТИЖИМО: постусловие attach ищет ТОЛЬКО что вставленный блок (у него
// комментария нет по построению — его нарисовал RenderInterfaceBlock), а
// постусловие detach проходит при present == false, то есть неверный разбор
// id даёт там тот же ответ, что и верный. Иными словами, сквозной тест эту
// ветку не покрыл бы даже случайно — а без покрытия она и есть та «третья
// копия», которую финальное ревью велело схлопнуть.
const presentYAML = `interfaces:
  - id: awg3      # первый
    interface: awg3
  - id: awg2      # второй
    interface: awg2
`

// TestBlockPresentStripsInlineComment — третья из трёх копий обхода списка
// (InsertInterface, RemoveInterface, blockPresent) читает id тем же
// разбором, что и первые две. До финального ревью ветки копий и вправду
// было три, и починка разбора в одной из них оставила бы постусловие
// применения врать: config.yaml, взятый со свежей установки (install.sh
// копирует deploy/config.example.yaml с подписанными строками `- id:`
// дословно), не содержал бы для blockPresent НИ ОДНОГО распознанного id.
func TestBlockPresentStripsInlineComment(t *testing.T) {
	for _, id := range []string{"awg3", "awg2"} {
		ok, err := blockPresent(presentYAML, id)
		if err != nil {
			t.Fatalf("blockPresent(%q): %v", id, err)
		}
		if !ok {
			t.Errorf("blockPresent(%q) = false — id с хвостовым комментарием не распознан", id)
		}
	}
	ok, err := blockPresent(presentYAML, "нетакого")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("blockPresent нашла id, которого в тексте нет")
	}
}

// TestStripInlineComment — правила YAML для хвостового комментария в одном
// месте: комментарий начинается с `#`, перед которым пробел, табуляция или
// начало строки, и НЕ начинается внутри кавычек. Каждая строка таблицы —
// значение, которое реально может стоять в config.yaml на боевом хосте.
func TestStripInlineComment(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`awg3`, `awg3`},
		{`awg3      # slug для URL`, `awg3      `},
		{`"awg3"    # подпись`, `"awg3"    `},
		{`a#b`, `a#b`},                // решётка без пробела — часть скаляра
		{`"a#b"`, `"a#b"`},            // решётка в кавычках — часть скаляра
		{`"a # b"`, `"a # b"`},        // и с пробелом тоже, раз она в кавычках
		{`"a\"# b" # x`, `"a\"# b" `}, // экранированная кавычка не закрывает строку
		{`# только комментарий`, ``},
		{"awg3\t# после табуляции", "awg3\t"},
	} {
		if got := stripInlineComment(tc.in); got != tc.want {
			t.Errorf("stripInlineComment(%q) = %q, ожидали %q", tc.in, got, tc.want)
		}
	}
}
