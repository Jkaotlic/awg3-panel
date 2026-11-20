package iface_test

import (
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/iface"
)

func attachRequest() iface.Request {
	return iface.Request{
		Version: 1, Action: iface.ActionAttach,
		CreatedAt: "2026-08-27T10:00:00Z", CreatedBy: "admin", ID: "awg2",
		Attach: &iface.AttachPayload{
			ConfPath: "/etc/amnezia/amneziawg/awg2.conf",
			Device:   "awg2",
			Block: config.Interface{
				ID: "awg2", Title: "тест", Interface: "awg2",
				Config: "/etc/amnezia/amneziawg/awg2.conf",
				BinDir: "/opt/awg2/bin",
			},
		},
	}
}

// TestSaveThenListRoundTrip — заявка, записанная на диск, читается обратно
// той же по значению. Это основа всей схемы: между записью и применением
// стоит перезапуск процесса и, как правило, другая машина оператора, и
// исполнитель обязан получить ровно то, что показала консоль.
func TestSaveThenListRoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := attachRequest()

	name, err := iface.Save(dir, want)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(name, ".json") {
		t.Errorf("имя заявки = %q, ожидали суффикс .json", name)
	}

	got, err := iface.List(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("заявок %d, ожидали 1", len(got))
	}
	if got[0].Attach == nil || got[0].Attach.Block.BinDir != "/opt/awg2/bin" {
		t.Errorf("payload не пережил круговой обход: %+v", got[0].Attach)
	}
}

// TestSaveWritesPrivateFile — заявка лежит в каталоге состояния и
// описывает будущее изменение хоста. Права 0600 не косметика: файл читает
// root по SSH, а всё остальное на этой машине читать его не должно.
func TestSaveWritesPrivateFile(t *testing.T) {
	if goruntime.GOOS == "windows" {
		t.Skip("unix-права не проверяются на Windows")
	}
	dir := t.TempDir()
	name, err := iface.Save(dir, attachRequest())
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Errorf("права = %o, ожидали 600", perm)
	}
}

// TestParseRejectsUnknownField — разбор строгий. Заявка, собранная НОВОЙ
// версией панели, не должна тихо применяться старым исполнителем не
// полностью: пропущенное поле — это пропущенный шаг изменения хоста, и
// узнать о нём постфактум неоткуда (спека 2026-08-25, раздел 4).
func TestParseRejectsUnknownField(t *testing.T) {
	raw := []byte(`{"version":1,"action":"attach","id":"awg2","переносим_ключи":true}`)
	if _, err := iface.Parse(raw); err == nil {
		t.Fatal("неизвестное поле принято, ожидался отказ")
	}
}

// TestParseRejectsUnknownAction — то же для значения action: исполнитель,
// не знающий действия, обязан отказаться, а не выполнить ближайшее похожее.
func TestParseRejectsUnknownAction(t *testing.T) {
	raw := []byte(`{"version":1,"action":"перенести","id":"awg2"}`)
	if _, err := iface.Parse(raw); err == nil {
		t.Fatal("неизвестное действие принято, ожидался отказ")
	}
}

// TestParseRejectsFutureVersion — версия формата старше известной значит,
// что заявку писала более новая панель. Применять её нельзя по той же
// причине, что и заявку с неизвестным полем.
func TestParseRejectsFutureVersion(t *testing.T) {
	raw := []byte(`{"version":2,"action":"attach","id":"awg2"}`)
	if _, err := iface.Parse(raw); err == nil {
		t.Fatal("будущая версия принята, ожидался отказ")
	}
}

// TestParseRejectsPayloadMismatch — action и payload обязаны совпадать.
// Заявка с action=attach и телом detach не «наполовину верна», она
// бессмысленна, и обнаружить это надо при разборе, а не на середине
// изменения хоста.
func TestParseRejectsPayloadMismatch(t *testing.T) {
	raw := []byte(`{"version":1,"action":"attach","id":"awg2",` +
		`"detach":{"id":"awg2","device":"awg2"}}`)
	if _, err := iface.Parse(raw); err == nil {
		t.Fatal("заявка с чужим payload принята, ожидался отказ")
	}
}

// TestCancelRemovesRequest — отмена убирает заявку из каталога.
// Идемпотентности здесь НЕ требуется: повторная отмена уже отменённой —
// это, скорее всего, промах по имени, и молчать о нём незачем.
func TestCancelRemovesRequest(t *testing.T) {
	dir := t.TempDir()
	name, err := iface.Save(dir, attachRequest())
	if err != nil {
		t.Fatal(err)
	}
	if err := iface.Cancel(dir, name); err != nil {
		t.Fatal(err)
	}
	got, err := iface.List(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("после отмены заявок %d, ожидали 0", len(got))
	}
}

// TestCancelRejectsPathTraversal — имя заявки приходит из HTTP-запроса
// (DELETE /api/manage/requests/{name}, спека 2026-08-25, раздел 9), то есть
// от недоверенной стороны. Без этой проверки «..%2f..%2fetc%2fshadow»
// удалял бы файлы вне каталога заявок правами демона.
func TestCancelRejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()
	for _, bad := range []string{"../evil.json", "sub/evil.json", "..", ""} {
		if err := iface.Cancel(dir, bad); err == nil {
			t.Errorf("имя %q принято, ожидался отказ", bad)
		}
	}
}

// TestListIgnoresForeignFiles — в каталоге может лежать что угодно
// (недописанный временный файл, заметка оператора). Перечисление обязано
// брать только заявки и не падать на остальном.
func TestListIgnoresForeignFiles(t *testing.T) {
	dir := t.TempDir()
	if _, err := iface.Save(dir, attachRequest()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "заметка.txt"), []byte("не заявка"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := iface.List(dir)
	if err != nil {
		t.Fatalf("перечисление упало на чужом файле: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("заявок %d, ожидали 1", len(got))
	}
}

// TestRequestsDirDerivedFromState — каталог заявок соседствует с
// каталогами состояния интерфейсов, а не задаётся отдельным полем.
func TestRequestsDirDerivedFromState(t *testing.T) {
	cfg := &config.Config{Interfaces: []config.Interface{{
		ID: "awg3", Storage: config.Storage{State: "/var/lib/awg3panel/awg3/peers.json"},
	}}}
	got, err := iface.RequestsDir(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got != "/var/lib/awg3panel/requests" {
		t.Errorf("RequestsDir = %q", got)
	}
}
