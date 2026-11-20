package iface_test

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/iface"
)

// TestFakeHostRecordsCallsInOrder — подставной хост существует ради одного:
// проверять ПОРЯДОК побочных действий. Тест исполнителя иначе не написать —
// «файл на месте» проходит и при удалении с последующим восстановлением.
func TestFakeHostRecordsCallsInOrder(t *testing.T) {
	h := iface.NewFakeHost()
	if err := h.WriteFileAtomic("/etc/awg3panel/config.yaml", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := h.MkdirAll("/var/lib/awg3panel/awg2", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := h.Systemctl("restart", "awg3panel"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"write /etc/awg3panel/config.yaml",
		"mkdir /var/lib/awg3panel/awg2",
		"systemctl restart awg3panel",
	}
	if !reflect.DeepEqual(h.Calls, want) {
		t.Errorf("журнал = %v, ожидали %v", h.Calls, want)
	}
}

// TestFakeHostReadsBackWhatItWrote — подставной хост держит файлы в памяти,
// иначе исполнитель нельзя проверить целиком: он пишет config.yaml и тут же
// обязан прочитать его обратно при откате.
func TestFakeHostReadsBackWhatItWrote(t *testing.T) {
	h := iface.NewFakeHost()
	if err := h.WriteFileAtomic("/tmp/a", []byte("привет"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := h.ReadFile("/tmp/a")
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "привет" {
		t.Errorf("прочитано %q", b)
	}
}

// TestFakeHostFailAt — инъекция отказа на конкретном вызове: без неё
// нельзя проверить откат, ради которого исполнитель и написан.
func TestFakeHostFailAt(t *testing.T) {
	h := iface.NewFakeHost()
	h.FailAt = "systemctl restart awg3panel"
	if err := h.Systemctl("restart", "awg3panel"); err == nil {
		t.Fatal("инъекция отказа не сработала")
	}
}

// TestFakeHostFailAtOnceFiresOnlyOnce — FailAtOnce нужен для проверки
// отката: восстановительный systemctl restart внутри restore несёт то же
// имя вызова, что и провалившийся исходный, — без одноразового отказа
// нельзя было бы отличить «оба рестарта упали» от «упал только первый, а
// восстановительный поднял панель обратно» (ревью задачи 7, находка 1).
func TestFakeHostFailAtOnceFiresOnlyOnce(t *testing.T) {
	h := iface.NewFakeHost()
	h.FailAt = "systemctl restart awg3panel"
	h.FailAtOnce = true
	if err := h.Systemctl("restart", "awg3panel"); err == nil {
		t.Fatal("первый вызов обязан отказать")
	}
	if err := h.Systemctl("restart", "awg3panel"); err != nil {
		t.Fatalf("второй вызов обязан пройти, отказ одноразовый: %v", err)
	}
	if err := h.Systemctl("restart", "awg3panel"); err != nil {
		t.Fatalf("третий вызов тоже обязан пройти: %v", err)
	}
}

// TestFakeHostExistsSeesDirectories — Exists должен видеть каталоги,
// созданные через MkdirAll, иначе подстава расходится с осHost и тесты
// идемпотентности напишутся ложными.
func TestFakeHostExistsSeesDirectories(t *testing.T) {
	h := iface.NewFakeHost()
	if err := h.MkdirAll("/var/lib/test", 0o700); err != nil {
		t.Fatal(err)
	}
	exists, err := h.Exists("/var/lib/test")
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Error("MkdirAll создал каталог, но Exists его не видит")
	}
}

// TestFakeHostDirEmptyOnNonexistent — DirEmpty на несуществующем каталоге
// вернёт true (спека 2026-08-25, раздел 7: «каталога нет ИЛИ он пуст»).
func TestFakeHostDirEmptyOnNonexistent(t *testing.T) {
	h := iface.NewFakeHost()
	empty, err := h.DirEmpty("/nonexistent/path")
	if err != nil {
		t.Fatal(err)
	}
	if !empty {
		t.Error("несуществующий каталог должен считаться пустым")
	}
}

// TestFakeHostDirEmptyOnNonEmpty — DirEmpty на посеянном непустом каталоге
// вернёт false. Этот отказ нужен для проверки отката подключения при
// наличии старого каталога состояния (раздел 7 спеки 2026-08-25).
func TestFakeHostDirEmptyOnNonEmpty(t *testing.T) {
	h := iface.NewFakeHost()
	h.SeedDir("/var/lib/old") // посеять непустой каталог
	empty, err := h.DirEmpty("/var/lib/old")
	if err != nil {
		t.Fatal(err)
	}
	if empty {
		t.Error("посеянный непустой каталог должен считаться непустым")
	}
}

// TestOSHostExistsAndDirEmptyBehavior — валидация, что osHost.Exists и
// osHost.DirEmpty соответствуют своим контрактам, как описано в интерфейсе
// Host и повторено в FakeHost.
func TestOSHostExistsAndDirEmptyBehavior(t *testing.T) {
	h := iface.NewOSHost()
	dir := t.TempDir()

	// Exists должен видеть созданный каталог
	if err := h.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	exists, err := h.Exists(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Error("osHost.Exists не видит каталог после MkdirAll")
	}

	// DirEmpty должен вернуть true для пустого каталога
	empty, err := h.DirEmpty(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !empty {
		t.Error("osHost.DirEmpty должен вернуть true для пустого каталога")
	}

	// DirEmpty должен вернуть true для несуществующего каталога
	empty, err = h.DirEmpty(filepath.Join(dir, "nonexistent"))
	if err != nil {
		t.Fatal(err)
	}
	if !empty {
		t.Error("osHost.DirEmpty должен вернуть true для несуществующего каталога")
	}
}
