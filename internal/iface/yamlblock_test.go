package iface_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/iface"
)

// sampleYAML — конфиг той же формы, что боевой: комментарий сверху,
// listen, auth, список интерфейсов. Значения выдуманы.
//
// Строки `- id:`, `title:` и `interface:` несут ХВОСТОВЫЕ КОММЕНТАРИИ —
// ровно так, как их кладёт на боевой хост install.sh: он копирует
// deploy/config.example.yaml в /etc/awg3panel/config.yaml дословно
// (install.sh, шаг «конфиг: создаётся ТОЛЬКО если его нет»), а в примере
// каждая из этих строк подписана. До финального ревью ветки фикстура
// называла себя «конфигом той же формы, что боевой», но выбрасывала именно
// эту деталь — и разбор id, не отрезавший комментарий, дожил до финала:
// на СВЕЖЕЙ установке detach отказывал сообщением «интерфейса с id awg3 в
// config.yaml нет» на физически присутствующем интерфейсе, уже записав
// .bak. Фикстура без комментариев — это не «конфиг той же формы».
const sampleYAML = `# Панель слушает ТОЛЬКО адрес внутри туннеля.
listen: "10.11.0.1:8081"

auth:
  user: "admin"
  bcrypt: "$2b$12$FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFA"

interfaces:
  - id: awg3                        # slug для URL и каталога хранилища: [a-z0-9-], уникален
    title: "awg3 (боевой)"          # подпись вкладки в вебе
    interface: awg3                 # имя устройства для awg show/syncconf
    config: /etc/amnezia/amneziawg/awg3.conf
    bin_dir: /opt/awg3/bin
    client:
      endpoint: "203.0.113.10:51772"
      allowed_ips: "0.0.0.0/0"
    storage:
      state: /var/lib/awg3panel/awg3/peers.json
      backups: /var/lib/awg3panel/awg3/backups
      keys: /var/lib/awg3panel/awg3/keys
`

func newIface() config.Interface {
	return config.Interface{
		ID: "awg2", Title: "awg2 (2.0)", Interface: "awg2",
		Config: "/etc/amnezia/amneziawg/awg2.conf",
		BinDir: "/opt/awg2/bin",
		Client: config.Client{Endpoint: "203.0.113.10:3478", AllowedIPs: "0.0.0.0/0"},
		Storage: config.Storage{
			State:   "/var/lib/awg3panel/awg2/peers.json",
			Backups: "/var/lib/awg3panel/awg2/backups",
			Keys:    "/var/lib/awg3panel/awg2/keys",
		},
	}
}

// loadFrom пишет текст во временный файл и грузит его настоящим
// config.Load — единственная проверка, которая что-то значит: результат
// хирургии обязан быть тем, что панель примет при старте, а не тем, что
// «похоже на YAML».
func loadFrom(t *testing.T, text string) *config.Config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("получившийся config.yaml не грузится: %v\n---\n%s", err, text)
	}
	return cfg
}

// TestInsertInterfaceIsLoadable — вставленный блок читается настоящим
// загрузчиком и даёт ровно те поля, что были переданы.
func TestInsertInterfaceIsLoadable(t *testing.T) {
	got, err := iface.InsertInterface(sampleYAML, newIface())
	if err != nil {
		t.Fatal(err)
	}
	cfg := loadFrom(t, got)
	if len(cfg.Interfaces) != 2 {
		t.Fatalf("интерфейсов %d, ожидали 2", len(cfg.Interfaces))
	}
	if !reflect.DeepEqual(cfg.Interfaces[1], newIface()) {
		t.Errorf("вставленный интерфейс прочитался иначе:\n%+v\n%+v", cfg.Interfaces[1], newIface())
	}
}

// TestInsertKeepsEverythingElseByteForByte — всё, кроме дописанного,
// остаётся теми же байтами. Комментарий, кавычки, отступы и хеш пароля
// принадлежат оператору, и хирургия не вправе их переформатировать.
func TestInsertKeepsEverythingElseByteForByte(t *testing.T) {
	got, err := iface.InsertInterface(sampleYAML, newIface())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, sampleYAML) {
		t.Error("исходный текст изменён, а не дописан")
	}
}

// TestRemoveInterfaceIsLoadable — вырезание убирает ровно один блок.
func TestRemoveInterfaceIsLoadable(t *testing.T) {
	two, err := iface.InsertInterface(sampleYAML, newIface())
	if err != nil {
		t.Fatal(err)
	}
	got, err := iface.RemoveInterface(two, "awg2")
	if err != nil {
		t.Fatal(err)
	}
	cfg := loadFrom(t, got)
	if len(cfg.Interfaces) != 1 || cfg.Interfaces[0].ID != "awg3" {
		t.Fatalf("после вырезания осталось: %+v", cfg.Interfaces)
	}
}

// TestInsertRemoveIsIdentity — круговой обход возвращает файл БАЙТ В БАЙТ.
// Проверка не косметическая: панель на боевом хосте будет подключать и
// отвязывать интерфейсы годами, и хирургия, накапливающая по строке за
// круг, однажды разъедется с тем, что оператор считает своим файлом.
// Такое уже случалось в этом репозитории с разделительными пустыми
// строками в awg3.conf — байт за цикл, без верхней границы.
func TestInsertRemoveIsIdentity(t *testing.T) {
	two, err := iface.InsertInterface(sampleYAML, newIface())
	if err != nil {
		t.Fatal(err)
	}
	back, err := iface.RemoveInterface(two, "awg2")
	if err != nil {
		t.Fatal(err)
	}
	if back != sampleYAML {
		t.Errorf("круговой обход изменил файл:\n--- было ---\n%q\n--- стало ---\n%q", sampleYAML, back)
	}
}

// TestRemoveMiddleInterface — вырезается блок, стоящий НЕ последним.
// Отдельный случай, потому что границы блока определяются началом
// следующего, а у последнего следующего нет.
func TestRemoveMiddleInterface(t *testing.T) {
	second := newIface()
	third := newIface()
	third.ID, third.Interface = "awg4", "awg4"
	third.Config = "/etc/amnezia/amneziawg/awg4.conf"
	third.BinDir = "/opt/awg4/bin"
	third.Storage = config.Storage{
		State:   "/var/lib/awg3panel/awg4/peers.json",
		Backups: "/var/lib/awg3panel/awg4/backups",
		Keys:    "/var/lib/awg3panel/awg4/keys",
	}

	text, err := iface.InsertInterface(sampleYAML, second)
	if err != nil {
		t.Fatal(err)
	}
	text, err = iface.InsertInterface(text, third)
	if err != nil {
		t.Fatal(err)
	}
	got, err := iface.RemoveInterface(text, "awg2")
	if err != nil {
		t.Fatal(err)
	}
	cfg := loadFrom(t, got)
	if len(cfg.Interfaces) != 2 {
		t.Fatalf("интерфейсов %d, ожидали 2", len(cfg.Interfaces))
	}
	if cfg.Interfaces[0].ID != "awg3" || cfg.Interfaces[1].ID != "awg4" {
		t.Errorf("вырезан не тот блок: %s, %s", cfg.Interfaces[0].ID, cfg.Interfaces[1].ID)
	}
}

// TestRemoveUnknownIDFails — вырезать нечего, значит отказ, а не тихий
// возврат исходного текста: исполнитель на этом основании решает, что
// делать дальше, и «сделано» вместо «нечего делать» его обманет.
func TestRemoveUnknownIDFails(t *testing.T) {
	if _, err := iface.RemoveInterface(sampleYAML, "нетакого"); err == nil {
		t.Fatal("вырезание несуществующего id прошло, ожидался отказ")
	}
}

// TestInsertDuplicateIDFails — второй интерфейс с тем же id отвергается
// здесь, а не валидатором конфига после записи файла: к тому моменту
// config.yaml уже испорчен, и панель не поднимется.
func TestInsertDuplicateIDFails(t *testing.T) {
	dup := newIface()
	dup.ID = "awg3"
	if _, err := iface.InsertInterface(sampleYAML, dup); err == nil {
		t.Fatal("дубликат id принят, ожидался отказ")
	}
}

// TestRenderCoversEveryConfigField — сторож против молчаливой потери поля.
// Блок рисуется по своей структуре-зеркалу, а не по config.Interface
// напрямую (см. комментарий к renderable): поле, добавленное в
// config.Interface и забытое в зеркале, иначе просто не попало бы в
// config.yaml — панель поднялась бы, а настройка тихо исчезла.
func TestRenderCoversEveryConfigField(t *testing.T) {
	missing := iface.RenderableFieldsMissing()
	if len(missing) != 0 {
		t.Fatalf("поля config.Interface не покрыты рендером блока: %v", missing)
	}
}

// sampleYAMLFourSpaces — config с четырёхпробельным отступом элементов.
// Валидный YAML, но отступ другой. InsertInterface обязана отвергнуть
// дубликат даже при несовпадении отступа, а не молча его пропустить.
const sampleYAMLFourSpaces = `# Панель слушает ТОЛЬКО адрес внутри туннеля.
listen: "10.11.0.1:8081"

auth:
  user: "admin"
  bcrypt: "$2b$12$FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFA"

interfaces:
    - id: awg3
      title: "awg3 (боевой)"
      interface: awg3
      config: /etc/amnezia/amneziawg/awg3.conf
      bin_dir: /opt/awg3/bin
      client:
        endpoint: "203.0.113.10:51772"
        allowed_ips: "0.0.0.0/0"
      storage:
        state: /var/lib/awg3panel/awg3/peers.json
        backups: /var/lib/awg3panel/awg3/backups
        keys: /var/lib/awg3panel/awg3/keys
`

// TestInsertWithFourSpaceIndentRejectsDuplicate — если существующие элементы
// отступлены четырьмя пробелами, InsertInterface обязана заметить ID awg3
// и отвергнуть попытку вставить дубликат. Иначе конфиг испортится.
func TestInsertWithFourSpaceIndentRejectsDuplicate(t *testing.T) {
	dup := newIface()
	dup.ID = "awg3"
	// Явно создаём конфиг с четырёхпробельным отступом, чтобы избежать
	// проблем при копировании строк. Используем strings.Repeat для четкости.
	configFourSpace := "listen: \"10.11.0.1:8081\"\n\ninterfaces:\n" +
		strings.Repeat(" ", 4) + "- id: awg3\n" +
		strings.Repeat(" ", 6) + "title: test\n" +
		strings.Repeat(" ", 6) + "interface: awg3\n" +
		strings.Repeat(" ", 6) + "config: /etc/test.conf\n" +
		strings.Repeat(" ", 6) + "bin_dir: /opt/test\n" +
		strings.Repeat(" ", 6) + "storage:\n" +
		strings.Repeat(" ", 8) + "state: /var/lib/test/peers.json\n" +
		strings.Repeat(" ", 8) + "backups: /var/lib/test/backups\n" +
		strings.Repeat(" ", 8) + "keys: /var/lib/test/keys\n"

	if _, err := iface.InsertInterface(configFourSpace, dup); err == nil {
		t.Fatal("дубликат id в конфиге с четырёхпробельным отступом не был обнаружен, ожидался отказ")
	}
}

// sampleYAMLInterfacesWithSpace — config где ключ "interfaces:" имеет хвостовой пробел.
const sampleYAMLInterfacesWithSpace = `# Панель слушает ТОЛЬКО адрес внутри туннеля.
listen: "10.11.0.1:8081"

auth:
  user: "admin"
  bcrypt: "$2b$12$FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFA"

interfaces:
  - id: awg3
    title: "awg3 (боевой)"
    interface: awg3
    config: /etc/amnezia/amneziawg/awg3.conf
    bin_dir: /opt/awg3/bin
    client:
      endpoint: "203.0.113.10:51772"
      allowed_ips: "0.0.0.0/0"
    storage:
      state: /var/lib/awg3panel/awg3/peers.json
      backups: /var/lib/awg3panel/awg3/backups
      keys: /var/lib/awg3panel/awg3/keys
`

// TestInterfaceWithTrailingSpaceIsDetected — ключ "interfaces: " (с хвостовым
// пробелом) обязан разбираться корректно, а не отвергаться ошибкой
// "нет ключа interfaces:".
func TestInterfaceWithTrailingSpaceIsDetected(t *testing.T) {
	got, err := iface.InsertInterface(sampleYAMLInterfacesWithSpace, newIface())
	if err != nil {
		t.Fatal(err)
	}
	cfg := loadFrom(t, got)
	if len(cfg.Interfaces) != 2 {
		t.Fatalf("интерфейсов %d, ожидали 2", len(cfg.Interfaces))
	}
}

// TestInsertRemoveIsIdentityFourSpace — круговой обход на файле с
// четырёхпробельным отступом обязан вернуть файл БАЙТ В БАЙТ. Если
// распознавание и рендер не согласованы по отступу, получится смешание
// отступов и невалидный YAML.
func TestInsertRemoveIsIdentityFourSpace(t *testing.T) {
	configFourSpace := "listen: \"10.11.0.1:8081\"\n\ninterfaces:\n" +
		strings.Repeat(" ", 4) + "- id: awg3\n" +
		strings.Repeat(" ", 6) + "title: test\n" +
		strings.Repeat(" ", 6) + "interface: awg3\n" +
		strings.Repeat(" ", 6) + "config: /etc/test.conf\n" +
		strings.Repeat(" ", 6) + "bin_dir: /opt/test\n" +
		strings.Repeat(" ", 6) + "storage:\n" +
		strings.Repeat(" ", 8) + "state: /var/lib/test/peers.json\n" +
		strings.Repeat(" ", 8) + "backups: /var/lib/test/backups\n" +
		strings.Repeat(" ", 8) + "keys: /var/lib/test/keys\n"

	// Вставляем элемент с пяти пробелами — должен быть вставлен с тем же
	// отступом, что у существующих (4 пробела), иначе круговой обход сломан.
	toInsert := newIface()
	two, err := iface.InsertInterface(configFourSpace, toInsert)
	if err != nil {
		t.Fatal(err)
	}

	// Вырезаем вставленный элемент.
	back, err := iface.RemoveInterface(two, toInsert.ID)
	if err != nil {
		t.Fatal(err)
	}

	// Проверяем, что вернулись к исходному файлу.
	if back != configFourSpace {
		t.Errorf("круговой обход на четырёхпробельном отступе изменил файл:\n--- было ---\n%q\n--- стало ---\n%q",
			configFourSpace, back)
	}
}

// TestInsertInFourSpaceYAMLIsValid — результат вставки в файл с
// четырёхпробельным отступом обязан быть валидным YAML.
func TestInsertInFourSpaceYAMLIsValid(t *testing.T) {
	configFourSpace := "listen: \"10.11.0.1:8081\"\n\nauth:\n" +
		"  user: \"admin\"\n" +
		"  bcrypt: \"$2b$12$FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFA\"\n\n" +
		"interfaces:\n" +
		strings.Repeat(" ", 4) + "- id: awg3\n" +
		strings.Repeat(" ", 6) + "title: test\n" +
		strings.Repeat(" ", 6) + "interface: awg3\n" +
		strings.Repeat(" ", 6) + "config: /etc/test.conf\n" +
		strings.Repeat(" ", 6) + "bin_dir: /opt/test\n" +
		strings.Repeat(" ", 6) + "client:\n" +
		strings.Repeat(" ", 8) + "endpoint: \"203.0.113.10:51772\"\n" +
		strings.Repeat(" ", 8) + "allowed_ips: \"0.0.0.0/0\"\n" +
		strings.Repeat(" ", 6) + "storage:\n" +
		strings.Repeat(" ", 8) + "state: /var/lib/test/peers.json\n" +
		strings.Repeat(" ", 8) + "backups: /var/lib/test/backups\n" +
		strings.Repeat(" ", 8) + "keys: /var/lib/test/keys\n"

	got, err := iface.InsertInterface(configFourSpace, newIface())
	if err != nil {
		t.Fatal(err)
	}
	cfg := loadFrom(t, got)
	if len(cfg.Interfaces) != 2 {
		t.Fatalf("интерфейсов %d, ожидали 2", len(cfg.Interfaces))
	}
}

// TestInsertRejectsNonUniformIndent — если элементы списка имеют разные
// отступы (первый 2 пробела, второй 4 пробела), InsertInterface обязана
// отказать ошибкой, а не молча писать несогласованный YAML.
func TestInsertRejectsNonUniformIndent(t *testing.T) {
	// Конфиг с неоднородными отступами: первый элемент 2 пробела, второй 4.
	nonUniformConfig := "listen: \"10.11.0.1:8081\"\n\ninterfaces:\n" +
		"  - id: awg3\n" +
		"    title: test\n" +
		"    interface: awg3\n" +
		"    config: /etc/test.conf\n" +
		"    bin_dir: /opt/test\n" +
		"    storage:\n" +
		"      state: /var/lib/test/peers.json\n" +
		"      backups: /var/lib/test/backups\n" +
		"      keys: /var/lib/test/keys\n" +
		strings.Repeat(" ", 4) + "- id: awg2\n" +
		strings.Repeat(" ", 6) + "title: test2\n" +
		strings.Repeat(" ", 6) + "interface: awg2\n" +
		strings.Repeat(" ", 6) + "config: /etc/test2.conf\n" +
		strings.Repeat(" ", 6) + "bin_dir: /opt/test2\n" +
		strings.Repeat(" ", 6) + "storage:\n" +
		strings.Repeat(" ", 8) + "state: /var/lib/test2/peers.json\n" +
		strings.Repeat(" ", 8) + "backups: /var/lib/test2/backups\n" +
		strings.Repeat(" ", 8) + "keys: /var/lib/test2/keys\n"

	toInsert := newIface()
	if _, err := iface.InsertInterface(nonUniformConfig, toInsert); err == nil {
		t.Fatal("вставка в конфиг с неоднородными отступами прошла, ожидался отказ")
	}
}

// commentedYAML — тот же список, но ОБА элемента подписаны хвостовыми
// комментариями. Форма не выдуманная: install.sh кладёт
// deploy/config.example.yaml в /etc/awg3panel/config.yaml дословно, а там
// подписана каждая строка `- id:`.
const commentedYAML = `listen: "10.11.0.1:8081"

auth:
  user: "admin"
  bcrypt: "$2b$12$FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFA"

interfaces:
  - id: awg3            # первый — тот, на адресе которого слушает панель
    title: "awg3"
    interface: awg3
    config: /etc/amnezia/amneziawg/awg3.conf
    bin_dir: /opt/awg3/bin
    client:
      endpoint: "203.0.113.10:51772"
      allowed_ips: "0.0.0.0/0"
    storage:
      state: /var/lib/awg3panel/awg3/peers.json
      backups: /var/lib/awg3panel/awg3/backups
      keys: /var/lib/awg3panel/awg3/keys
  - id: awg2            # второй — тот, который отвязывают
    title: "awg2"
    interface: awg2
    config: /etc/amnezia/amneziawg/awg2.conf
    bin_dir: /opt/awg2/bin
    client:
      endpoint: "203.0.113.10:3478"
      allowed_ips: "0.0.0.0/0"
    storage:
      state: /var/lib/awg3panel/awg2/peers.json
      backups: /var/lib/awg3panel/awg2/backups
      keys: /var/lib/awg3panel/awg2/keys
`

// TestRemoveInterfaceStripsInlineComment — находка CRITICAL финального
// ревью ветки. Разбор id обязан отрезать хвостовой комментарий строки
// `- id: awg2   # ...`, иначе значением станет вся строка целиком.
//
// Цена ошибки не в косметике разбора. `install.sh` кладёт
// `deploy/config.example.yaml` в `/etc/awg3panel/config.yaml` ДОСЛОВНО, а
// там каждая строка `- id:` подписана — то есть на СВЕЖЕЙ установке ни
// один id не читался вовсе. Консоль при этом показывала интерфейс
// (`PlanDetach` работает по РАЗОБРАННОМУ конфигу, а не по тексту), заявку
// принимала, `iface apply` успевал записать `.bak` — и только потом
// отказывал сообщением «интерфейса с id awg2 в config.yaml нет» на
// физически присутствующем элементе. Ровно тот «диагноз, уводящий
// оператора от настоящей причины», от которого предостерегает докстринг
// RemoveInterface.
func TestRemoveInterfaceStripsInlineComment(t *testing.T) {
	got, err := iface.RemoveInterface(commentedYAML, "awg2")
	if err != nil {
		t.Fatalf("вырезание по id с хвостовым комментарием отказало: %v", err)
	}
	cfg := loadFrom(t, got)
	if len(cfg.Interfaces) != 1 || cfg.Interfaces[0].ID != "awg3" {
		t.Fatalf("после вырезания осталось: %+v", cfg.Interfaces)
	}
}

// TestInsertRejectsDuplicateWithInlineComment — вторая половина той же
// находки: защита от молчаливой вставки дубликата тоже читает id из текста.
// Сегодня до неё не доходит (PlanAttach отсекает дубликат по разобранному
// конфигу раньше), но это защита В ГЛУБИНУ, и план Б позовёт
// InsertInterface из мастера создания, где первого рубежа может не
// оказаться.
func TestInsertRejectsDuplicateWithInlineComment(t *testing.T) {
	dup := newIface()
	dup.ID = "awg3"
	if _, err := iface.InsertInterface(commentedYAML, dup); err == nil {
		t.Fatal("дубликат id, подписанного хвостовым комментарием, принят — ожидался отказ")
	}
}

// TestHashInsideQuotesIsNotComment — `#` внутри кавычек комментарием НЕ
// является (YAML: комментарий начинается только с `#`, перед которым пробел
// или начало строки). Обрезание «до первого решётки» испортило бы id вида
// "a#b": вырезание такого элемента отказывало бы, а вставка второго с тем
// же id прошла бы молча.
func TestHashInsideQuotesIsNotComment(t *testing.T) {
	const text = `interfaces:
  - id: "a#b"
    interface: dev
`
	if _, err := iface.RemoveInterface(text, "a#b"); err != nil {
		t.Errorf("id \"a#b\" не распознан целиком: %v", err)
	}
	if _, err := iface.RemoveInterface(text, "a"); err == nil {
		t.Error("id обрезан по решётке внутри кавычек — вырезан не тот элемент")
	}
}

// TestHashWithoutSpaceIsPartOfValue — обратная сторона: в YAML `#` без
// пробела перед ним принадлежит скаляру, а не комментарию. `id: a#b` — это
// id "a#b" целиком, и разбор обязан читать его так же, как его прочитает
// сам yaml.v3 при загрузке конфига: иначе текстовая хирургия и загрузчик
// разойдутся в том, какой интерфейс где.
func TestHashWithoutSpaceIsPartOfValue(t *testing.T) {
	const text = `interfaces:
  - id: a#b
    interface: dev
`
	if _, err := iface.RemoveInterface(text, "a#b"); err != nil {
		t.Errorf("id a#b (решётка без пробела — часть значения) не распознан: %v", err)
	}
}

// TestZeroIndentListIsNotMistakenForEmpty — элементы списка вправе стоять
// на НУЛЕВОМ отступе: это валидный YAML, и yaml.v3 такой файл читает. До
// финального ревью и itemStarts, и getListIndentAndCheck возвращали ""
// одновременно и как «отступ нулевой», и как «элементов нет» — два разных
// факта под одним значением. Следствием была бы вставка дубликата: список
// с одним элементом выглядел бы пустым, проверка на дубликат не нашла бы
// ничего, и в config.yaml легли бы два интерфейса с одним id.
func TestZeroIndentListIsNotMistakenForEmpty(t *testing.T) {
	const text = `listen: "10.11.0.1:8081"

auth:
  user: "admin"
  bcrypt: "$2b$12$FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFA"

interfaces:
- id: awg3
  title: "awg3"
  interface: awg3
  config: /etc/amnezia/amneziawg/awg3.conf
  bin_dir: /opt/awg3/bin
  client:
    endpoint: "203.0.113.10:51772"
    allowed_ips: "0.0.0.0/0"
  storage:
    state: /var/lib/awg3panel/awg3/peers.json
    backups: /var/lib/awg3panel/awg3/backups
    keys: /var/lib/awg3panel/awg3/keys
`
	dup := newIface()
	dup.ID = "awg3"
	if _, err := iface.InsertInterface(text, dup); err == nil {
		t.Error("дубликат id в списке с нулевым отступом принят — список сочли пустым")
	}

	two, err := iface.InsertInterface(text, newIface())
	if err != nil {
		t.Fatal(err)
	}
	cfg := loadFrom(t, two)
	if len(cfg.Interfaces) != 2 {
		t.Fatalf("интерфейсов %d, ожидали 2:\n%s", len(cfg.Interfaces), two)
	}
	back, err := iface.RemoveInterface(two, "awg2")
	if err != nil {
		t.Fatal(err)
	}
	if back != text {
		t.Errorf("круговой обход на нулевом отступе изменил файл:\n--- было ---\n%q\n--- стало ---\n%q", text, back)
	}
}
