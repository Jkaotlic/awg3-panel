//go:build !readonly

package main

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/iface"
	"github.com/Jkaotlic/awg3-panel/internal/issuer"
)

// testConfig строит конфиг с ОДНИМ интерфейсом внутри t.TempDir() — тем же
// приёмом с прямым слэшем, что и tmpInterfaceStorage (cli_list_test.go):
// iface.RequestsDir вычисляет каталог заявок через path.Dir (путь на
// целевом Linux-хосте), а filepath.Join на Windows дал бы обратный слэш, в
// котором path.Dir не находит разделителя. Storage.State лежит на уровень
// ГЛУБЖЕ временного каталога (.../awg3/peers.json, а не .../peers.json),
// иначе RequestsDir вывела бы каталог заявок соседом самого t.TempDir(), а
// не внутри него, и заявки утекали бы за пределы песочницы теста.
func testConfig(t *testing.T) *config.Config {
	t.Helper()
	base := filepath.ToSlash(t.TempDir())
	cfg := config.Default()
	cfg.Interfaces[0].Storage = config.Storage{
		State:   base + "/awg3/peers.json",
		Backups: base + "/awg3/backups",
		Keys:    base + "/awg3/keys",
	}
	cfg.Path = base + "/config.yaml"
	return cfg
}

// seedAttachRequest — заявка attach на подключение "awg2", той же формы,
// что реальный PlanAttach собрал бы (внутренние тесты пакета iface, см.
// request_test.go/plan_attach_test.go), но записанная напрямую: ifaceCmd
// работает с уже сохранённой заявкой, а не с её сборкой.
func seedAttachRequest(t *testing.T, cfg *config.Config) {
	t.Helper()
	dir, err := iface.RequestsDir(cfg)
	if err != nil {
		t.Fatal(err)
	}
	req := iface.Request{
		Version:   iface.RequestVersion,
		Action:    iface.ActionAttach,
		CreatedAt: "2026-08-27T10:00:00Z",
		CreatedBy: "admin",
		ID:        "awg2",
		Attach: &iface.AttachPayload{
			ConfPath: "/etc/amnezia/amneziawg/awg2.conf",
			Device:   "awg2",
			Block: config.Interface{
				ID: "awg2", Title: "awg2 (2.0)", Interface: "awg2",
				Config: "/etc/amnezia/amneziawg/awg2.conf",
				BinDir: "/opt/awg2/bin",
				Client: config.Client{Endpoint: "203.0.113.10:3478", AllowedIPs: "0.0.0.0/0"},
				Storage: config.Storage{
					State:   "/var/lib/awg3panel/awg2/peers.json",
					Backups: "/var/lib/awg3panel/awg2/backups",
					Keys:    "/var/lib/awg3panel/awg2/keys",
				},
			},
		},
	}
	if _, err := iface.Save(dir, req); err != nil {
		t.Fatal(err)
	}
}

// seedRequest — имя из брифа задачи 8. Обёртка над seedAttachRequest: в
// текущем наборе тестов нужна только заявка attach, но имя без "Attach"
// оставлено на случай, если следующая задача добавит detach-вариант.
func seedRequest(t *testing.T, cfg *config.Config) { t.Helper(); seedAttachRequest(t, cfg) }

// requestCount — сколько заявок ждёт применения. Через iface.List, а не
// подсчёт файлов в каталоге руками: список уже умеет пропускать чужие файлы
// (см. TestListIgnoresForeignFiles в internal/iface).
func requestCount(t *testing.T, cfg *config.Config) int {
	t.Helper()
	dir, err := iface.RequestsDir(cfg)
	if err != nil {
		t.Fatal(err)
	}
	reqs, err := iface.List(dir)
	if err != nil {
		t.Fatal(err)
	}
	return len(reqs)
}

// TestIfaceApplyRefusesNonInteractive — при неинтерактивном запуске
// исполнитель отказывается работать, а не считает пустой ввод согласием
// (спека 2026-08-25, раздел 8). Цена ошибки — изменение хоста без человека.
// Заявок здесь нарочно НЕТ: отказ обязан случиться до того, как apply вообще
// посмотрит, что применять, иначе пустой каталог заявок маскировал бы
// пропущенную проверку терминала.
func TestIfaceApplyRefusesNonInteractive(t *testing.T) {
	var out bytes.Buffer
	err := ifaceCmd([]string{"apply"}, testConfig(t), &out, strings.NewReader(""))
	if err == nil {
		t.Fatal("применение без подтверждения прошло")
	}
}

// TestIfaceApplyDryRunChangesNothing — --dry-run печатает план и выходит.
func TestIfaceApplyDryRunChangesNothing(t *testing.T) {
	cfg := testConfig(t)
	seedRequest(t, cfg)
	var out bytes.Buffer
	if err := ifaceCmd([]string{"apply", "--dry-run"}, cfg, &out, strings.NewReader("")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "attach") {
		t.Errorf("план не напечатан: %q", out.String())
	}
	if requestCount(t, cfg) != 1 {
		t.Error("--dry-run удалил заявку")
	}
}

// TestIfaceRequestsListsPending — оператор должен видеть, что ждёт
// применения, не заглядывая в каталог руками.
func TestIfaceRequestsListsPending(t *testing.T) {
	cfg := testConfig(t)
	seedRequest(t, cfg)
	var out bytes.Buffer
	if err := ifaceCmd([]string{"requests"}, cfg, &out, strings.NewReader("")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "awg2") {
		t.Errorf("заявка не перечислена: %q", out.String())
	}
}

// TestIfaceUnknownSubcommand — опечатка обязана быть ошибкой ввода
// (код возврата 2), а не «внутренней ошибкой».
func TestIfaceUnknownSubcommand(t *testing.T) {
	err := ifaceCmd([]string{"аплай"}, testConfig(t), io.Discard, strings.NewReader(""))
	if !errors.Is(err, issuer.ErrInvalidInput) {
		t.Errorf("ошибка %v не классифицирована как ошибка ввода", err)
	}
}

// Ниже — четыре теста находки ревью task-8 (Important): ветка
// dry=false && isTerminal(in)==true была структурно недостижима из тестов,
// потому что isTerminal проверяет *os.File, а тесты подают
// bytes.Buffer/strings.Reader. applyRequestsWith принимает isTerm и apply
// подменяемыми параметрами именно для этого — applyRequests (продакшен-путь,
// единственный вызываемый из ifaceCmd) всегда передаёт туда настоящие
// isTerminal и iface.Apply, так что подмена ничего не ослабляет в бою.

// TestIfaceApplyConfirmedWordInvokesApply — верное слово подтверждения
// («attach» для заявки attach) ведёт к вызову iface.Apply ровно один раз, с
// той же заявкой. iface.Apply подменяется фиктивной функцией: тесту нельзя
// дёргать systemctl и переписывать настоящий config.yaml.
func TestIfaceApplyConfirmedWordInvokesApply(t *testing.T) {
	cfg := testConfig(t)
	seedRequest(t, cfg)
	dir, err := iface.RequestsDir(cfg)
	if err != nil {
		t.Fatal(err)
	}

	var applyCalls int
	fakeApply := func(r iface.Request, env iface.Env, configPath string) error {
		applyCalls++
		if r.ID != "awg2" {
			t.Errorf("apply вызван не для той заявки: %q", r.ID)
		}
		return nil
	}

	var out bytes.Buffer
	err = applyRequestsWith(dir, cfg, &out, strings.NewReader("attach\n"), false,
		func(io.Reader) bool { return true }, fakeApply)
	if err != nil {
		t.Fatal(err)
	}
	if applyCalls != 1 {
		t.Errorf("iface.Apply вызван %d раз, ожидался 1", applyCalls)
	}
	if !strings.Contains(out.String(), "применено") {
		t.Errorf("вывод не сообщает о применении: %q", out.String())
	}
}

// TestIfaceApplyWrongWordSkipsApply — неверное слово подтверждения
// пропускает заявку: iface.Apply не вызывается вовсе, заявка остаётся в
// каталоге, вывод честно говорит «пропущено», а не «применено».
func TestIfaceApplyWrongWordSkipsApply(t *testing.T) {
	cfg := testConfig(t)
	seedRequest(t, cfg)
	dir, err := iface.RequestsDir(cfg)
	if err != nil {
		t.Fatal(err)
	}

	var applyCalls int
	fakeApply := func(iface.Request, iface.Env, string) error {
		applyCalls++
		return nil
	}

	var out bytes.Buffer
	err = applyRequestsWith(dir, cfg, &out, strings.NewReader("нет\n"), false,
		func(io.Reader) bool { return true }, fakeApply)
	if err != nil {
		t.Fatal(err)
	}
	if applyCalls != 0 {
		t.Errorf("iface.Apply вызван при неверном слове подтверждения")
	}
	if !strings.Contains(out.String(), "пропущено") {
		t.Errorf("вывод не сообщает о пропуске: %q", out.String())
	}
	if requestCount(t, cfg) != 1 {
		t.Error("заявка удалена из каталога при пропуске — этого не должно быть")
	}
}

// TestIfaceApplyRemovesRequestAfterApply — после успешного применения
// (верное слово, iface.Apply вернул nil) заявка исчезает из каталога через
// iface.Cancel: применённая заявка, оставшаяся в каталоге, при следующем
// запуске "iface apply" была бы предложена оператору повторно.
func TestIfaceApplyRemovesRequestAfterApply(t *testing.T) {
	cfg := testConfig(t)
	seedRequest(t, cfg)
	dir, err := iface.RequestsDir(cfg)
	if err != nil {
		t.Fatal(err)
	}

	fakeApply := func(iface.Request, iface.Env, string) error { return nil }

	var out bytes.Buffer
	err = applyRequestsWith(dir, cfg, &out, strings.NewReader("attach\n"), false,
		func(io.Reader) bool { return true }, fakeApply)
	if err != nil {
		t.Fatal(err)
	}
	if requestCount(t, cfg) != 0 {
		t.Error("заявка не удалена из каталога после успешного применения")
	}
}

// TestIfaceApplyUnknownArgumentIsInputError — "iface apply --dryrun"
// (опечатка вместо --dry-run) обязана отклоняться явной ошибкой ввода, а не
// молча уходить в режим реального применения. До правки `dry := len(args) >
// 1 && args[1] == "--dry-run"` на нераспознанном втором аргументе молча
// оставляла dry=false, и оператор, уверенный, что запустил сухой прогон,
// получал бы запрос подтверждения на настоящее применение.
func TestIfaceApplyUnknownArgumentIsInputError(t *testing.T) {
	err := ifaceCmd([]string{"apply", "--dryrun"}, testConfig(t), io.Discard, strings.NewReader(""))
	if !errors.Is(err, issuer.ErrInvalidInput) {
		t.Errorf("ошибка %v не классифицирована как ошибка ввода", err)
	}
}

// TestIfaceEnvUsesSharedRoots — парный тест к TestManageEnvUsesSharedRoots
// (internal/web/manage_internal_test.go), находка IMPORTANT 5 финального
// ревью ветки. Исполнитель обязан смотреть на ТЕ ЖЕ корни, что и консоль,
// иначе пере-проверка предусловий шага 1 раздела 6А.5 спеки 2026-08-25
// теряет смысл: она проверяет другой хост, чем тот, по которому собиралась
// заявка. До правки корни были литералами здесь и константами в web, а
// StateRoot вычислялся выражением, написанным в трёх местах.
func TestIfaceEnvUsesSharedRoots(t *testing.T) {
	cfg := testConfig(t)
	env := ifaceEnv(cfg)
	if env.ConfDir != iface.DefaultConfDir {
		t.Errorf("ConfDir = %q, ожидали iface.DefaultConfDir (%q)", env.ConfDir, iface.DefaultConfDir)
	}
	if env.BinRoot != iface.DefaultBinRoot {
		t.Errorf("BinRoot = %q, ожидали iface.DefaultBinRoot (%q)", env.BinRoot, iface.DefaultBinRoot)
	}
	if want := iface.StateRoot(cfg); env.StateRoot != want {
		t.Errorf("StateRoot = %q, ожидали iface.StateRoot(cfg) (%q)", env.StateRoot, want)
	}
	if env.Cfg != cfg {
		t.Error("окружение собрано не по переданному конфигу")
	}
}

// TestIfaceEnvOnEmptyInterfacesDoesNotPanic — незащищённый
// cfg.Interfaces[0] в сборке окружения был спасён только тем, что
// iface.RequestsDir отказывает раньше по тому же поводу. Порядок вызовов —
// не то, на чём должна держаться защита от паники: он меняется правкой,
// которая о ней не знает.
func TestIfaceEnvOnEmptyInterfacesDoesNotPanic(t *testing.T) {
	if got := ifaceEnv(&config.Config{}).StateRoot; got != "" {
		t.Errorf("StateRoot = %q, ожидали пусто", got)
	}
}
