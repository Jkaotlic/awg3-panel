//go:build !readonly

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/iface"
	"github.com/Jkaotlic/awg3-panel/internal/runtime"
)

// ifaceCmd — исполнитель заявок (спека 2026-08-25, раздел 10).
//
// Живой демон здесь НЕ помеха, в отличие от add/rm: refuseIfDaemonRunning
// защищает от потерянной записи, когда демон и CLI пишут один файл, а эта
// команда правит config.yaml, которого демон не пишет вовсе — песочница
// юнита ему этого не позволяет (ReadWritePaths несёт только
// /etc/amnezia/amneziawg и /var/lib/awg3panel). Второго писателя у файла нет.
func ifaceCmd(args []string, cfg *config.Config, out io.Writer, in io.Reader) error {
	if len(args) == 0 {
		return cliInputError{"использование: awg3panel iface requests|apply|cancel <имя>"}
	}
	dir, err := iface.RequestsDir(cfg)
	if err != nil {
		return err
	}
	switch args[0] {
	case "requests":
		return printRequests(dir, out)
	case "cancel":
		if len(args) < 2 {
			return cliInputError{"iface cancel: не указано имя заявки"}
		}
		return iface.Cancel(dir, args[1])
	case "apply":
		dry, err := parseApplyArgs(args[1:])
		if err != nil {
			return err
		}
		return applyRequests(dir, cfg, out, in, dry)
	default:
		return cliInputError{fmt.Sprintf("iface: неизвестная подкоманда %q", args[0])}
	}
}

// describe печатает заявку человекочитаемо. Печатается ровно то, что
// изменит хост, — оператор видит одно и то же дважды: в консоли перед
// записью заявки и здесь перед исполнением (спека 2026-08-25, раздел 3.3).
func describe(w io.Writer, r iface.Request) {
	fmt.Fprintf(w, "\n=== %s: %s (создана %s, %q) ===\n", r.Action, r.ID, r.CreatedAt, r.Name)
	switch r.Action {
	case iface.ActionAttach:
		fmt.Fprintf(w, "  устройство: %q\n  конфиг:     %q\n  bin_dir:    %q\n  endpoint:   %q\n"+
			"  состояние:  %q\n  ФАЙЛ .conf НЕ ИЗМЕНЯЕТСЯ, он только читается\n",
			r.Attach.Device, r.Attach.ConfPath, r.Attach.Block.BinDir,
			r.Attach.Block.Client.Endpoint, path.Dir(r.Attach.Block.Storage.State))
	case iface.ActionDetach:
		// Peers посчитан по .conf, собранному в заявку ЗАРАНЕЕ (спека
		// 2026-08-25, раздел 6А.1: detach не обращается к устройству вовсе), а
		// не по живому серверу, по которому строит список сама панель — числа
		// могут разойтись, если пир добавлен или снесён вручную между сборкой
		// заявки и её применением. Источник назван прямо в строке: без этого
		// оператор сверил бы число со списком в панели, не сошлось бы, и было
		// бы неясно, какому верить.
		fmt.Fprintf(w, "  устройство: %q\n  конфиг:     %q\n  состояние:  %q (ОСТАЁТСЯ на диске)\n"+
			"  пиров:      %d (по .conf на момент сборки заявки, не по живому серверу) —\n"+
			"              они продолжат работать, панель просто перестанет их видеть\n",
			r.Detach.Device, r.Detach.ConfPath, r.Detach.StateDir, r.Detach.Peers)
	}
}

// parseApplyArgs разбирает аргументы после "apply". Единственный
// поддерживаемый — "--dry-run"; всё остальное отклоняется явной ошибкой
// ввода. До этой правки код читал `len(args) > 1 && args[1] == "--dry-run"`
// молча: нераспознанный второй аргумент (например, опечатка "--dryrun")
// оставлял dry=false, и команда уходила в режим реального применения, пока
// оператор был уверен, что запустил сухой прогон (находка ревью task-8,
// «мелочь того же места»). Мгновенной мутации это не давало — подтверждение
// всё равно спросили бы, — но вводило оператора в заблуждение насчёт того,
// что он только что подтвердил.
func parseApplyArgs(args []string) (dry bool, err error) {
	switch len(args) {
	case 0:
		return false, nil
	case 1:
		if args[0] == "--dry-run" {
			return true, nil
		}
		return false, cliInputError{fmt.Sprintf(
			"iface apply: неизвестный аргумент %q, ожидался --dry-run", args[0])}
	default:
		return false, cliInputError{fmt.Sprintf(
			"iface apply: лишние аргументы: %v", args[1:])}
	}
}

func printRequests(dir string, out io.Writer) error {
	reqs, err := iface.List(dir)
	if err != nil {
		return err
	}
	if len(reqs) == 0 {
		fmt.Fprintln(out, "неприменённых заявок нет")
		return nil
	}
	for _, r := range reqs {
		describe(out, r)
	}
	fmt.Fprintf(out, "\nвсего: %d. Применить: awg3panel iface apply\n", len(reqs))
	return nil
}

// isTerminal — проверка через режим файла, а не через golang.org/x/term:
// вендорить библиотеку ради одного вызова дороже, чем две строки, и в
// vendor/ её сейчас нет.
func isTerminal(in io.Reader) bool {
	f, ok := in.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// ifaceEnv собирает окружение исполнителя. Ни один путь здесь не написан
// литералом: корни раскладки и корень состояния берутся из internal/iface
// (DefaultConfDir/DefaultBinRoot/StateRoot) — ровно те же значения, по
// которым консоль собирала заявку (internal/web, manageEnv). Весь смысл
// пере-проверки предусловий здесь (шаг 1 раздела 6А.5 спеки 2026-08-25) в
// том, что исполнитель смотрит на ТО ЖЕ, на что смотрела консоль; пока
// пути были написаны в двух местах, это держалось на совпадении строк, и
// ни один тест этого не сверял (находка IMPORTANT 5 финального ревью).
//
// Заодно уходит незащищённый cfg.Interfaces[0]: iface.StateRoot на пустом
// списке возвращает "", а не паникует. Прежде от паники спасал лишь
// порядок — iface.RequestsDir отказывала раньше по тому же поводу, — а
// порядок вызовов меняется правкой, которая о такой зависимости не знает.
func ifaceEnv(cfg *config.Config) iface.Env {
	return iface.Env{
		Cfg: cfg, ConfDir: iface.DefaultConfDir,
		StateRoot: iface.StateRoot(cfg),
		BinRoot:   iface.DefaultBinRoot, H: iface.NewOSHost(),
		R: func(binDir string) runtime.Runner { return runtime.NewExec(binDir) },
	}
}

// applyRequests выполняет заявки по одной, каждую — с подтверждением.
//
// Отказ при неинтерактивном запуске (спека 2026-08-25, раздел 8) стоит
// ПЕРЕД чтением каталога заявок, а не только перед циклом их применения:
// цена ошибки — изменение хоста без человека, и она не зависит от того,
// сколько заявок сейчас лежит в каталоге — «пустой ввод как согласие»
// недопустим даже тогда, когда заявок нет вовсе (оператор, доверяющий
// коду возврата "0" из неинтерактивного запуска, не должен получать успех
// там, где решение принять было некому).
func applyRequests(dir string, cfg *config.Config, out io.Writer, in io.Reader, dry bool) error {
	if dry || !isTerminal(in) {
		return applyRequestsWith(dir, cfg, out, in, dry, isTerminal, iface.Apply)
	}
	if os.Geteuid() != 0 {
		return cliInputError{"iface apply: запустите команду от root"}
	}
	configPath, err := filepath.Abs(cfg.Path)
	if err != nil {
		return err
	}
	lock, err := iface.LockApply(configPath)
	if err != nil {
		return err
	}
	defer lock.Close()
	recovered, err := iface.RecoverApply(configPath, iface.NewOSHost())
	if err != nil {
		return fmt.Errorf("восстановление iface apply: %w", err)
	}
	if recovered {
		fmt.Fprintln(out, "  восстановление предыдущего iface apply завершено")
	}

	current, err := config.Load(configPath)
	if err != nil {
		return err
	}
	dir, err = iface.RequestsDir(current)
	if err != nil {
		return err
	}
	err = applyRequestsWith(dir, current, out, in, false, isTerminal, func(r iface.Request, _ iface.Env, configPath string) error {
		latest, err := config.Load(configPath)
		if err != nil {
			return err
		}
		return iface.ApplyQueued(r, ifaceEnv(latest), configPath, dir)
	})
	if err != nil {
		return err
	}
	_, err = iface.RecoverApply(configPath, iface.NewOSHost())
	return err
}

// applyRequestsWith — тело applyRequests с подменяемыми проверкой терминала
// (isTerm) и самим применением заявки (apply). Подмена нужна ТОЛЬКО тестам:
// isTerminal проверяет `in.(*os.File)` и режим устройства через os.Stat, а
// тесты подают bytes.Buffer/strings.Reader — тип-проверка не проходит
// никогда, и без этого выделения ветка confirm/apply/cancel была бы
// структурно недостижима из тестов вообще (находка ревью task-8, Important:
// именно ради неё существует эта команда, а покрытой она не была).
// iface.Apply не выполняется в тестах по-настоящему: реальная реализация
// дёргает systemctl и переписывает config.yaml, а тесту нельзя ни того, ни
// другого — только фиктивная функция, подтверждающая факт и аргументы
// вызова.
func applyRequestsWith(dir string, cfg *config.Config, out io.Writer, in io.Reader, dry bool,
	isTerm func(io.Reader) bool, apply func(iface.Request, iface.Env, string) error) error {
	if !dry && !isTerm(in) {
		return cliInputError{"iface apply: ввод не терминал — подтверждение получить не у кого. " +
			"Запустите команду вручную по SSH либо используйте --dry-run"}
	}

	reqs, err := iface.List(dir)
	if err != nil {
		return err
	}
	if len(reqs) == 0 {
		fmt.Fprintln(out, "неприменённых заявок нет")
		return nil
	}

	env := ifaceEnv(cfg)

	reader := bufio.NewReader(in)
	for _, r := range reqs {
		describe(out, r)
		if dry {
			fmt.Fprintln(out, "  --dry-run: не применяется")
			continue
		}
		fmt.Fprintf(out, "  для подтверждения введите %q (пусто — пропустить): ", r.Action)
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			return fmt.Errorf("чтение подтверждения: %w", err)
		}
		if strings.TrimSpace(line) != string(r.Action) {
			fmt.Fprintln(out, "  пропущено")
			continue
		}
		if err := iface.ApplyConfirmed(dir, r, func(current iface.Request) error {
			return apply(current, env, cfg.Path)
		}); err != nil {
			return fmt.Errorf("заявка %q: %w", r.Name, err)
		}
		fmt.Fprintln(out, "  применено")
	}
	return nil
}
