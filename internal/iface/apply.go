package iface

import (
	"fmt"
	"path"
	"strings"

	"github.com/Jkaotlic/awg3-panel/internal/config"
)

// PanelUnit — имя юнита панели. Константа, а не литерал в трёх местах:
// перезапуск входит и в прямой путь, и в откат, и в постусловие.
const PanelUnit = "awg3panel"

// attachDiff перечисляет поля, которыми заявка (want) разошлась с планом,
// пересчитанным по ТЕКУЩЕМУ состоянию хоста (got). Пустой срез — заявка
// по-прежнему описывает то, что произойдёт.
//
// Список полей явный, а не reflect.DeepEqual, ради текста отказа: оператор
// должен прочитать, ЧТО именно изменилось и на что (спека 2026-08-25,
// раздел 5.7), а «структуры не равны» отправило бы его сравнивать JSON
// заявки с конфигом руками.
//
// Джиттера (Jc/Jmin/Jmax) в списке нет намеренно: он СЛУЧАЕН по построению
// (issuer.GenerateJitter в PlanAttach), пересчёт даёт другую тройку всегда,
// и сравнение отвергало бы каждую заявку без исключения. Расхождением это
// не является и по существу: джиттер — чисто клиентский параметр, сервер о
// нём не знает, применяется РОВНО тот, что показан в заявке, и «применённое
// совпало с показанным» для него выполняется по построению.
func attachDiff(want, got AttachPayload) []string {
	fields := []struct{ name, want, got string }{
		{"conf_path", want.ConfPath, got.ConfPath},
		{"устройство", want.Device, got.Device},
		{"id", want.Block.ID, got.Block.ID},
		{"title", want.Block.Title, got.Block.Title},
		{"interface", want.Block.Interface, got.Block.Interface},
		{"config", want.Block.Config, got.Block.Config},
		{"bin_dir", want.Block.BinDir, got.Block.BinDir},
		{"interface_edit", fmt.Sprint(want.Block.InterfaceEdit), fmt.Sprint(got.Block.InterfaceEdit)},
		{"client.endpoint", want.Block.Client.Endpoint, got.Block.Client.Endpoint},
		{"client.allowed_ips", want.Block.Client.AllowedIPs, got.Block.Client.AllowedIPs},
		{"client.persistent_keepalive", want.Block.Client.PersistentKeepalive, got.Block.Client.PersistentKeepalive},
		{"client.dns", want.Block.Client.DNS, got.Block.Client.DNS},
		{"storage.state", want.Block.Storage.State, got.Block.Storage.State},
		{"storage.backups", want.Block.Storage.Backups, got.Block.Storage.Backups},
		{"storage.keys", want.Block.Storage.Keys, got.Block.Storage.Keys},
		{"storage.client_configs", want.Block.Storage.ClientConfigs, got.Block.Storage.ClientConfigs},
	}
	var out []string
	for _, f := range fields {
		if f.want != f.got {
			out = append(out, fmt.Sprintf("%s: в заявке %q, сейчас %q", f.name, f.want, f.got))
		}
	}
	return out
}

// Apply выполняет заявку: все шесть шагов раздела 6А.5 спеки 2026-08-25—
// предусловия заново, бэкап, хирургия config.yaml, каталог состояния
// (attach), безусловный restart, постусловие, — и откат в обратном порядке
// при отказе любого из них после хирургии.
//
// Предусловия проверяются ЗАНОВО, а не берутся из заявки на веру: между
// сборкой заявки в консоли и её применением по SSH проходит произвольное
// время, за которое оператор мог поменять хост руками.
//
// Постусловие (шаг 6) — не формальность: systemctl restart возвращает 0 в
// момент, когда процесс СТАРТОВАЛ, а не когда демон доказанно жив; он может
// упасть в цикл рестартов на невалидном конфиге секундой позже, и без
// постусловия Apply рапортовал бы успех оператору, который в этот момент
// уже без консоли (ревью задачи 7, находка 2; незыблемое правило 3
// CLAUDE.md — мутация обязана заканчиваться проверкой постусловия, а не
// только применением). Провал постусловия ведёт к тому же restore, что и
// провал любого шага раньше.
func Apply(r Request, env Env, configPath string) error {
	switch r.Action {
	case ActionAttach:
		fresh, err := PlanAttach(AttachInput{
			ID: r.Attach.Block.ID, Title: r.Attach.Block.Title,
			// path, а не path/filepath: ConfPath — путь на целевом Linux-хосте
			// (панель разрабатывается на Windows), та же ловушка, что уже
			// описана у PlanAttach и config.Interface.StateDir. filepath.Base
			// дал бы на Windows-сборке иной результат, чем path.Base на
			// боевом хосте, и молча разошёлся бы с исходным ConfName.
			ConfName: path.Base(r.Attach.ConfPath),
		}, env)
		if err != nil {
			return fmt.Errorf("предусловия изменились с момента сборки заявки: %w", err)
		}
		// Пересчитанный план СРАВНИВАЕТСЯ с заявкой, а не выбрасывается
		// (находка IMPORTANT 4 финального ревью ветки: раньше здесь стояло
		// `if _, err := PlanAttach(...)`). Отказы раздела 7 спеки
		// 2026-08-25 не покрывают ВЫВЕДЕННЫХ значений: поменяй оператор
		// ListenPort в .conf или client.endpoint первого интерфейса между
		// сборкой заявки и её применением — все отказы пройдут заново, а в
		// config.yaml ляжет устаревший endpoint из заявки. Клиенты,
		// выпущенные с такого интерфейса, пойдут не на тот порт, и ни одна
		// проверка постусловия этого не увидит: она смотрит на присутствие
		// id и живость демона, а не на смысл записанного.
		//
		// Раздел 5.7 спеки требует ровно этого — «Расхождение — отказ с
		// объяснением, что именно изменилось с момента сборки заявки», —
		// а раздел 3.2: «применённое обязано совпасть с показанным».
		if diff := attachDiff(*r.Attach, fresh); len(diff) > 0 {
			return fmt.Errorf(
				"хост изменился с момента сборки заявки, применённое не совпало бы с показанным: %s; "+
					"снимите заявку (awg3panel iface cancel %s) и соберите её в консоли заново",
				strings.Join(diff, "; "), r.Name)
		}
	case ActionDetach:
		if _, err := PlanDetach(r.ID, env); err != nil {
			return fmt.Errorf("предусловия изменились с момента сборки заявки: %w", err)
		}
	}

	before, err := env.H.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("чтение %s: %w", configPath, err)
	}

	// Копия ДО первой правки. Собранная после бесполезна ровно тогда, когда
	// нужна, — если правка сорвалась на середине.
	backup := configPath + ".bak-" + stamp(r.CreatedAt)
	if err := env.H.WriteFileAtomic(backup, before, 0o600); err != nil {
		return fmt.Errorf("резервная копия %s: %w", backup, err)
	}

	var after string
	switch r.Action {
	case ActionAttach:
		after, err = InsertInterface(string(before), r.Attach.Block)
	case ActionDetach:
		after, err = RemoveInterface(string(before), r.ID)
	}
	if err != nil {
		// config.yaml на диске ещё несёт "before" — перезапись начинается
		// строчкой ниже. Откат не нужен: нечего откатывать.
		return err
	}

	// restore возвращает config.yaml как было и поднимает панель. Вызывается
	// на КАЖДОМ пути отказа ниже: оператор не должен остаться без консоли
	// из-за неудавшейся заявки (спека 2026-08-25, раздел 10).
	restore := func(cause error) error {
		if err := env.H.WriteFileAtomic(configPath, before, 0o600); err != nil {
			return fmt.Errorf("%w; ОТКАТ НЕ УДАЛСЯ, config.yaml остался изменённым, копия: %s (%v)", cause, backup, err)
		}
		if err := env.H.Systemctl("restart", PanelUnit); err != nil {
			return fmt.Errorf("%w; конфиг откачен, но панель не поднялась: %v", cause, err)
		}
		return cause
	}

	// restoreConfigOnly — то же, что restore, но БЕЗ перезапуска панели.
	// Используется на всех путях отказа ДО первого systemctl restart: панель
	// там ещё не потревожена (жива на СТАРОМ конфиге), и её рестарт был бы
	// лишним риском, а не восстановлением — неудачный рестарт ЗДОРОВОГО
	// демона оставил бы оператора без консоли ровно там, где бездействие не
	// оставило бы. Цена ошибки несимметрична, поэтому выбор между «ничего не
	// делать» и «дёрнуть работающий демон» решается в пользу первого.
	restoreConfigOnly := func(cause error) error {
		if err := env.H.WriteFileAtomic(configPath, before, 0o600); err != nil {
			return fmt.Errorf("%w; ОТКАТ НЕ УДАЛСЯ, config.yaml остался изменённым, копия: %s (%v)", cause, backup, err)
		}
		return cause
	}

	if err := env.H.WriteFileAtomic(configPath, []byte(after), 0o600); err != nil {
		return fmt.Errorf("запись %s: %w", configPath, err)
	}

	// Проверка ДО того, как тронута работающая панель (ревью задачи 7,
	// круг 2): systemctl restart для Type=simple рапортует "active", едва
	// процесс форкнулся, а демон, падающий на невалидном конфиге секундой
	// позже, к моменту постусловия ПОСЛЕ restart (ниже) ещё жив — это
	// гонка, а не гарантия. Записанный config.yaml обязан ЗАГРУЖАТЬСЯ
	// настоящим разбором и валидацией config.Parse (то же, что делает
	// config.Load, минус чтение файла — см. её докстринг) РАНЬШЕ, чем
	// панель вообще тронута. blockPresent ниже по функции смотрит только
	// на ТЕКСТ и не поймал бы, например, испорченный r.Attach.Block с
	// пустым client.allowed_ips: текстуально блок на месте, а
	// config.Validate его бы отверг.
	written, err := env.H.ReadFile(configPath)
	if err != nil {
		return restoreConfigOnly(fmt.Errorf("перечитывание записанного config.yaml: %w", err))
	}
	if _, err := config.Parse(written); err != nil {
		return restoreConfigOnly(fmt.Errorf("записанный config.yaml не грузится, панель не тронута: %w", err))
	}

	if r.Action == ActionAttach {
		// restoreConfigOnly, а не restore (находка «мелочи» финального ревью
		// ветки): systemctl restart к этому моменту ещё НЕ вызывался — по
		// собственному доводу restoreConfigOnly выше панель здесь не
		// потревожена, и перезапускать её незачем.
		if err := env.H.MkdirAll(path.Dir(r.Attach.Block.Storage.State), 0o700); err != nil {
			return restoreConfigOnly(fmt.Errorf("создание каталога состояния: %w", err))
		}
	}
	if err := env.H.Systemctl("restart", PanelUnit); err != nil {
		return restore(fmt.Errorf("перезапуск панели: %w", err))
	}

	// Постусловие: демон активен.
	if err := env.H.Systemctl("is-active", PanelUnit); err != nil {
		return restore(fmt.Errorf("постусловие: демон не активен после перезапуска: %w", err))
	}

	// Постусловие: «id виден в списке интерфейсов» (attach) / «id из
	// списка исчез» (detach) — проверяется ПОВТОРНЫМ перечитыванием
	// config.yaml С ДИСКА (не той же переменной written и не after в
	// памяти): постусловие обязано убедиться, что записано именно то, что
	// применение задумало, а не то, что мы думаем, что записали
	// (WriteFileAtomic мог вернуть nil, а Host — разойтись с тем, что
	// реально легло на диск).
	written, err = env.H.ReadFile(configPath)
	if err != nil {
		return restore(fmt.Errorf("постусловие: config.yaml не перечитывается: %w", err))
	}
	id := r.ID
	if r.Action == ActionAttach {
		id = r.Attach.Block.ID
	}
	present, err := blockPresent(string(written), id)
	if err != nil {
		return restore(fmt.Errorf("постусловие: %w", err))
	}
	switch r.Action {
	case ActionAttach:
		if !present {
			return restore(fmt.Errorf("постусловие: блок id %q не найден в записанном config.yaml", id))
		}
		// Постусловие attach: устройство отвечает на awg show. Проверка
		// ПОСЛЕ restart, а не повтор предусловия: предусловие выше уже
		// подтвердило, что устройство было живо ДО применения, а это
		// подтверждает, что оно живо ПОСЛЕ.
		if _, err := env.R(r.Attach.Block.BinDir).Show(r.Attach.Device); err != nil {
			return restore(fmt.Errorf("постусловие: устройство %s не отвечает: %w", r.Attach.Device, err))
		}
	case ActionDetach:
		if present {
			return restore(fmt.Errorf("постусловие: блок id %q всё ещё в config.yaml после отвязки", id))
		}
	}

	return nil
}
