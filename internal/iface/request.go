// Package iface — жизненный цикл интерфейсов панели: заведение, взятие под
// управление, отвязка и удаление (спека 2026-08-25).
//
// Пакет намеренно ничего не выполняет сам. Он собирает ЗАЯВКУ — файл,
// описывающий будущее изменение хоста, — и отдельно умеет её выполнить.
// Разделение не архитектурное украшательство: заявку пишет демон панели,
// запертый песочницей systemd, а выполняет её подкоманда CLI, запущенная
// человеком по SSH под root. Между нажатием в консоли и изменением хоста
// стоит явный запуск человеком, и оператор видит одно и то же дважды.
package iface

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/Jkaotlic/awg3-panel/internal/atomicfile"
	"github.com/Jkaotlic/awg3-panel/internal/config"
)

// RequestVersion — версия формата заявки. Заявка более высокой версии
// отвергается: её писала панель, знающая шаги, которых этот исполнитель не
// умеет, и выполнить её «насколько получится» значит изменить хост
// наполовину.
const RequestVersion = 1

type Action string

const (
	ActionAttach Action = "attach"
	ActionDetach Action = "detach"
)

// knownActions — множество, а не switch: то же множество нужно и разбору, и
// сообщению об ошибке, и расширяться оно будет планом Б (create/delete).
var knownActions = map[Action]bool{ActionAttach: true, ActionDetach: true}

// AttachPayload — всё, что нужно, чтобы вписать существующий интерфейс в
// config.yaml. Block — РОВНО тот блок, который будет вставлен: исполнитель
// ничего не выводит заново, потому что применённое обязано совпасть с
// показанным (спека 2026-08-25, раздел 3.2).
type AttachPayload struct {
	ConfigRevision string           `json:"config_revision,omitempty"`
	ConfPath       string           `json:"conf_path"`
	Device         string           `json:"device"`
	Block          config.Interface `json:"block"`
}

// DetachPayload — снимок отвязываемого, нужный только для подтверждения:
// человек в терминале должен увидеть, что именно исчезнет из панели.
// Каталог состояния при отвязке остаётся на диске (спека 2026-08-25,
// раздел 6А.4), поэтому его путь здесь — предмет показа, а не удаления.
type DetachPayload struct {
	ConfigRevision string `json:"config_revision,omitempty"`
	ID             string `json:"id"`
	Device         string `json:"device"`
	ConfPath       string `json:"conf_path"`
	StateDir       string `json:"state_dir"`
	// Peers — число секций [Peer] в .conf на момент сборки заявки (спека
	// 2026-08-25, раздел 6А.1: detach не обращается к устройству вовсе).
	// Список пиров, который показывает панель, строится по ЖИВОМУ серверу
	// (awg show), а не по .conf, — числа могут разойтись, если пир добавлен
	// или снесён вручную между сборкой заявки и её применением. Это поле
	// только для подтверждения в терминале, не источник истины о составе.
	//
	// Тег JSON называет источник прямо в имени ключа (peers_from_conf, а не
	// просто peers) — находка ревью задачи 9: потребитель ответа
	// /api/manage/preview видит только сериализованный JSON, а не этот
	// комментарий, и без пометки в самом ключе прочитал бы число как «пиров
	// сейчас», спутав его со счётчиком из issuer.IfaceSummary (тот — по
	// живому серверу). Переименование безопасно: формат заявки не выпущен
	// ни в одной уже применённой сборке (задача 9 — первый вызывающий,
	// пишущий такие заявки через HTTP), и на диске не лежит ни одного файла
	// со старым ключом.
	Peers int `json:"peers_from_conf"`
}

type Request struct {
	Version        int            `json:"version"`
	Action         Action         `json:"action"`
	CreatedAt      string         `json:"created_at"`
	CreatedBy      string         `json:"created_by"`
	ID             string         `json:"id"`
	ConfigRevision string         `json:"config_revision,omitempty"`
	Attach         *AttachPayload `json:"attach,omitempty"`
	Detach         *DetachPayload `json:"detach,omitempty"`

	// Name — имя файла, из которого заявка прочитана. Не сериализуется:
	// имя принадлежит каталогу, а не заявке, и хранить его внутри значило бы
	// завести второй источник правды, расходящийся при переименовании.
	Name string `json:"-"`
}

// Parse разбирает заявку СТРОГО: неизвестное поле, неизвестное действие,
// версия из будущего и несовпадение action с payload — отказы.
func Parse(b []byte) (Request, error) {
	var r Request
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return Request{}, fmt.Errorf("разбор заявки: %w", err)
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return Request{}, fmt.Errorf("после заявки есть лишние данные")
	}
	if r.Version != RequestVersion {
		return Request{}, fmt.Errorf("версия заявки %d, этот исполнитель знает %d", r.Version, RequestVersion)
	}
	if !knownActions[r.Action] {
		return Request{}, fmt.Errorf("неизвестное действие %q", r.Action)
	}
	if _, err := time.Parse(time.RFC3339, r.CreatedAt); err != nil {
		return Request{}, fmt.Errorf("неверное время создания заявки")
	}
	if !idRe.MatchString(r.ID) {
		return Request{}, fmt.Errorf("неверный id заявки")
	}
	switch r.Action {
	case ActionAttach:
		if r.Attach == nil || r.Detach != nil {
			return Request{}, fmt.Errorf("заявка attach обязана нести ровно payload attach")
		}
	case ActionDetach:
		if r.Detach == nil || r.Attach != nil {
			return Request{}, fmt.Errorf("заявка detach обязана нести ровно payload detach")
		}
	}
	payloadRevision := r.payloadRevision()
	if r.ConfigRevision != "" && payloadRevision != "" && r.ConfigRevision != payloadRevision {
		return Request{}, fmt.Errorf("ревизии config.yaml в заявке не совпадают")
	}
	if value := r.configRevision(); value != "" {
		sum, err := hex.DecodeString(value)
		if err != nil || len(sum) != sha256.Size || value != strings.ToLower(value) {
			return Request{}, fmt.Errorf("неверная контрольная сумма config.yaml")
		}
	}

	return r, nil
}

// stamp превращает метку времени заявки (RFC 3339) в кусок имени файла:
// «2026-08-27T10:00:00Z» → «20260827T100000Z». Одна функция, а не два
// одинаковых strings.NewReplacer в разных файлах: тем же преобразованием
// исполнитель называет резервную копию config.yaml (apply.go), и одна
// правка формата развела бы имя заявки с именем её бэкапа — оператор,
// разбирающий последствия неудавшегося применения, сопоставляет их именно
// по этой метке.
func stamp(createdAt string) string {
	return strings.NewReplacer(":", "", "-", "").Replace(createdAt)
}

// Save publishes a private request with a distinct name even when several
// operators submit the same action within one second.
func Save(dir string, r Request) (string, error) {
	created, err := time.Parse(time.RFC3339, r.CreatedAt)
	if err != nil {
		return "", fmt.Errorf("время создания заявки: %w", err)
	}
	if !knownActions[r.Action] || !idRe.MatchString(r.ID) {
		return "", fmt.Errorf("недопустимое действие или id заявки")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name := fmt.Sprintf("%s-%s-%s-%s.json", stamp(created.UTC().Format(time.RFC3339)), r.Action, r.ID, rand.Text())
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return name, atomicfile.Write(filepath.Join(dir, name), append(b, '\n'), 0o600)
}

// List перечисляет заявки каталога в порядке имён — то есть в порядке
// времени создания, потому что имя начинается с метки времени. Отсутствие
// каталога — не ошибка: заявок просто нет.
//
// Чужие файлы пропускаются молча, а вот заявка, которая НЕ разбирается,
// возвращается ошибкой: молчаливый пропуск скрыл бы от оператора ровно то,
// что он ждёт применить.
func List(dir string) ([]Request, error) {
	root, err := openRequestDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer root.Close()
	entries, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer entries.Close()
	ents, err := entries.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(ents, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	var out []Request
	for _, e := range ents {
		if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), ".json") || strings.HasPrefix(e.Name(), ".tmp-") {
			continue
		}
		b, err := readRegular(root, e.Name(), 1<<20)
		if err != nil {
			return nil, err
		}
		r, err := Parse(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		r.Name = e.Name()
		out = append(out, r)
	}
	return out, nil
}

// Cancel удаляет заявку по имени. Имя приходит из HTTP-пути, поэтому
// проверяется: только базовое имя, только суффикс .json. Без этого
// «../../etc/…» удалял бы файлы вне каталога правами демона.
func Cancel(dir, name string) error {
	if !validRequestName(name) {
		return fmt.Errorf("недопустимое имя заявки %q", name)
	}
	root, err := openRequestDir(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	locked, err := lockRequestDir(root)
	if err != nil {
		return err
	}
	defer locked.Close()
	if err := root.Remove(name); err != nil {
		return err
	}
	return syncQueue(locked)
}

func validRequestName(name string) bool {
	return name != "" && name == filepath.Base(name) && filepath.Ext(name) == ".json"
}

func lockRequestDir(root *os.Root) (*os.File, error) {
	dir, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	if err := lockQueue(dir); err != nil {
		dir.Close()
		return nil, fmt.Errorf("каталог заявок занят: %w", err)
	}
	return dir, nil
}

// ApplyConfirmed checks that the operator's preview is still current.
func ApplyConfirmed(dir string, approved Request, apply func(Request) error) error {
	if !validRequestName(approved.Name) {
		return fmt.Errorf("недопустимое имя заявки %q", approved.Name)
	}
	root, err := openRequestDir(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	locked, err := lockRequestDir(root)
	if err != nil {
		return err
	}
	defer locked.Close()
	if err := checkApproved(root, approved); err != nil {
		return err
	}
	if err := apply(approved); err != nil {
		return err
	}
	return consumeApproved(root, locked, approved)
}

func checkApproved(root *os.Root, approved Request) error {
	raw, err := readRegular(root, approved.Name, 1<<20)
	if err != nil {
		return err
	}
	current, err := Parse(raw)
	if err != nil {
		return err
	}
	current.Name = approved.Name
	if !reflect.DeepEqual(current, approved) {
		return fmt.Errorf("заявка изменилась после показа, повторите подтверждение")
	}
	return nil
}

func consumeApproved(root *os.Root, locked *os.File, approved Request) error {
	if err := checkApproved(root, approved); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := root.Remove(approved.Name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncQueue(locked)
}

func planRevision(env Env) (string, error) {
	if env.Cfg.Path == "" {
		return "", nil
	}
	raw, err := env.H.ReadFile(env.Cfg.Path)
	if err != nil {
		return "", err
	}
	current, err := config.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("config.yaml изменился, перечитайте конфиг")
	}
	current.Path = env.Cfg.Path
	if !reflect.DeepEqual(current, env.Cfg) {
		return "", fmt.Errorf("config.yaml изменился, перечитайте конфиг")
	}
	return revision(raw), nil
}

func revision(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (r Request) configRevision() string {
	if r.ConfigRevision != "" {
		return r.ConfigRevision
	}
	return r.payloadRevision()
}

func (r Request) payloadRevision() string {
	if r.Attach != nil {
		return r.Attach.ConfigRevision
	}
	if r.Detach != nil {
		return r.Detach.ConfigRevision
	}
	return ""
}

// Раскладка на целевом Linux-хосте — ОДНО объявление на весь бинарь.
//
// До финального ревью ветки эти два корня были объявлены дважды:
// константами в internal/web/handlers_manage.go и литералами в
// cmd/awg3panel/cli_iface.go. Согласие двух объявлений держалось на том,
// что строки написаны одинаково, и ни один тест этого не сверял — а весь
// смысл пере-проверки предусловий в исполнителе (шаг 1 раздела 6А.5 спеки
// 2026-08-25) в том, что он смотрит на ТО ЖЕ, на что смотрела консоль.
// Разойдись они — консоль собирала бы заявку по одному хосту, исполнитель
// применял бы её к другому, и оба были бы «правы».
//
// Полями config.yaml они не сделаны намеренно: поле пришлось бы вписать в
// каждый уже существующий конфиг на боевых хостах ДО обновления панели,
// иначе она после него не поднимется. И вывести их, в отличие от
// StateRoot, неоткуда — они не связаны ни с одним уже настроенным
// интерфейсом, а описывают место, где лежит ЕЩЁ НЕ подключённый.
const (
	DefaultConfDir = "/etc/amnezia/amneziawg"
	DefaultBinRoot = "/opt"
)

// StateRoot — корень состояния панели: /var/lib/awg3panel. Выводится из
// уже написанного (storage.state первого интерфейса лежит в
// <корень>/<id>/peers.json, значит корень — на два уровня выше), а не
// задаётся отдельным полем, по той же причине, что и корни выше.
//
// Пустой список интерфейсов — не ошибка, а "": гарантия «интерфейс есть
// хотя бы один» живёт ВЫШЕ по стеку (config.Validate при загрузке
// config.yaml), а не внутри вызывающего, и ронять HTTP-обработчик паникой
// по индексу вместо понятного отказа планировщика она не обязана. Тем, кому
// пустой корень бессмыслен, отказывает RequestsDir ниже — явным текстом.
//
// path, а не filepath: путь принадлежит целевому Linux-хосту, и на Windows
// filepath.Dir не нашёл бы разделителя (та же ловушка, что уже описана у
// config.Interface.StateDir).
func StateRoot(cfg *config.Config) string {
	if len(cfg.Interfaces) == 0 {
		return ""
	}
	return path.Dir(path.Dir(cfg.Interfaces[0].Storage.State))
}

// RequestsDir — каталог заявок, выведенный из конфига: заявки живут рядом с
// состоянием интерфейсов, в /var/lib/awg3panel/requests.
func RequestsDir(cfg *config.Config) (string, error) {
	root := StateRoot(cfg)
	if root == "" {
		return "", fmt.Errorf("в config.yaml нет ни одного интерфейса — неоткуда вывести каталог заявок")
	}
	return path.Join(root, "requests"), nil
}
