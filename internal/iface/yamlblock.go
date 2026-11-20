package iface

import (
	"fmt"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Jkaotlic/awg3-panel/internal/config"
)

// renderable — зеркало config.Interface с omitempty. Существует затем,
// чтобы блок в config.yaml выглядел так, как его написал бы человек: без
// строк вида `interface_edit: false` и `client_configs: ""`, которые
// yaml.Marshal по самой config.Interface напечатал бы обязательно.
//
// Дубль опасен ровно одним: поле, добавленное в config.Interface и забытое
// здесь, молча не попадёт в записанный config.yaml. Против этого стоит
// RenderableFieldsMissing и тест-страж, который её вызывает.
type renderable struct {
	ID            string         `yaml:"id"`
	Title         string         `yaml:"title,omitempty"`
	Interface     string         `yaml:"interface"`
	Config        string         `yaml:"config"`
	BinDir        string         `yaml:"bin_dir"`
	InterfaceEdit bool           `yaml:"interface_edit,omitempty"`
	Client        config.Client  `yaml:"client,omitempty"`
	Storage       config.Storage `yaml:"storage"`
}

// RenderableFieldsMissing возвращает имена полей config.Interface, которых
// нет в зеркале. Пустой срез — зеркало полно.
func RenderableFieldsMissing() []string {
	have := map[string]bool{}
	rt := reflect.TypeOf(renderable{})
	for i := 0; i < rt.NumField(); i++ {
		have[rt.Field(i).Name] = true
	}
	var missing []string
	ct := reflect.TypeOf(config.Interface{})
	for i := 0; i < ct.NumField(); i++ {
		if !have[ct.Field(i).Name] {
			missing = append(missing, ct.Field(i).Name)
		}
	}
	return missing
}

const itemIndent = "  "

// RenderInterfaceBlock рисует один элемент списка interfaces:, включая
// маркер "- " и отступ в два пробела, и завершается переводом строки.
func RenderInterfaceBlock(in config.Interface) (string, error) {
	b, err := yaml.Marshal([]renderable{{
		ID: in.ID, Title: in.Title, Interface: in.Interface,
		Config: in.Config, BinDir: in.BinDir, InterfaceEdit: in.InterfaceEdit,
		Client: in.Client, Storage: in.Storage,
	}})
	if err != nil {
		return "", err
	}
	var out strings.Builder
	for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		out.WriteString(itemIndent + line + "\n")
	}
	return out.String(), nil
}

// interfacesBlock возвращает границы блока списка interfaces: в тексте:
// начало (индекс первого байта после строки "interfaces:") и конец —
// начало первой следующей строки НУЛЕВОГО отступа, либо длину текста.
// Ключ "interfaces:" определяется по содержимому после удаления хвостовых
// пробелов и переводов строк, поэтому работает и с хвостовыми пробелами.
func interfacesBlock(text string) (start, end int, err error) {
	lines := strings.SplitAfter(text, "\n")
	off, found := 0, false
	for _, line := range lines {
		// Убираем переводы строк и хвостовые пробелы, но НЕ ведущие пробелы,
		// чтобы проверка !strings.HasPrefix(trimmed, " ") работала правильно.
		trimmed := strings.TrimRight(strings.TrimRight(line, "\n"), "\r ")
		switch {
		case !found && trimmed == "interfaces:":
			found, start = true, off+len(line)
		case found && trimmed != "" && !strings.HasPrefix(trimmed, " ") &&
			!strings.HasPrefix(strings.TrimSpace(trimmed), "#") &&
			// Строка "- ..." на нулевом отступе — это ЭЛЕМЕНТ списка, а не
			// следующий ключ верхнего уровня: YAML разрешает писать элементы
			// без отступа относительно ключа, и yaml.v3 такой файл читает.
			// Без этой оговорки блок списка заканчивался прямо на первом же
			// его элементе, и текстовая хирургия видела ПУСТОЙ список там,
			// где загрузчик видит интерфейс, — вставка дубликата проходила
			// молча, а вставленный блок ложился ВЫШЕ существующих элементов
			// и ломал YAML отступом (находка финального ревью ветки,
			// вторая половина CRITICAL 1).
			!strings.HasPrefix(trimmed, "- "):
			return start, off, nil
		}
		off += len(line)
	}
	if !found {
		return 0, 0, fmt.Errorf("в config.yaml нет ключа interfaces:")
	}
	return start, len(text), nil
}

// stripInlineComment отрезает хвостовой YAML-комментарий от значения
// скаляра. Два правила языка, оба существенные:
//
//   - комментарий начинается только с `#`, перед которым пробел, табуляция
//     или начало строки. `id: a#b` — это id "a#b" целиком, а не "a";
//   - `#` внутри кавычек комментарием не является вовсе: `id: "a#b"`.
//
// Обрезание «до первой решётки» нарушило бы оба и разошлось бы с тем, как
// тот же файл прочитает yaml.v3 при загрузке конфига, — а хирургия текста и
// загрузчик обязаны сходиться в том, какой интерфейс где, иначе панель
// правит не тот блок, который показала оператору.
func stripInlineComment(s string) string {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote == '"' && c == '\\':
			i++ // экранированный символ (в том числе кавычка) строку не закрывает
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t'):
			return s[:i]
		}
	}
	return s
}

// idOfItem читает id элемента, начинающегося в позиции from. Хвостовой
// комментарий отрезается ДО разбора значения: на свежей установке он есть у
// КАЖДОЙ строки `- id:` — install.sh копирует deploy/config.example.yaml в
// /etc/awg3panel/config.yaml дословно, а там строка подписана
// («slug для URL и каталога хранилища»).
func idOfItem(text string, from, to int) string {
	for _, line := range strings.Split(text[from:to], "\n") {
		t := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "- "))
		if rest, ok := strings.CutPrefix(t, "id:"); ok {
			v := strings.TrimSpace(stripInlineComment(strings.TrimSpace(rest)))
			return strings.Trim(v, `"'`)
		}
	}
	return ""
}

// listItem — один элемент списка interfaces: с его границами в тексте
// ([from, to) — байты вместе со всеми строками элемента) и уже разобранным
// id.
type listItem struct {
	from, to int
	id       string
}

// itemList — разобранный список interfaces: целиком.
//
// found отделено от indent намеренно: до финального ревью ветки обе функции
// разбора возвращали "" одновременно и как «отступ нулевой», и как
// «элементов нет» — два разных факта под одним значением, из-за чего
// валидный список с элементами на нулевом отступе выглядел пустым.
type itemList struct {
	indent string // фактический отступ маркеров "- "
	found  bool   // в списке есть хотя бы один элемент
	items  []listItem
}

// parseList — ЕДИНСТВЕННЫЙ обход элементов списка interfaces: на весь
// пакет. До финального ревью ветки связка «найти начала элементов +
// вычислить границу to + сравнить id» была написана трижды — в
// InsertInterface, RemoveInterface и blockPresent, — и правка разбора id
// (обрезание хвостового комментария, см. idOfItem) попала бы в одно место
// из трёх. Расхождение было бы не теоретическим: attach решает по одной
// копии, detach — по другой, постусловие применения — по третьей, и «id
// найден» у них означало бы разное на одном и том же файле.
//
// Однородность отступа проверяется здесь же, а не у вызывающих: отступ
// определяется по ПЕРВОМУ найденному элементу, и элементы с другим отступом
// молча выпали бы из обхода — на конфиге, правленом руками, это дало бы
// «интерфейса с id … нет» на физически присутствующем элементе.
func parseList(text string, start, end int) (itemList, error) {
	var l itemList
	lines := strings.SplitAfter(text[start:end], "\n")

	// Первый проход — отступ и его однородность.
	for _, line := range lines {
		bare := strings.TrimRight(line, "\r\n")
		trimmed := strings.TrimLeft(bare, " \t")
		if !strings.HasPrefix(trimmed, "- ") {
			continue
		}
		cur := bare[:len(bare)-len(trimmed)]
		if !l.found {
			l.indent, l.found = cur, true
			continue
		}
		if l.indent != cur {
			return itemList{}, fmt.Errorf(
				"элементы списка interfaces: имеют разные отступы: %q и %q (список должен быть единообразным)",
				l.indent, cur)
		}
	}
	if !l.found {
		return l, nil
	}

	// Второй проход — границы элементов и их id.
	var starts []int
	off := start
	for _, line := range lines {
		if strings.HasPrefix(line, l.indent+"- ") {
			starts = append(starts, off)
		}
		off += len(line)
	}
	for i, from := range starts {
		to := end
		if i+1 < len(starts) {
			to = starts[i+1]
		}
		l.items = append(l.items, listItem{from: from, to: to, id: idOfItem(text, from, to)})
	}
	return l, nil
}

// reindentBlock переотступает блок YAML с одного отступа на другой.
// Каждая строка в блоке, которая начинается с oldIndent, переписывается
// с newIndent вместо oldIndent.
func reindentBlock(block, oldIndent, newIndent string) string {
	if oldIndent == newIndent {
		return block
	}
	lines := strings.Split(strings.TrimRight(block, "\n"), "\n")
	var out strings.Builder
	for _, line := range lines {
		if strings.HasPrefix(line, oldIndent) {
			out.WriteString(newIndent + line[len(oldIndent):] + "\n")
		} else {
			out.WriteString(line + "\n")
		}
	}
	return out.String()
}

// InsertInterface дописывает блок интерфейса в конец списка interfaces:.
// Исходные байты не меняются: результат — исходный текст с врезанным в
// одну точку блоком.
//
// Отступ вставляемого элемента определяется по фактическому отступу
// существующих элементов списка (если они есть). Если элементов нет,
// используется стандартный отступ itemIndent. Если отступы существующих
// элементов неоднородны, вставка отвергается ошибкой: смешение отступов
// делает YAML невалидным.
func InsertInterface(text string, in config.Interface) (string, error) {
	start, end, err := interfacesBlock(text)
	if err != nil {
		return "", err
	}

	l, err := parseList(text, start, end)
	if err != nil {
		return "", err
	}
	for _, it := range l.items {
		if it.id == in.ID {
			return "", fmt.Errorf("интерфейс с id %q уже есть в config.yaml", in.ID)
		}
	}

	// Отступ вставляемого элемента — фактический отступ уже существующих.
	// Если элементов нет ВОВСЕ (l.found == false, а не l.indent == "":
	// нулевой отступ — валидный YAML и не означает пустого списка), берётся
	// стандартный.
	actualIndent := l.indent
	if !l.found {
		actualIndent = itemIndent
	}

	// Рендерим блок со стандартным отступом itemIndent.
	block, err := RenderInterfaceBlock(in)
	if err != nil {
		return "", err
	}

	// Если фактический отступ отличается от стандартного, переотступаем блок.
	block = reindentBlock(block, itemIndent, actualIndent)

	// Врезка идёт в КОНЕЦ блока списка, а не в конец файла: между
	// interfaces: и следующим ключом верхнего уровня может стоять что
	// угодно, и дописывание в конец файла увело бы блок из списка.
	return text[:end] + block + text[end:], nil
}

// RemoveInterface вырезает элемент списка по id вместе с его строками.
// Всё, что вне вырезанного диапазона, остаётся теми же байтами — поэтому
// пара Insert/Remove сходится в неподвижную точку с первого же круга.
//
// Однородность отступа проверяется здесь тем же getListIndentAndCheck, что
// и в InsertInterface (задача 7 плана 2026-08-27, ревью брифа). Без этой
// проверки itemStarts определяет отступ по ПЕРВОМУ найденному элементу и
// молча пропускает остальные — на конфиге, правленом руками так, что
// искомый id отступлен иначе первого элемента, функция вернула бы
// «интерфейса с id … нет» на физически присутствующем элементе: диагноз,
// уводящий оператора от настоящей причины.
func RemoveInterface(text, id string) (string, error) {
	start, end, err := interfacesBlock(text)
	if err != nil {
		return "", err
	}
	l, err := parseList(text, start, end)
	if err != nil {
		return "", err
	}
	for _, it := range l.items {
		if it.id == id {
			return text[:it.from] + text[it.to:], nil
		}
	}
	return "", fmt.Errorf("интерфейса с id %q в config.yaml нет", id)
}

// blockPresent сообщает, есть ли в тексте элемент списка interfaces: с
// данным id. Текст не мутирует — в отличие от RemoveInterface, это только
// проверка присутствия.
//
// Существует для постусловия шага 6 раздела 6А.5 спеки 2026-08-25 («новый
// id виден в списке интерфейсов» для attach, «id из списка исчез» для
// detach): сеть здесь не годится — у Host нет и не должно быть
// HTTP-клиента, а демон к моменту проверки мог ещё не открыть сокет.
// Перечитанный с диска (не переменная after в памяти) config.yaml,
// проверенный тем же разбором, что и сама хирургия, — тот минимум, который
// подтверждает, что на диске именно то, что применение задумало записать.
func blockPresent(text, id string) (bool, error) {
	start, end, err := interfacesBlock(text)
	if err != nil {
		return false, err
	}
	l, err := parseList(text, start, end)
	if err != nil {
		return false, err
	}
	for _, it := range l.items {
		if it.id == id {
			return true, nil
		}
	}
	return false, nil
}
