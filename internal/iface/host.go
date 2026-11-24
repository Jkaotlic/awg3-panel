package iface

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Jkaotlic/awg3-panel/internal/atomicfile"
)

// Host — всё, чем исполнитель трогает машину. Узкий намеренно: каждый метод
// здесь — это то, что в тесте придётся подменить, и чем их меньше, тем
// меньше расхождение между проверенным и выполняемым.
//
// Вызовов awg здесь нет: они уже спрятаны за runtime.Runner, и заводить им
// второй фасад значило бы иметь две подставные реализации одного и того же.
type Host interface {
	ReadFile(path string) ([]byte, error)
	WriteFileAtomic(path string, data []byte, perm os.FileMode) error
	MkdirAll(path string, perm os.FileMode) error
	Exists(path string) (bool, error)
	// DirEmpty — «каталога нет ИЛИ он пуст». Отдельный метод, а не пара
	// Exists+ReadDir у вызывающего: это условие отказа из спеки
	// (2026-08-25, раздел 7), и выражать его на месте каждый раз заново
	// значит однажды выразить иначе.
	DirEmpty(path string) (bool, error)
	Systemctl(args ...string) error
}

type osHost struct{}

func NewOSHost() Host { return osHost{} }

func (osHost) ReadFile(p string) ([]byte, error) { return os.ReadFile(p) }

// OpenRoot confines even concurrent symlink changes to the trusted config directory.
func (osHost) ReadAttachConfig(dir, name string) ([]byte, error) {
	root, err := openRealDir(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return readRegular(root, name, 64<<20)
}

func openRealDir(name string) (*os.Root, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%q должен быть обычным каталогом", name)
	}
	root, err := os.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	actual, err := root.Stat(".")
	if err != nil || !os.SameFile(info, actual) {
		root.Close()
		return nil, fmt.Errorf("каталог %q изменился при открытии", name)
	}
	return root, nil
}

func openRequestDir(name string) (*os.Root, error) {
	name = filepath.Clean(name)
	parent, err := openRealDir(filepath.Dir(name))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	base := filepath.Base(name)
	info, err := parent.Lstat(base)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%q должен быть обычным каталогом", name)
	}
	root, err := parent.OpenRoot(base)
	if err != nil {
		return nil, err
	}
	actual, err := root.Stat(".")
	if err != nil || !os.SameFile(info, actual) {
		root.Close()
		return nil, fmt.Errorf("каталог %q изменился при открытии", name)
	}
	return root, nil
}

// Read through the opened directory and verify the opened inode. Nonblocking
// open prevents a concurrently substituted FIFO from stalling the operator.
func readRegular(root *os.Root, name string, limit int64) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%q должен быть обычным файлом", name)
	}
	f, err := root.OpenFile(name, readFlags, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, fmt.Errorf("%q изменился при открытии", name)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%q превышает допустимый размер", name)
	}
	return data, err
}

func (osHost) WriteFileAtomic(p string, data []byte, perm os.FileMode) error {
	return atomicfile.Write(p, data, perm)
}

func (osHost) MkdirAll(p string, perm os.FileMode) error { return os.MkdirAll(p, perm) }

func (osHost) Exists(p string) (bool, error) {
	_, err := os.Stat(p)
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

func (osHost) DirEmpty(p string) (bool, error) {
	ents, err := os.ReadDir(p)
	if os.IsNotExist(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return len(ents) == 0, nil
}

// Systemctl вызывается с таймаутом: restart демона, зависший навсегда,
// оставил бы оператора без консоли и без сообщения о том, почему.
func (osHost) Systemctl(args ...string) error {
	cmd := exec.Command("/usr/bin/systemctl", args...)
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("systemctl %s: %w", strings.Join(args, " "), err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(out.String()))
		}
		return nil
	case <-time.After(90 * time.Second):
		_ = cmd.Process.Kill()
		return fmt.Errorf("systemctl %s: не завершился за 90 с", strings.Join(args, " "))
	}
}

// FakeHost — подставной хост для тестов. Держит файлы в памяти и ведёт
// журнал вызовов: только по журналу и проверяется ПОРЯДОК шагов, а он и
// есть то, ради чего исполнитель написан.
type FakeHost struct {
	Files  map[string][]byte
	Calls  []string
	FailAt string          // вызов, на котором вернуть ошибку (точное совпадение со строкой журнала)
	Dirs   map[string]bool // true — каталог посеян непустым; false — пустой или созданный MkdirAll
	// FailAtOnce ограничивает FailAt одним срабатыванием: после первого
	// отказа FailAt сбрасывается в "", и тот же вызов дальше проходит
	// успешно. Нужен там, где восстановительный вызов внутри restore несёт
	// ТО ЖЕ имя, что и провалившийся исходный (например, оба —
	// "systemctl restart awg3panel"), — без этого поля нельзя проверить,
	// что откат реально поднимает панель обратно, а не просто откатывает
	// config.yaml при вечно падающем рестарте (ревью задачи 7, находка 1).
	FailAtOnce bool
	// FailAtSkip — сколько СОВПАДЕНИЙ с FailAt пропустить, прежде чем
	// отказать. Нужен там, где отказать надо не первому вызову с этим
	// именем, а последующему: восстановительная запись config.yaml внутри
	// restore несёт ТО ЖЕ имя ("write /etc/awg3panel/config.yaml"), что и
	// исходная, успешная. Без этого поля ветка «ОТКАТ НЕ УДАЛСЯ» —
	// единственная, чей текст оператор увидит, оставшись с изменённым
	// config.yaml на руках, — недостижима из тестов вообще (находка
	// IMPORTANT 6 финального ревью ветки).
	FailAtSkip int
}

func NewFakeHost() *FakeHost { return &FakeHost{Files: map[string][]byte{}, Dirs: map[string]bool{}} }

// SeedDir посеивает каталог в состояние «существует и не пуст» — используется
// для тестирования отказов при наличии старого каталога состояния.
func (f *FakeHost) SeedDir(p string) {
	f.Dirs[p] = true
}

func (f *FakeHost) record(call string) error {
	f.Calls = append(f.Calls, call)
	if f.FailAt == call {
		if f.FailAtSkip > 0 {
			f.FailAtSkip--
			return nil
		}
		if f.FailAtOnce {
			f.FailAt = ""
		}
		return fmt.Errorf("подставной отказ на %q", call)
	}
	return nil
}

func (f *FakeHost) ReadFile(p string) ([]byte, error) {
	b, ok := f.Files[p]
	if !ok {
		return nil, os.ErrNotExist
	}
	return b, nil
}

func (f *FakeHost) WriteFileAtomic(p string, data []byte, _ os.FileMode) error {
	if err := f.record("write " + p); err != nil {
		return err
	}
	f.Files[p] = append([]byte(nil), data...)
	return nil
}

func (f *FakeHost) MkdirAll(p string, _ os.FileMode) error {
	if err := f.record("mkdir " + p); err != nil {
		return err
	}
	// Добавить каталог в Dirs, если его там ещё нет. Посеянные непустые
	// каталоги остаются непустыми (Dirs[p] == true).
	if _, exists := f.Dirs[p]; !exists {
		f.Dirs[p] = false
	}
	return nil
}

func (f *FakeHost) Exists(p string) (bool, error) {
	// Exists видит и файлы из Files, и каталоги из Dirs
	if _, ok := f.Files[p]; ok {
		return true, nil
	}
	_, ok := f.Dirs[p]
	return ok, nil
}

func (f *FakeHost) DirEmpty(p string) (bool, error) {
	// Несуществующий каталог считается пустым
	isNonEmpty, exists := f.Dirs[p]
	if !exists {
		return true, nil
	}
	// Посеянный непустой каталог — не пуст
	if isNonEmpty {
		return false, nil
	}
	// Пустой каталог (созданный MkdirAll или посеянный с false) — пуст
	return true, nil
}

func (f *FakeHost) Systemctl(args ...string) error {
	return f.record("systemctl " + strings.Join(args, " "))
}
