package issuer

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Снимок каталога состояния — спека 2026-10-29, раздел 4. Бэкап серверного
// конфига (Applier.backup) не спасает от потери peers.json, defaults.json и
// ключей клиентов: без них выданные конфиги не перевыдать. Снимок делается в
// начале каждого мутирующего метода Service — «до», как и бэкап конфига, — и
// не делается на согласовании при чтении (loadState): опрос раз в 10 секунд
// вытеснил бы полезные снимки за минуты.

// maxStateBackups — сколько снимков держать; отдельный счёт от бэкапов конфига.
const maxStateBackups = 20

// snapshotState пишет files (по базовому имени) и содержимое keysDir (как
// keys/<имя>) в <dir>/state.<UTC>-<seq>.tar.gz. Отсутствующий файл или
// каталог — не ошибка, просто не входит в архив. Запись — во временный файл
// с последующим rename: оборванный снимок не выдаёт себя за целый.
func snapshotState(dir string, files []string, keysDir string, now time.Time, seq int) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	// MkdirAll не трогает права уже существующего каталога, а внутри снимков
	// — ключи клиентов (финальное ревью, M4).
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", err
	}
	name := filepath.Join(dir, fmt.Sprintf("state.%s-%04d.tar.gz", now.UTC().Format("20060102T150405"), seq))
	tmp, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name()) // после rename — no-op
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return "", err
	}
	zw := gzip.NewWriter(tmp)
	tw := tar.NewWriter(zw)
	add := func(src, as string) error {
		b, err := os.ReadFile(src)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := tw.WriteHeader(&tar.Header{Name: as, Mode: 0o600, Size: int64(len(b)), ModTime: now}); err != nil {
			return err
		}
		_, err = tw.Write(b)
		return err
	}
	for _, f := range files {
		if err := add(f, filepath.Base(f)); err != nil {
			tmp.Close()
			return "", err
		}
	}
	// Каталог ключей, которого нет или который не каталог, — «ключей нет»:
	// снимок копирует то, что есть, а отказ записи ключа мутация получит
	// своей ошибкой от KeyStore, с понятным текстом.
	var entries []os.DirEntry
	if st, err := os.Stat(keysDir); err == nil && st.IsDir() {
		if entries, err = os.ReadDir(keysDir); err != nil {
			tmp.Close()
			return "", err
		}
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if err := add(filepath.Join(keysDir, e.Name()), "keys/"+e.Name()); err != nil {
			tmp.Close()
			return "", err
		}
	}
	if err := tw.Close(); err != nil {
		tmp.Close()
		return "", err
	}
	if err := zw.Close(); err != nil {
		tmp.Close()
		return "", err
	}
	// Sync до rename: иначе при потере питания возможен «целый по имени»,
	// но пустой архив (финальное ревью, M2).
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), name); err != nil {
		return "", err
	}
	return name, nil
}

// pruneStateBackups оставляет keep самых новых снимков. Имена содержат
// UTC-таймштамп и счётчик — лексикографический порядок хронологический.
func pruneStateBackups(dir string, keep int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "state.") && strings.HasSuffix(e.Name(), ".tar.gz") {
			names = append(names, e.Name())
		}
		// Временный файл, брошенный упавшим процессом, — с ключами внутри;
		// час заведомо больше любой живой записи (финальное ревью, M3).
		if !e.IsDir() && strings.HasPrefix(e.Name(), ".state-") && strings.HasSuffix(e.Name(), ".tmp") {
			if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > time.Hour {
				_ = os.Remove(filepath.Join(dir, e.Name()))
			}
		}
	}
	if len(names) <= keep {
		return
	}
	sort.Strings(names)
	for _, n := range names[:len(names)-keep] {
		_ = os.Remove(filepath.Join(dir, n))
	}
}

// snapshot снимает состояние интерфейса перед мутацией. Вызывать только под
// s.mu. Отказ снимка — отказ мутации: молча менять состояние без копии
// значит потерять возможность откатиться ровно тогда, когда она нужна.
func (s *Service) snapshot() error {
	s.stateSeq++
	dir := filepath.Join(s.iface.Storage.Backups, "state")
	if _, err := snapshotState(dir, []string{s.iface.Storage.State, s.iface.DefaultsPath()},
		s.iface.Storage.Keys, time.Now(), s.stateSeq); err != nil {
		return fmt.Errorf("снимок состояния перед изменением: %w", err)
	}
	pruneStateBackups(dir, maxStateBackups)
	return nil
}
