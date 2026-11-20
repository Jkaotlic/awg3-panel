package issuer

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readTarGz(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	out := map[string]string{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		out[h.Name] = string(b)
	}
}

func TestSnapshotStateСодержимое(t *testing.T) {
	src := t.TempDir()
	peers := filepath.Join(src, "peers.json")
	defs := filepath.Join(src, "defaults.json")
	keys := filepath.Join(src, "keys")
	os.WriteFile(peers, []byte(`{"p":1}`), 0o600)
	os.WriteFile(defs, []byte(`{"d":1}`), 0o600)
	os.MkdirAll(keys, 0o700)
	os.WriteFile(filepath.Join(keys, "a.key"), []byte("KEY"), 0o600)

	dir := filepath.Join(t.TempDir(), "state")
	path, err := snapshotState(dir, []string{peers, defs}, keys, time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC), 1)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != "state.20261029T120000-0001.tar.gz" {
		t.Errorf("имя снимка %q", filepath.Base(path))
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Errorf("права снимка %v, ожидалось 0600", st.Mode().Perm())
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Errorf("права каталога %v, ожидалось 0700", st.Mode().Perm())
	}
	got := readTarGz(t, path)
	want := map[string]string{"peers.json": `{"p":1}`, "defaults.json": `{"d":1}`, "keys/a.key": "KEY"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("содержимое снимка %v, ожидалось %v", got, want)
	}
}

func TestSnapshotStateБезDefaults(t *testing.T) {
	src := t.TempDir()
	peers := filepath.Join(src, "peers.json")
	os.WriteFile(peers, []byte(`{}`), 0o600)
	path, err := snapshotState(filepath.Join(t.TempDir(), "state"),
		[]string{peers, filepath.Join(src, "defaults.json")}, filepath.Join(src, "keys"), time.Now(), 1)
	if err != nil {
		t.Fatalf("отсутствие defaults.json и keys — не ошибка: %v", err)
	}
	if got := readTarGz(t, path); len(got) != 1 || got["peers.json"] != "{}" {
		t.Fatalf("ожидался только peers.json, получено %v", got)
	}
}

func TestPruneStateBackups(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 25; i++ {
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("state.20261029T1200%02d-0001.tar.gz", i)), nil, 0o600)
	}
	pruneStateBackups(dir, 20)
	entries, _ := os.ReadDir(dir)
	if len(entries) != 20 || entries[0].Name() != "state.20261029T120005-0001.tar.gz" {
		t.Fatalf("ожидались 20 самых новых, первый — ...120005, получено %d, первый %s", len(entries), entries[0].Name())
	}
}

func TestSnapshotStateKeysНеКаталог(t *testing.T) {
	src := t.TempDir()
	peers := filepath.Join(src, "peers.json")
	keys := filepath.Join(src, "keys")
	os.WriteFile(peers, []byte(`{}`), 0o600)
	os.WriteFile(keys, []byte("занято"), 0o600)
	if _, err := snapshotState(filepath.Join(t.TempDir(), "state"), []string{peers}, keys, time.Now(), 1); err != nil {
		t.Fatalf("keys-файл вместо каталога — «ключей нет», а не отказ снимка: %v", err)
	}
}

// Финальное ревью, M3: осиротевшие временные файлы снимка (внутри — ключи)
// убираются, если старше часа; свежие (идущая запись) не трогаются.
func TestPruneStateBackupsУбираетСтарыеTmp(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, ".state-1.tmp")
	fresh := filepath.Join(dir, ".state-2.tmp")
	os.WriteFile(old, []byte("KEY"), 0o600)
	os.WriteFile(fresh, []byte("KEY"), 0o600)
	past := time.Now().Add(-2 * time.Hour)
	os.Chtimes(old, past, past)
	pruneStateBackups(dir, 20)
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("старый .state-*.tmp не удалён")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Error("свежий .state-*.tmp удалён — им может пользоваться идущая запись")
	}
}

// Финальное ревью, M4: существующий каталог снимков с широкими правами ужесточается до 0700.
func TestSnapshotStateУжесточаетПраваКаталога(t *testing.T) {
	src := t.TempDir()
	peers := filepath.Join(src, "peers.json")
	os.WriteFile(peers, []byte(`{}`), 0o600)
	dir := filepath.Join(t.TempDir(), "state")
	os.MkdirAll(dir, 0o755)
	os.Chmod(dir, 0o755)
	if _, err := snapshotState(dir, []string{peers}, "", time.Now(), 1); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Fatalf("права каталога %v, ожидалось 0700", st.Mode().Perm())
	}
}
