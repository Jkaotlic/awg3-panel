package iface_test

import (
	"os"
	"path"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/iface"
)

// TestAdoptableExcludesManaged — под управление предлагаются только те
// .conf, которых ещё нет в config.yaml. Предложить уже подключённый значит
// пообещать действие, которое отказом и закончится (дубликат id/устройства).
func TestAdoptableExcludesManaged(t *testing.T) {
	// Прямой слэш, а не filepath.Join: Adoptable сравнивает пути через path
	// (значение config: из config.yaml — путь целевого Linux-хоста), и на
	// Windows смешение разделителей дало бы «не совпало» там, где на боевом
	// хосте совпадает. Тот же приём, что в testConfig
	// (cmd/awg3panel/cli_iface_test.go) и tmpInterfaceStorage.
	dir := filepath.ToSlash(t.TempDir())
	for _, n := range []string{"awg3.conf", "awg2.conf", "awgref.conf", "заметка.txt"} {
		if err := os.WriteFile(path.Join(dir, n), []byte("[Interface]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{Interfaces: []config.Interface{
		{ID: "awg3", Config: path.Join(dir, "awg3.conf")},
		{ID: "awgref", Config: path.Join(dir, "awgref.conf")},
	}}

	got, err := iface.Adoptable(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"awg2.conf"}) {
		t.Errorf("Adoptable = %v, ожидали [awg2.conf]", got)
	}
}

// TestAdoptableMissingDirIsEmpty — каталога может не быть вовсе (панель на
// хосте без AmneziaWG). Это «подключать нечего», а не ошибка: консоль
// показывает пустой список, а не плашку.
func TestAdoptableMissingDirIsEmpty(t *testing.T) {
	got, err := iface.Adoptable(path.Join(filepath.ToSlash(t.TempDir()), "нет"), &config.Config{})
	if err != nil {
		t.Fatalf("отсутствие каталога стало ошибкой: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Adoptable = %v, ожидали пусто", got)
	}
}
