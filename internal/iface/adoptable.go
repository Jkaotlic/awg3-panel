package iface

import (
	"os"
	"path"
	"sort"

	"github.com/Jkaotlic/awg3-panel/internal/config"
)

// Adoptable перечисляет файлы *.conf каталога confDir, которых ещё нет в
// config.yaml, — то, из чего оператор выбирает при взятии под управление
// (спека 2026-08-25, раздел 6А.2).
//
// Сравнение идёт по ОЧИЩЕННОМУ пути, а не по имени файла: config.yaml
// вправе ссылаться на тот же файл записью с ".." или лишним слэшем, и
// такой интерфейс предлагать к подключению нельзя — он уже подключён.
//
// path, а не path/filepath: сравниваемые строки — пути на целевом
// Linux-хосте (значение config: из config.yaml и confDir), а не пути машины,
// где выполняется код, — панель разрабатывается на Windows. То же
// соглашение, что уже объяснено у config.Interface.StateDir, PlanAttach,
// Apply и RequestsDir; filepath здесь работал по совпадению (на боевом
// Linux-хосте обе реализации Clean/Join делают одно и то же) и выбивался из
// него единственным местом в ветке.
func Adoptable(confDir string, cfg *config.Config) ([]string, error) {
	managed := map[string]bool{}
	for _, in := range cfg.Interfaces {
		managed[path.Clean(in.Config)] = true
	}
	ents, err := os.ReadDir(confDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() || path.Ext(e.Name()) != ".conf" {
			continue
		}
		if managed[path.Clean(path.Join(confDir, e.Name()))] {
			continue
		}
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out, nil
}
