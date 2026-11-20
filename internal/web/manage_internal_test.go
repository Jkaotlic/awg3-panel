//go:build !readonly

package web

import (
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/iface"
)

// TestManageEnvUsesSharedRoots — находка IMPORTANT 5 финального ревью
// ветки. Смысл пере-проверки предусловий в исполнителе (iface.Apply, шаг 1
// раздела 6А.5 спеки 2026-08-25) в том, что он смотрит на ТО ЖЕ, на что
// смотрела консоль. До этой правки корни `/etc/amnezia/amneziawg` и `/opt`
// были объявлены дважды — константами здесь и литералами в
// cmd/awg3panel/cli_iface.go, — а выражение
// `path.Dir(path.Dir(cfg.Interfaces[0].Storage.State))` написано трижды.
// Согласие держалось на том, что строки написаны одинаково, и ни один тест
// этого не сверял: разойдись они, консоль собрала бы заявку по одному
// хосту, а исполнитель применил бы её к другому — и оба были бы «правы».
//
// Парный тест на стороне исполнителя — TestIfaceEnvUsesSharedRoots
// (cmd/awg3panel/cli_iface_test.go). Оба сверяются с ОДНИМ экспортированным
// объявлением в internal/iface, поэтому разъехаться теперь физически
// нечему.
func TestManageEnvUsesSharedRoots(t *testing.T) {
	cfg := config.Default()
	cfg.Interfaces[0].Storage.State = "/var/lib/awg3panel/awg3/peers.json"
	s := &Server{cfg: cfg}

	env := s.manageEnv()
	if env.ConfDir != iface.DefaultConfDir {
		t.Errorf("ConfDir = %q, ожидали iface.DefaultConfDir (%q)", env.ConfDir, iface.DefaultConfDir)
	}
	if env.BinRoot != iface.DefaultBinRoot {
		t.Errorf("BinRoot = %q, ожидали iface.DefaultBinRoot (%q)", env.BinRoot, iface.DefaultBinRoot)
	}
	if want := iface.StateRoot(cfg); env.StateRoot != want {
		t.Errorf("StateRoot = %q, ожидали iface.StateRoot(cfg) (%q)", env.StateRoot, want)
	}
}

// TestManageEnvOnEmptyInterfacesDoesNotPanic — пустой список интерфейсов не
// должен ронять сборку окружения: гарантия «интерфейс есть хотя бы один»
// живёт ВЫШЕ по стеку (config.Validate при загрузке), а не внутри
// HTTP-обработчика. Тот же довод, что уже записан у PlanAttach про
// env.Cfg.Interfaces[0] и у iface.RequestsDir.
func TestManageEnvOnEmptyInterfacesDoesNotPanic(t *testing.T) {
	s := &Server{cfg: &config.Config{}}
	if got := s.manageEnv().StateRoot; got != "" {
		t.Errorf("StateRoot = %q, ожидали пусто", got)
	}
}
