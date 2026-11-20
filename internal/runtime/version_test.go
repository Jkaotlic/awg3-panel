package runtime

import (
	"runtime/debug"
	"testing"
)

// amneziawg-go --version печатает константу 0.0.20250522 для ЛЮБОЙ сборки
// 3.x — апстрим её не бампает (проверено на v3.1.20260814 и v3.1.20260828).
// Настоящая версия лежит в buildinfo бинаря (модуль
// github.com/amnezia-vpn/amneziawg-go/v3 при сборке через go install по
// module-пути); из tarball-сборки там "(devel)" — тогда остаётся --version.
func TestModuleVersionИзBuildinfo(t *testing.T) {
	bi := &debug.BuildInfo{Main: debug.Module{Path: "github.com/amnezia-vpn/amneziawg-go/v3", Version: "v3.1.20260828"}}
	if got := moduleVersion(bi); got != "amneziawg-go v3.1.20260828" {
		t.Fatalf("moduleVersion = %q", got)
	}
	// Сборка из tarball: версии нет — пусто, вызывающий откатится на --version.
	bi = &debug.BuildInfo{Main: debug.Module{Path: "github.com/amnezia-vpn/amneziawg-go/v3", Version: "(devel)"}}
	if got := moduleVersion(bi); got != "" {
		t.Fatalf("на (devel) ожидалась пустая строка, получено %q", got)
	}
	// Чужой модуль в Main (например, обёртка), а amneziawg-go — зависимость.
	bi = &debug.BuildInfo{
		Main: debug.Module{Path: "example.com/wrapper", Version: "(devel)"},
		Deps: []*debug.Module{{Path: "github.com/amnezia-vpn/amneziawg-go/v3", Version: "v3.1.20260814"}},
	}
	if got := moduleVersion(bi); got != "amneziawg-go v3.1.20260814" {
		t.Fatalf("moduleVersion из Deps = %q", got)
	}
	if got := moduleVersion(nil); got != "" {
		t.Fatalf("nil buildinfo: %q", got)
	}
}
