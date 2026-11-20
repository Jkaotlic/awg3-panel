package runtime

import (
	"debug/buildinfo"
	"runtime/debug"
	"strings"
)

// amneziawgModule — module-путь движка; при сборке через
// `go install github.com/amnezia-vpn/amneziawg-go/v3/...@<tag>` линкер
// записывает тег в buildinfo бинаря, и это единственное место, где лежит
// НАСТОЯЩАЯ версия: `amneziawg-go --version` печатает константу
// 0.0.20250522 для любой сборки 3.x — апстрим её не бампает (проверено на
// v3.1.20260814 и v3.1.20260828 живьём, 07.09.2026).
const amneziawgModule = "github.com/amnezia-vpn/amneziawg-go"

// moduleVersion достаёт версию движка из buildinfo. Пусто — если buildinfo
// нет, модуль не найден или версия "(devel)" (сборка из tarball, не по
// module-пути): тогда вызывающий откатывается на --version.
func moduleVersion(bi *debug.BuildInfo) string {
	if bi == nil {
		return ""
	}
	mods := append([]*debug.Module{&bi.Main}, bi.Deps...)
	for _, m := range mods {
		if m == nil || !strings.HasPrefix(m.Path, amneziawgModule) {
			continue
		}
		if m.Version == "" || m.Version == "(devel)" {
			return ""
		}
		return "amneziawg-go " + m.Version
	}
	return ""
}

func versionFromBinary(path string) string {
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return ""
	}
	return moduleVersion(bi)
}
