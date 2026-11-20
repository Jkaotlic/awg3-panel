//go:build readonly

package web

// ifaceEnvOverride в read-only сборке ничего не собирает: маршрутов
// /api/manage, которым поле Server.ifaceEnv нужно, в этой сборке нет вовсе
// — handlers_manage.go целиком под тегом !readonly, и registerManage
// никогда не вызывается (registerMutations здесь — пустая функция, см.
// handlers_mutate_readonly.go). Тип объявлен здесь под тем же именем, что и
// в handlers_manage.go, — то же решение, что уже несут PeerMutator и
// MutatorRegistry (handlers_mutate.go / handlers_mutate_readonly.go), и по
// той же причине: поле Server.ifaceEnv обязано компилироваться в обеих
// сборках без утечки internal/iface и internal/runtime в readonly. Сама
// функциональная форма (func()) значения не имеет — в этой сборке значение
// этого типа никогда не создаётся и не вызывается.
type ifaceEnvOverride func()
