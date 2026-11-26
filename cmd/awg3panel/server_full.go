//go:build !readonly

package main

import (
	"log"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/web"
)

// newServer собирает сервер с реестром мутаторов. NewServerWithMutator и
// web.AdaptMutators существуют только в полной сборке, поэтому выбор
// конструктора разведён по файлам с build-тегами, а не условием внутри
// main: в read-only бинаре этой строки не должно быть физически (раздел
// 12.1 спеки). Задача 10 перевела сервер с одного заранее выбранного
// интерфейса на весь реестр — маршруты сами решают, какой интерфейс
// обслуживать, по сегменту пути /api/ifaces/{iface}/...
func newServer(cfg *config.Config, reg *issuer.Registry) *web.Server {
	server := web.NewServerWithMutator(cfg, web.Adapt(reg), web.AdaptMutators(reg))
	if err := configureJunkTune(server, cfg, reg); err != nil {
		log.Printf("автоподбор Keenetic отключён: %v", err)
	}
	return server
}

func recoverBeforeServe(reg *issuer.Registry) error {
	for _, svc := range reg.All() {
		if err := svc.Recover(); err != nil {
			log.Printf("восстановление интерфейса: %v", err)
		}
	}
	return nil
}
