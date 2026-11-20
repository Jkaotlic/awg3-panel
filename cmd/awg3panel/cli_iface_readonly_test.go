//go:build readonly

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/iface"
	"github.com/Jkaotlic/awg3-panel/internal/issuer"
)

// TestIfaceReadonlyRefusesWithoutTouchingDisk — read-only сборка физически
// не несёт исполнителя заявок (см. cli_iface_readonly.go): ifaceCmd здесь —
// заглушка, отвечающая тем же текстом, каким cli_readonly.go отвечает на
// add/rm (fix round 1, minor 3 из cli_readonly_test.go — оператор обязан
// отличать «команда выключена этой сборкой» от «такой команды нет»).
//
// Проверяется не только текст ошибки, но и что заглушка не тронула диск:
// заявка, лежащая в каталоге заранее, обязана остаться на месте — иначе
// текстовая проверка ничего не доказывает (тот же принцип, что уже
// применён в TestReadonlyRunCLIRefusesMutationsWithoutSideEffects).
func TestIfaceReadonlyRefusesWithoutTouchingDisk(t *testing.T) {
	base := filepath.ToSlash(t.TempDir())
	cfg := config.Default()
	cfg.Interfaces[0].Storage = config.Storage{
		State:   base + "/awg3/peers.json",
		Backups: base + "/awg3/backups",
		Keys:    base + "/awg3/keys",
	}
	cfg.Path = base + "/config.yaml"

	dir, err := iface.RequestsDir(cfg)
	if err != nil {
		t.Fatal(err)
	}
	req := iface.Request{
		Version: iface.RequestVersion, Action: iface.ActionAttach,
		CreatedAt: "2026-08-27T10:00:00Z", ID: "awg2",
		Attach: &iface.AttachPayload{
			ConfPath: "/etc/amnezia/amneziawg/awg2.conf", Device: "awg2",
			Block: config.Interface{ID: "awg2", Interface: "awg2"},
		},
	}
	name, err := iface.Save(dir, req)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}

	for _, args := range [][]string{
		{"requests"},
		{"apply"},
		{"apply", "--dry-run"},
		{"cancel", name},
	} {
		var out bytes.Buffer
		err := ifaceCmd(args, cfg, &out, strings.NewReader(""))
		if err == nil {
			t.Errorf("%v: read-only сборка обязана отказать", args)
			continue
		}
		if !strings.Contains(err.Error(), "только чтения") {
			t.Errorf("%v: текст ошибки не объясняет причину: %q", args, err.Error())
		}
		if !errors.Is(err, issuer.ErrInvalidInput) {
			t.Errorf("%v: ошибка не классифицирована для кода возврата: %v", args, err)
		}
		if out.Len() != 0 {
			t.Errorf("%v: в out при отказе ничего не должно попасть: %q", args, out.String())
		}
	}

	after, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Error("заявка изменилась в read-only сборке")
	}
}
