//go:build readonly

package main

import (
	"fmt"
	"io"

	"github.com/Jkaotlic/awg3-panel/internal/config"
)

// В сборке только для чтения исполнителя заявок нет физически: весь код,
// правящий config.yaml и дёргающий systemctl, живёт в cli_iface.go с тегом
// "!readonly" и сюда не компилируется. Остаётся объявление с тем же
// сообщением, каким cli_readonly.go отвечает на add/rm, — оператор обязан
// различать «команда выключена этой сборкой» и «такой команды нет».
func ifaceCmd([]string, *config.Config, io.Writer, io.Reader) error {
	return cliInputError{fmt.Sprintf(
		"команда %q недоступна: бинарь собран в режиме только чтения", "iface")}
}
