// Package runtime изолирует все побочные эффекты работы с AmneziaWG:
// вызовы awg и awg-quick. Всё, что выше по стеку, зависит только от
// интерфейса Runner, поэтому логика применения изменений тестируется
// без живого туннеля.
//
// Метода SetConf здесь нет и не должно появиться: awg setconf рвёт живые
// сессии, awg syncconf — нет (раздел 6.1 спеки).
package runtime

type Runner interface {
	// Show возвращает вывод `awg show <iface> dump`.
	Show(iface string) (string, error)
	// ShowConf возвращает вывод `awg showconf <iface>` — конфиг живого устройства.
	ShowConf(iface string) (string, error)
	// Strip возвращает вывод `awg-quick strip <confPath>` — конфиг без
	// Address/MTU/PostUp/PostDown, пригодный для syncconf. Передаётся путь,
	// а не имя интерфейса: по имени awg-quick ищет только
	// /etc/amnezia/amneziawg/<имя>.conf и не видит конфиг, лежащий в другом
	// месте (например, в каталоге контейнера на RPi).
	Strip(confPath string) (string, error)
	// SyncConf применяет конфиг из файла по пути path, не разрывая сессии.
	SyncConf(iface, path string) error
	GenKey() (string, error)
	GenPSK() (string, error)
	PubKey(priv string) (string, error)
	// Version возвращает вывод `amneziawg-go --version` — строку вида
	// "amneziawg-go 0.0.20250522". Это единственный метод Runner, не
	// привязанный к конкретному интерфейсу: бинарь один на bin_dir, версия у
	// него одна независимо от того, какой awgN он сейчас обслуживает.
	// Вызывающий обязан кэшировать результат сам (см. issuer.Service) —
	// Version его не кэширует и опрашивает бинарь заново на каждый вызов.
	Version() (string, error)
}
