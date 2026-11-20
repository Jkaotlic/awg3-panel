package issuer

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Jkaotlic/awg3-panel/internal/wgconf"
)

// interfaceWarnings сверяет живой серверный [Interface] с правилами AWG 3.x —
// спека 2026-10-29, раздел 3. Только чтение: правило 2 репозитория не даёт
// панели чинить [Interface], поэтому нарушение — предупреждение оператору,
// а не отказ. Неразбираемое значение — тоже предупреждение, не паника и не
// ошибка: сводка не должна падать из-за ручной правки сервера.
//
// Правила и откуда они:
//   - HeaderProtectionKey ⇒ S1..S4 ≥ 12: nonce шифра берётся из паддинга,
//     иначе интерфейс не поднимается (device/uapi.go);
//   - S4 ≤ 32: потолок amneziawg-tools (src/config.c);
//   - H1..H4 не пересекаются: «headers must not overlap»;
//   - RandomTrailers ⇒ ContentPaddingAddition: без него паддинг берётся из
//     растущего udpWindow (send.go), и скорость падает примерно в сто раз
//     (замер bivlked: 11,94 → 0,09–0,14 МБ/с);
//   - RandomTrailers ⇒ S1 = S2 = S3 = S4: иначе приёмник примеряет
//     транспортные пакеты к веткам рукопожатия по разным смещениям и молча
//     теряет часть из них (amneziawg-go#186, kmod#226).
func interfaceWarnings(iface *wgconf.Section) []string {
	var out []string
	warn := func(format string, a ...any) { out = append(out, fmt.Sprintf(format, a...)) }

	hpk := iface.Get("HeaderProtectionKey") != ""
	var s [4]int
	sAll := true
	for i := range s {
		key := fmt.Sprintf("S%d", i+1)
		v := iface.Get(key)
		if v == "" {
			sAll = false
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			warn("%s = %q не разобрать как число", key, v)
			sAll = false
			continue
		}
		s[i] = n
		if hpk && n < 12 {
			warn("%s = %d меньше 12 при заданном HeaderProtectionKey — интерфейс с таким значением не поднимется", key, n)
		}
	}
	if s[3] > 32 {
		warn("S4 = %d больше 32 — потолок amneziawg-tools", s[3])
	}

	type band struct {
		key    string
		lo, hi uint64
	}
	var bands []band
	for i := 1; i <= 4; i++ {
		key := fmt.Sprintf("H%d", i)
		v := iface.Get(key)
		if v == "" {
			continue
		}
		lo, hi, ok := parseHeaderBand(v)
		if !ok {
			warn("%s = %q не разобрать: ожидается число или диапазон N-M", key, v)
			continue
		}
		bands = append(bands, band{key: key, lo: lo, hi: hi})
	}
	for i := range bands {
		for j := i + 1; j < len(bands); j++ {
			if bands[i].lo <= bands[j].hi && bands[j].lo <= bands[i].hi {
				warn("%s и %s пересекаются — тип пакета не определить однозначно", bands[i].key, bands[j].key)
			}
		}
	}

	if isOn(iface.Get("RandomTrailers")) {
		if iface.Get("ContentPaddingAddition") == "" {
			warn("RandomTrailers включён без ContentPaddingAddition — скорость упадёт примерно в сто раз")
		}
		if sAll && !(s[0] == s[1] && s[1] == s[2] && s[2] == s[3]) {
			warn("RandomTrailers включён при неравных S1..S4 (%d/%d/%d/%d) — тихие потери части пакетов (#186); нужны равные S",
				s[0], s[1], s[2], s[3])
		}
	}
	return out
}

// parseHeaderBand разбирает H как «N» или «N-M» (N ≤ M).
func parseHeaderBand(v string) (lo, hi uint64, ok bool) {
	a, b, isRange := strings.Cut(v, "-")
	lo, err := strconv.ParseUint(a, 10, 32)
	if err != nil {
		return 0, 0, false
	}
	if !isRange {
		return lo, lo, true
	}
	hi, err = strconv.ParseUint(b, 10, 32)
	if err != nil || hi < lo {
		return 0, 0, false
	}
	return lo, hi, true
}
