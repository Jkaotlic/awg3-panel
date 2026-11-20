package issuer

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/wgconf"
)

// TestGenerateJitterДержитсяДиапазонов проверяет и границы (значение не
// выходит за диапазон), и — находка ревью задачи 8, Important #1 —
// ДОСТИЖИМОСТЬ краёв диапазона Jc: без этого off-by-one в randRange
// (например, big.NewInt(hi-lo) вместо big.NewInt(hi-lo+1), тихо сужающий
// верхний край до 9 вместо 10) прошёл бы все три теста файла незамеченным —
// ни одна проверка не утверждала, что край когда-либо ВСТРЕЧАЕТСЯ, только
// что ничего не выходит НАРУЖУ.
//
// Jc проверяется здесь же, в этом цикле на 300 прогонов: ширина диапазона
// Jc — 7 (4..10), и вероятность ни разу не встретить конкретное значение за
// 300 независимых прогонов — (6/7)^300 ≈ 8·10⁻²¹, то есть флака отсюда не
// будет практически никогда. Проверка достижимости Jmin вынесена в
// отдельный тест ниже с бОльшим числом прогонов: у Jmin диапазон шириной
// 101 (50..150), и на этих же 300 прогонах вероятность пропустить край —
// (100/101)^300 ≈ 0.05, то есть примерно один прогон CI из двадцати падал бы
// без всякой реальной причины. Потолок Jmax (1000) больше не зажимается в
// коде — см. комментарий у GenerateJitter — поэтому проверка "Jmax > 1000"
// ниже теперь единственный сторож против расширения диапазонов Jmin/span за
// пределы MTU.
func TestGenerateJitterДержитсяДиапазонов(t *testing.T) {
	sawJcMin, sawJcMax := false, false
	for i := 0; i < 300; i++ {
		j, err := GenerateJitter(rand.Reader)
		if err != nil {
			t.Fatalf("прогон %d: %v", i, err)
		}
		if j.Jc < 4 || j.Jc > 7 {
			t.Fatalf("Jc = %d вне 4..7", j.Jc)
		}
		if j.Jc == 4 {
			sawJcMin = true
		}
		if j.Jc == 7 {
			sawJcMax = true
		}
		if j.Jmin < 64 || j.Jmin > 150 {
			t.Fatalf("Jmin = %d вне 64..150", j.Jmin)
		}
		if j.Jmax > 1000 {
			t.Fatalf("Jmax = %d больше потолка 1000 (MTU боевых — 1280)", j.Jmax)
		}
		if err := jitterTripleErr(j.Jc, j.Jmin, j.Jmax); err != nil {
			t.Fatalf("сгенерированная тройка не проходит собственную проверку панели: %v (%+v)", err, j)
		}
	}
	if !sawJcMin {
		t.Error("за 300 прогонов Jc ни разу не оказался равен нижней границе 4 — " +
			"похоже на off-by-one в randRange, сужающий диапазон")
	}
	if !sawJcMax {
		t.Error("за 300 прогонов Jc ни разу не оказался равен верхней границе 7 — " +
			"похоже на off-by-one в randRange, сужающий диапазон")
	}
}

// TestGenerateJitterJminДостигаетКраёв — та же проверка достижимости, что и
// для Jc выше, но для Jmin отдельным тестом с бОльшим числом прогонов:
// диапазон Jmin шире (87 против 4 у Jc), и 300 прогонов, безопасных для
// Jc, для Jmin дают ощутимый шанс флака (см. комментарий у предыдущего
// теста). 20000 прогонов выбраны так, чтобы вероятность ни разу не
// встретить конкретную границу была пренебрежимо мала:
// (86/87)^20000 ≈ e^(-20000/87) ≈ e^-230 — на практике ноль, при этом
// цикл всё ещё укладывается в доли секунды (три обращения к crypto/rand на
// прогон).
func TestGenerateJitterJminДостигаетКраёв(t *testing.T) {
	const n = 20000
	sawMin, sawMax := false, false
	for i := 0; i < n; i++ {
		j, err := GenerateJitter(rand.Reader)
		if err != nil {
			t.Fatalf("прогон %d: %v", i, err)
		}
		if j.Jmin == 64 {
			sawMin = true
		}
		if j.Jmin == 150 {
			sawMax = true
		}
		if sawMin && sawMax {
			break // обе границы уже встретились — дальше прогонять незачем
		}
	}
	if !sawMin {
		t.Errorf("за %d прогонов Jmin ни разу не оказался равен нижней границе 50 — "+
			"похоже на off-by-one в randRange, сужающий диапазон", n)
	}
	if !sawMax {
		t.Errorf("за %d прогонов Jmin ни разу не оказался равен верхней границе 150 — "+
			"похоже на off-by-one в randRange, сужающий диапазон", n)
	}
}

// Генератор обязан быть функцией от источника, а не от глобального
// состояния: иначе его нечем проверить, кроме как гаданием по выборке.
//
// Байт для фиктивного источника — 0x00, а не что-то более «случайное» на
// вид: crypto/rand.Int делает rejection sampling (маскирует старший байт по
// битовой длине диапазона и перечитывает, пока значение не окажется меньше
// границы). Байт 0x07 здесь — неподвижная точка ровно для диапазона Jc
// (4..10, ширина 7, маска 0x07): 0x07&0x07 == 7 == max, отклоняется вечно,
// и на буфере 4096 повторов источник исчерпывается раньше, чем находится
// годное значение — GenerateJitter вернёт io.EOF, а не тройку (проверено
// прогоном: rand.Int с таким источником отдаёт <nil>, EOF, буфер пуст).
// 0x00 после маски всегда даёт 0, а 0 < max для любой ширины диапазона в
// этом файле — универсально безопасный фиксированный байт, не зависящий от
// конкретных границ Jc/Jmin/Jmax.
func TestGenerateJitterДетерминированПоИсточнику(t *testing.T) {
	src := func() *bytes.Reader { return bytes.NewReader(bytes.Repeat([]byte{0}, 4096)) }
	a, err := GenerateJitter(src())
	if err != nil {
		t.Fatalf("первый прогон: %v", err)
	}
	b, err := GenerateJitter(src())
	if err != nil {
		t.Fatalf("второй прогон: %v", err)
	}
	if a != b {
		t.Fatalf("один источник дал разные тройки: %+v и %+v", a, b)
	}
}

func TestGenerateJitterПустойИсточникЭтоОшибка(t *testing.T) {
	if _, err := GenerateJitter(bytes.NewReader(nil)); err == nil {
		t.Fatal("на исчерпанном источнике случайности ожидалась ошибка, её нет")
	}
}

// --- Задача 9: комплект параметров обфускации для НОВОГО интерфейса ---

// TestGenerateInterfaceParamsИнварианты прогоняет генератор 300 раз и
// проверяет КАЖДОЕ жёсткое правило раздела 6.1 спеки 2026-08-24 на каждом
// выпуске. Однократной проверки здесь недостаточно принципиально: генератор
// случаен, и ошибка в границе одного из восьми диапазонов проявляется не на
// каждом прогоне, а на доле прогонов — единственный вызов прошёл бы мимо
// неё с вероятностью, близкой к единице.
func TestGenerateInterfaceParamsИнварианты(t *testing.T) {
	for i := 0; i < 300; i++ {
		p, err := GenerateInterfaceParams(rand.Reader, MimicryQUIC)
		if err != nil {
			t.Fatalf("прогон %d: %v", i, err)
		}
		for name, v := range map[string]int{"S1": p.S1, "S2": p.S2, "S3": p.S3, "S4": p.S4} {
			if v < 12 {
				t.Fatalf("%s = %d < 12: при заданном HeaderProtectionKey это не работает", name, v)
			}
		}
		if p.S1 > 64 || p.S2 > 64 || p.S3 > 64 {
			t.Fatalf("S1..S3 вне 12..64: %+v", p)
		}
		if p.S4 > 32 {
			t.Fatalf("S4 = %d > 32: он падит каждый транспортный пакет", p.S4)
		}
		if p.S1+56 == p.S2 {
			t.Fatalf("S1+56 == S2 (%d): init и response совпадут по длине", p.S2)
		}
		hs := []HRange{p.H1, p.H2, p.H3, p.H4}
		for a := range hs {
			if hs[a].Lo < 5 {
				t.Fatalf("H%d начинается с %d < 5: столкнётся со стандартным типом пакета WireGuard", a+1, hs[a].Lo)
			}
			if hs[a].Hi > 2147483647 {
				t.Fatalf("H%d кончается на %d выше INT32_MAX", a+1, hs[a].Hi)
			}
			if hs[a].Lo >= hs[a].Hi {
				t.Fatalf("H%d = %s — полоса нулевой или отрицательной ширины", a+1, hs[a])
			}
			for b := a + 1; b < len(hs); b++ {
				if hs[a].Lo <= hs[b].Hi && hs[b].Lo <= hs[a].Hi {
					t.Fatalf("H%d = %s и H%d = %s пересекаются — сервер отвергнет такой конфиг на старте",
						a+1, hs[a], b+1, hs[b])
				}
			}
		}
		key, err := base64.StdEncoding.DecodeString(p.HeaderProtectionKey)
		if err != nil {
			t.Fatalf("HeaderProtectionKey не base64: %q", p.HeaderProtectionKey)
		}
		if len(key) != 32 {
			t.Fatalf("HeaderProtectionKey декодировался в %d байт, ожидалось 32", len(key))
		}
		if !strings.HasPrefix(p.ContentPaddingAddition, "0-") {
			t.Fatalf("ContentPaddingAddition = %q, ожидался вид 0-N", p.ContentPaddingAddition)
		}
	}
}

// TestHПолосыНеПересекаются — прямой страж ключевого инварианта раздела 6
// брифа задачи 1: сервер отвергает пересекающиеся полосы H1..H4 на старте, и
// генератор, способный такое выдать, был бы генератором нерабочих конфигов.
// hRanges строит полосы непересекающимися ПО ПОСТРОЕНИЮ (см. её комментарий),
// но проверка всё равно нужна как страж на случай, если способ построения
// когда-нибудь заменят.
func TestHПолосыНеПересекаются(t *testing.T) {
	for i := 0; i < 300; i++ {
		p, err := GenerateInterfaceParams(rand.Reader, MimicryQUIC)
		if err != nil {
			t.Fatalf("прогон %d: %v", i, err)
		}
		hs := []HRange{p.H1, p.H2, p.H3, p.H4}
		for a := range hs {
			if hs[a].Lo < 5 {
				t.Fatalf("H%d начинается с %d — ниже 5, столкнётся с типом пакета WireGuard", a+1, hs[a].Lo)
			}
			if hs[a].Hi > 2147483647 {
				t.Fatalf("H%d кончается на %d — выше INT32_MAX", a+1, hs[a].Hi)
			}
			if hs[a].Lo >= hs[a].Hi {
				t.Fatalf("H%d = %s — полоса нулевой или отрицательной ширины", a+1, hs[a])
			}
			for b := a + 1; b < len(hs); b++ {
				if hs[a].Lo <= hs[b].Hi && hs[b].Lo <= hs[a].Hi {
					t.Fatalf("H%d = %s и H%d = %s пересекаются — сервер отвергнет такой конфиг на старте",
						a+1, hs[a], b+1, hs[b])
				}
			}
		}
	}
}

// TestHПолосыВарьируютсяОтПрогонаКПрогону — находка финального ревью
// (Important #2). TestHПолосыНеПересекаются выше и инварианты в
// TestGenerateInterfaceParamsИнварианты проверяют только СТРУКТУРНЫЕ
// свойства (непересечение, границы, положительная ширина) — они выполняются
// и для генератора, который каждый раз возвращает одни и те же четыре
// полосы, или полосы шириной 1 (Lo = Hi - 1). Ради переменности эта задача
// вообще затевалась (см. комментарий HRange: одиночное значение — отпечаток
// сервера, полоса нужна ровно затем, чтобы значение МЕНЯЛОСЬ), а нигде в
// файле это до сих пор не проверялось.
//
// N = 50 выбрано по самому узкому месте проверки: диапазон стартов H1.Lo —
// randRange(rnd, lo, hi-width) внутри первой четверти пространства значений
// (lo=5, hi≈536 870 909), а width ∈ [50 000 000, 400 000 000], то есть даже
// при максимальном width диапазон стартов не уже примерно 136 млн
// значений. Вероятность коллизии (ни разу не увидеть второе значение
// H1.Lo) на 50 независимых прогонах по оценке из парадокса дней рождения
// ничтожна даже для диапазона на пять порядков уже — риска флака здесь нет.
func TestHПолосыВарьируютсяОтПрогонаКПрогону(t *testing.T) {
	const n = 50
	// Минимумы РАЗНЫЕ, потому что разные и назначения полос: у H4 ширина
	// бесплатна и остаётся большой, у H1..H3 она ограничена сверху ценой в
	// молча теряемые пакеты (см. TestПолосыH1H3УзкиеИначеТеряютсяПакеты).
	// Здесь проверяется только НИЖНЯЯ граница — что полоса не выродилась в
	// одиночное значение, ради чего задача и затевалась.
	const minWidthH4 = 50_000_000
	const minWidthH1H3 = 10_000
	lo1 := map[uint32]bool{}
	for i := 0; i < n; i++ {
		p, err := GenerateInterfaceParams(rand.Reader, MimicryQUIC)
		if err != nil {
			t.Fatalf("прогон %d: %v", i, err)
		}
		lo1[p.H1.Lo] = true
		for name, hr := range map[string]HRange{"H1": p.H1, "H2": p.H2, "H3": p.H3, "H4": p.H4} {
			minWidth := uint32(minWidthH1H3)
			if name == "H4" {
				minWidth = minWidthH4
			}
			if width := hr.Hi - hr.Lo; width < minWidth {
				t.Fatalf("прогон %d: %s = %s шириной %d — меньше документированного минимума %d "+
					"(регрессия вроде Lo = Hi - 1 прошла бы мимо всех структурных проверок файла)",
					i, name, hr, width, minWidth)
			}
		}
	}
	if len(lo1) < 2 {
		t.Fatalf("за %d прогонов H1.Lo ни разу не изменился (встречено значений: %d) — генератор мог "+
			"начать возвращать четыре фиксированные полосы: структурные проверки (непересечение, "+
			"границы, положительная ширина) такую регрессию не ловят", n, len(lo1))
	}
}

// TestПолосыH1H3УзкиеИначеТеряютсяПакеты — страж от дефекта, найденного на
// боевом эталоне awgref 25.08.2026: клиент терял 16.9 % транспортных пакетов
// в КАЖДУЮ сторону, а сервер при этом показывал ноль ошибок, ноль дропов
// UDP-сокета и 0.2 % CPU.
//
// Механизм — amneziawg-go v3.1.20260812, device/receive.go,
// DeterminePacketTypeAndPadding. Классификатор перебирает типы в порядке
// init → response → cookie → transport, и у первых трёх веток условие:
//
//	if size == expectedSize || randomTrailers && size > expectedSize {
//	    applyHash(headerBytes[:], packet[padding:padding+4], typeHash)
//	    if header.Contains(binary.LittleEndian.Uint32(headerBytes[:])) { ... }
//	}
//
// При RandomTrailers = off отбор строгий, и транспорт на эти ветки почти не
// попадает. При RandomTrailers = on второй дизъюнкт обнуляет отбор по
// размеру: КАЖДЫЙ транспортный пакет крупнее S1+148 примеряется к H1, H2 и
// H3. Проверяются 4 байта по смещению S1/S2/S3 — у транспортного пакета там
// либо случайный префикс S4, либо шифротекст, то есть равномерный шум, а
// UintRange.Contains (device/noise-types.go) — это попадание в полосу.
// Пойманный пакет уходит в очередь рукопожатий и умирает на CheckMAC1 с
// логом уровня Verbosef, то есть молча и без единого счётчика.
//
// Отсюда доля молча теряемых пакетов = (W1+W2+W3)/2³², где W = Hi-Lo+1.
// H4 в сумму НЕ входит: ветка transport проверяется последней и смотрит
// только на него — его ширина ничего не стоит, см. TestПолосаH4ОстаётсяШирокой.
//
// Спека 2026-08-24 задаёт H диапазонами как признак AWG 2.0, и этот тест их
// не отменяет, а ограничивает СВЕРХУ. Канонический образец протокола
// (H1 = 666067622-666092814) шириной 25 192 в порог укладывается с запасом:
// настоящие генераторы делают полосы узкими, широкими их сделали мы.
func TestПолосыH1H3УзкиеИначеТеряютсяПакеты(t *testing.T) {
	// 1e-4 — один пакет на десять тысяч, ниже фонового уровня потерь любого
	// реального канала, то есть для TCP заведомо незаметно.
	const limit = 1e-4
	const runs = 50
	for i := 0; i < runs; i++ {
		p, err := GenerateInterfaceParams(rand.Reader, MimicryQUIC)
		if err != nil {
			t.Fatalf("прогон %d: %v", i, err)
		}
		sum := uint64(p.H1.Hi-p.H1.Lo) + uint64(p.H2.Hi-p.H2.Lo) + uint64(p.H3.Hi-p.H3.Lo) + 3
		share := float64(sum) / float64(uint64(1)<<32)
		if share > limit {
			t.Fatalf("прогон %d: суммарная ширина H1..H3 = %d, это %.4f%% транспортных пакетов, "+
				"молча теряемых приёмником при RandomTrailers = on (порог %.4f%%). H1 = %s, H2 = %s, H3 = %s",
				i, sum, share*100, limit*100, p.H1, p.H2, p.H3)
		}
	}
}

// TestПолосаH4ОстаётсяШирокой — обратная сторона предыдущего теста. Сузить
// заодно и H4 было бы проще, но неправильно: транспортных пакетов 99.9 %
// потока, именно их тип наблюдатель видит чаще всего, и энтропия нужна
// прежде всего там. А стоит она там ноль: ветка transport в
// DeterminePacketTypeAndPadding проверяется ПОСЛЕДНЕЙ и ни с одной другой
// полосой не конкурирует.
func TestПолосаH4ОстаётсяШирокой(t *testing.T) {
	const minWidth = 50_000_000
	for i := 0; i < 20; i++ {
		p, err := GenerateInterfaceParams(rand.Reader, MimicryQUIC)
		if err != nil {
			t.Fatalf("прогон %d: %v", i, err)
		}
		if w := p.H4.Hi - p.H4.Lo; w < minWidth {
			t.Fatalf("прогон %d: H4 = %s шириной %d — уже %d. Ширина H4 бесплатна "+
				"(см. TestПолосыH1H3УзкиеИначеТеряютсяПакеты), сужать её незачем", i, p.H4, w, minWidth)
		}
	}
}

// TestSizesCollideЛовитВсеТриПары — прямая проверка правила, а не его следствий.
//
// Паддинг S1..S3 ставится ровно затем, чтобы три типа сообщений различались
// ПО ДЛИНЕ: наблюдателю, считающему длины, иначе не нужно ничего расшифровывать,
// чтобы отличить рукопожатие от cookie. Длины до паддинга — 148 (initiation),
// 92 (response), 64 (cookie reply), и правил, стало быть, три:
//
//	148+S1 != 92+S2   →  S2 != S1 + 56
//	148+S1 != 64+S3   →  S3 != S1 + 84
//	 92+S2 != 64+S3   →  S3 != S2 + 28
//
// До 25.08.2026 в файле жило только первое, и именно оно в коридоре 12..64
// сработать НЕ МОЖЕТ (S1+56 >= 68 > 64 >= S2) — то есть проверялось ровно то,
// что и так выполняется, а достижимое третье не проверялось вовсе.
//
// Правило выражено через сами длины, а не через три вынесенных смещения, и это
// намеренно: Any-Tech-ARCHITECT (MIT, Vadim Khristenko) поймал у себя ровно эту
// ошибку — два смещения из трёх были записаны неверно, инструмент предупреждал
// о паре, которая совпасть не может, и молчал о реальной (их issue #7).
// Смещение можно списать, разность длин — нет.
func TestSizesCollideЛовитВсеТриПары(t *testing.T) {
	cases := []struct {
		name       string
		s1, s2, s3 int
		collide    bool
	}{
		{"чисто — значения боевого awgref", 18, 47, 17, false},
		{"init против response: S2 = S1+56", 12, 68, 17, true},
		{"init против cookie: S3 = S1+84", 12, 47, 96, true},
		{"response против cookie: S3 = S2+28", 18, 20, 48, true},
		{"все три совпали", 12, 68, 96, true},
	}
	for _, c := range cases {
		if got := sizesCollide(c.s1, c.s2, c.s3); got != c.collide {
			t.Errorf("%s: sizesCollide(%d, %d, %d) = %v, ожидалось %v (длины %d / %d / %d)",
				c.name, c.s1, c.s2, c.s3, got, c.collide,
				msgInitiationSize+c.s1, msgResponseSize+c.s2, msgCookieSize+c.s3)
		}
	}
}

// TestГенераторНеВыдаётСовпадающихДлин — страж на самом генераторе.
//
// Достижимо в коридоре 12..64 только третье правило (S3 = S2 + 28): S2 из
// [12,36] даёт S2+28 внутри диапазона S3, вероятность около 0.89 % на выпуск.
// На 5000 прогонах генератор без правила даёт порядка сорока коллизий, с
// правилом — ноль. Прогонов много именно поэтому: сотней тест бы не поймал.
func TestГенераторНеВыдаётСовпадающихДлин(t *testing.T) {
	const runs = 5000
	bad := 0
	var first InterfaceParams
	for i := 0; i < runs; i++ {
		p, err := GenerateInterfaceParams(rand.Reader, MimicryQUIC)
		if err != nil {
			t.Fatalf("прогон %d: %v", i, err)
		}
		if sizesCollide(p.S1, p.S2, p.S3) {
			if bad == 0 {
				first = p
			}
			bad++
		}
	}
	if bad != 0 {
		t.Fatalf("на %d прогонов %d конфигов с совпадающими длинами сообщений; первый: "+
			"S1=%d S2=%d S3=%d → длины %d / %d / %d", runs, bad, first.S1, first.S2, first.S3,
			msgInitiationSize+first.S1, msgResponseSize+first.S2, msgCookieSize+first.S3)
	}
}

func TestHRangeПечатаетсяКакДиапазон(t *testing.T) {
	if got := (HRange{Lo: 5, Hi: 100}).String(); got != "5-100" {
		t.Fatalf("String() = %q, ожидалось \"5-100\"", got)
	}
}

// Страж: комплект, подставленный в [Interface], обязан проходить тот же
// путь, которым панель выпускает конфиги. Без этого генератор и выпуск
// разъедутся молча — ровно тот класс ошибки, за который в этом репозитории
// уже платили.
func TestСгенерированныйКомплектПроходитВыпуск(t *testing.T) {
	p, err := GenerateInterfaceParams(rand.Reader, MimicryQUIC)
	if err != nil {
		t.Fatalf("генерация: %v", err)
	}
	// ListenPort с задачи 5 (спека 2026-08-25, раздел 5.7) печатает сам
	// ServerBlock() — заголовок [Interface] здесь больше не несёт его вручную,
	// иначе ключ ListenPort повторился бы в тексте дважды.
	p.ListenPort = 51820
	conf, err := wgconf.Parse("[Interface]\nPrivateKey = aaa=\n" + p.ServerBlock())
	if err != nil {
		t.Fatalf("разбор сгенерированного [Interface]: %v", err)
	}
	obf, err := ExtractObfuscation(conf.Interface)
	if err != nil {
		t.Fatalf("ExtractObfuscation на сгенерированном комплекте: %v", err)
	}
	out, err := RenderClientConfig(ClientParams{
		PrivateKey: "priv=", Address: "10.0.0.2/32", ServerPublicKey: "pub=",
		Endpoint: "1.2.3.4:51820", AllowedIPs: "0.0.0.0/0",
		Obfuscation: obf,
		Jc:          p.Jitter.Jc, Jmin: p.Jitter.Jmin, Jmax: p.Jitter.Jmax,
	})
	if err != nil {
		t.Fatalf("RenderClientConfig на сгенерированном комплекте: %v", err)
	}
	if !strings.Contains(out, "HeaderProtectionKey = "+p.HeaderProtectionKey) {
		t.Fatal("ключ защиты заголовка не доехал до клиентского конфига")
	}
}

// TestServerBlockНесётВсеОбязательныеПоля — прямой страж расхождения
// генератора со списком RequiredObfuscationKeys (client.go). Предыдущий тест
// ловит это же расхождение через ExtractObfuscation, но только пока список
// обязательных полей и список печатаемых совпадают по составу; если завтра к
// RequiredObfuscationKeys добавят поле, а сюда забудут, разница будет видна
// именно здесь и с именем поля в тексте отказа.
func TestServerBlockНесётВсеОбязательныеПоля(t *testing.T) {
	p, err := GenerateInterfaceParams(rand.Reader, MimicryQUIC)
	if err != nil {
		t.Fatalf("генерация: %v", err)
	}
	block := p.ServerBlock()
	for _, k := range RequiredObfuscationKeys {
		if !strings.Contains(block, k+" = ") {
			t.Errorf("в блоке для [Interface] нет обязательного поля %s: %q", k, block)
		}
	}
}

// TestServerBlockДетерминирован — порядок печати фиксирован списком, а не
// обходом карты: один и тот же комплект обязан давать один и тот же текст,
// иначе оператор, сравнивающий две выдачи глазами, видит разницу там, где её
// нет. Заодно фиксируется сам порядок полей: ListenPort, S1..S4, H1..H4,
// ключ, паддинг, флаги 3.1. ListenPort первым — раздел 5.7 спеки 2026-08-25 (задача 5):
// оператор, поднимающий новый туннель, первым делом открывает порт.
func TestServerBlockДетерминирован(t *testing.T) {
	p := InterfaceParams{
		ListenPort: 443,
		S1:         13, S2: 14, S3: 15, S4: 16,
		H1: HRange{Lo: 17, Hi: 170}, H2: HRange{Lo: 18, Hi: 180},
		H3: HRange{Lo: 19, Hi: 190}, H4: HRange{Lo: 20, Hi: 200},
		HeaderProtectionKey:    "0123456789abcdef0123456789abcdef0123456789ab",
		ContentPaddingAddition: "0-96",
		Jitter:                 Jitter{Jc: 5, Jmin: 60, Jmax: 400},
	}
	want := "ListenPort = 443\n" +
		"S1 = 13\nS2 = 14\nS3 = 15\nS4 = 16\n" +
		"H1 = 17-170\nH2 = 18-180\nH3 = 19-190\nH4 = 20-200\n" +
		"HeaderProtectionKey = 0123456789abcdef0123456789abcdef0123456789ab\n" +
		"ContentPaddingAddition = 0-96\n" +
		"RandomTrailers = on\nDisableCookies = on\n"
	if got := p.ServerBlock(); got != want {
		t.Fatalf("текст блока разошёлся с ожидаемым:\n--- получено ---\n%s\n--- ожидалось ---\n%s", got, want)
	}
	if p.ServerBlock() != p.ServerBlock() {
		t.Fatal("два вызова на одном комплекте дали разный текст")
	}
	// Джиттер в блок НЕ попадает: сервер о Jc/Jmin/Jmax не знает вовсе
	// (см. комментарий к типу Jitter), и строка «Jc = 5» в серверном
	// [Interface] была бы мусором.
	for _, k := range []string{"Jc", "Jmin", "Jmax"} {
		if strings.Contains(p.ServerBlock(), k+" = ") {
			t.Errorf("клиентское поле %s попало в блок серверного [Interface]", k)
		}
	}
}

// TestGenerateInterfaceParamsПустойИсточникЭтоОшибка — глобальное
// ограничение задачи: ошибка чтения источника случайности обязана вернуться
// ошибкой, а не «комплектом» на нулевых байтах. Параметры обфускации,
// собранные из нулей, обфускацией не являются, но выглядят как настоящие.
func TestGenerateInterfaceParamsПустойИсточникЭтоОшибка(t *testing.T) {
	if _, err := GenerateInterfaceParams(bytes.NewReader(nil), MimicryQUIC); err == nil {
		t.Fatal("на исчерпанном источнике случайности ожидалась ошибка, её нет")
	}
}

// TestInterfaceParamsНеУмеетПрименяться — исполняемая формулировка правила 2
// репозитория для этой задачи: у типа не должно появиться ни одного
// ЭКСПОРТИРОВАННОГО метода, кроме рендера в строку. Проверка по списку имён,
// а не по «нет метода с именем Apply»: запрет по чёрному списку обходится
// переименованием, а белый список из одного имени ломается на любом
// добавленном экспортированном методе — в том числе на MarshalJSON или
// String, которые сами по себе безобидны, но заставляют автора правки
// прочитать этот комментарий и объяснить, почему новый метод ничего не
// пишет.
//
// Уточнение (ревью задачи 9): reflect.Type.NumMethod/Method видят ТОЛЬКО
// экспортированные методы — это задокументированное поведение пакета
// reflect, а не недосмотр здесь. Неэкспортированный метод вроде apply() у
// InterfaceParams или свободная функция в этом же пакете, принимающая
// InterfaceParams параметром и пишущая им в файл, этим тестом не ловятся
// вовсе. От такого обхода тест сознательно не защищает: гарантию для него
// несут снимок каталога (диff правки виден на ревью — код, пишущий в
// awg3.conf, не заводится незаметно) и то, что у InterfaceParams сегодня нет
// ни одного потребителя за пределами generate.go и этого файла. Тест здесь
// закрывает конкретно тот путь, каким «применение» обычно и просачивается
// внутрь типа: метод с понятным публичным именем вроде Apply, Save или
// WriteTo — этого достаточно, чтобы поймать самое вероятное направление
// правки, не обещая большего, чем reflect способен дать.
func TestInterfaceParamsНеУмеетПрименяться(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeOf(InterfaceParams{}),
		reflect.TypeOf(&InterfaceParams{}),
	} {
		var names []string
		for i := 0; i < typ.NumMethod(); i++ {
			names = append(names, typ.Method(i).Name)
		}
		if len(names) != 1 || names[0] != "ServerBlock" {
			t.Errorf("%s: набор методов = %v, ожидался ровно [ServerBlock] — "+
				"комплект печатается текстом и накатывается оператором руками; "+
				"кода, способного изменить серверный [Interface], в этом репозитории не существует "+
				"(правило 2 CLAUDE.md)", typ, names)
		}
	}
}

// --- Задача 2: три сборщика сигнатурных пакетов (спека 2026-08-25, разделы 5.2-5.4) ---

// decodeTags разворачивает строку тегов сигнатурного пакета в сырые байты:
// `<b 0xHEX>` даёт сами байты, `<r N>` — N нулей-заглушек. Это ровно то, что
// делает настоящий amneziawg-go при отправке пакета: `<b ...>` печатает
// буквально, `<r N>` заменяет на N случайных байт заново для КАЖДОЙ отправки.
// Для структурной проверки заглушки достаточно — важно место и длина, а не
// содержимое; проверить содержимое случайных частей этим помощником нельзя,
// и тесты ниже на это не претендуют.
//
// Общий для всех трёх профилей: написан один раз, используется в тестах
// QUIC, DNS и STUN — иначе три копии одного и того же разбора тегов
// разошлись бы при первой же правке формата.
func decodeTags(t *testing.T, s string) []byte {
	t.Helper()
	var out []byte
	for len(s) > 0 {
		if s[0] != '<' {
			t.Fatalf("ожидался тег, начинающийся с '<': %q (остаток %q)", s, s)
		}
		end := strings.IndexByte(s, '>')
		if end < 0 {
			t.Fatalf("незакрытый тег в %q", s)
		}
		tag := s[1:end]
		s = s[end+1:]
		switch {
		case strings.HasPrefix(tag, "r "):
			n, err := strconv.Atoi(strings.TrimSpace(tag[2:]))
			if err != nil {
				t.Fatalf("тег <r ...>: %q не число: %v", tag, err)
			}
			out = append(out, make([]byte, n)...)
		case strings.HasPrefix(tag, "b 0x"):
			b, err := hex.DecodeString(tag[4:])
			if err != nil {
				t.Fatalf("тег <b 0x...>: %q не hex: %v", tag, err)
			}
			out = append(out, b...)
		default:
			t.Fatalf("неизвестный тег %q", tag)
		}
	}
	return out
}

// TestQUICПрофильСтруктура разбирает клиентский Initial ВПЕРЁД от первого
// байта (RFC 9000 §17.2.2), а не индексацией с конца — индексация с конца
// вернула бы правдоподобные значения даже из пакета со сломанным varint
// длины, и именно на этом уже обжигались в прошлой работе над этим файлом
// (см. историю decodeSignatureTTL/decodeSignatureAddr выше по репозиторию).
func TestQUICПрофильСтруктура(t *testing.T) {
	for i := 0; i < 100; i++ {
		s, err := GenerateSignatureFor(rand.Reader, MimicryQUIC)
		if err != nil {
			t.Fatalf("прогон %d: %v", i, err)
		}
		raw := decodeTags(t, s)
		if len(raw) < 1200 {
			t.Fatalf("прогон %d: датаграмма %d байт — RFC 9000 §14.1 требует от клиентского Initial не меньше 1200", i, len(raw))
		}
		// &0xf0 == 0xc0, а не &0xc0 == 0xc0: проверка на два верхних бита одна
		// пропускает 0-RTT (0xd_), Handshake (0xe_) и Retry (0xf_) — любой из
		// них проходил бы этот тест, пока не сломан минимум 1200 байт или
		// нулевая длина токена, хотя вся структура и обоснование этой
		// функции (см. её doc-комментарий) — конкретно про Initial. Полный
		// полубайт ловит это на месте: Long Packet Type (биты 5-4, RFC 9000
		// §17.2) для Initial обязан быть 00, то есть верхний полубайт
		// целиком — 0xc.
		if raw[0]&0xf0 != 0xc0 {
			t.Fatalf("прогон %d: первый байт %#x — не Initial (RFC 9000 §17.2.2)", i, raw[0])
		}
		if v := binary.BigEndian.Uint32(raw[1:5]); v != 1 {
			t.Fatalf("прогон %d: версия %#x, ожидалась 1", i, v)
		}
		pos := 5
		dl := int(raw[pos])
		pos += 1 + dl
		sl := int(raw[pos])
		pos += 1 + sl
		if raw[pos] != 0x00 {
			t.Fatalf("прогон %d: длина токена %#x, у клиентского Initial ожидался ноль", i, raw[pos])
		}
		pos++
		ln := int(binary.BigEndian.Uint16(raw[pos:pos+2]) & 0x3fff)
		pos += 2
		if ln != len(raw)-pos {
			t.Fatalf("прогон %d: varint длины говорит %d, после него реально %d байт", i, ln, len(raw)-pos)
		}
	}
}

// TestQUICПрофильДлинаМеняется — изменчивость (шаг 4 брифа): длина полезной
// нагрузки — единственная величина, зависящая от источника случайности,
// которая доступна из decodeTags без расшифровки самих `<r N>`-заглушек
// (идентификаторы соединения decodeTags отдаёт нулями специально, их
// изменчивость проверить этим помощником нельзя — только их место и длину,
// см. её комментарий).
func TestQUICПрофильДлинаМеняется(t *testing.T) {
	const n = 40
	lens := map[int]bool{}
	for i := 0; i < n; i++ {
		s, err := GenerateSignatureFor(rand.Reader, MimicryQUIC)
		if err != nil {
			t.Fatalf("прогон %d: %v", i, err)
		}
		raw := decodeTags(t, s)
		lens[len(raw)] = true
	}
	if len(lens) < 2 {
		t.Errorf("за %d прогонов длина датаграммы ни разу не изменилась — PADDING сверх минимума не варьируется", n)
	}
}

// TestSTUNПрофильСтруктура проверяет Binding Request (RFC 5389 §6) плюс
// атрибут SOFTWARE (§15.10), добавленный поверх раздела 5.4 спеки по прямому
// указанию: голый заголовок без атрибутов — 20 байт, что короче порога в 32
// байта из официальной статьи Amnezia про мимикрию (сигнатура короче 32
// байт — примета сама по себе), и вдобавок нереалистично — настоящий
// STUN-запрос клиента WebRTC почти никогда не бывает без атрибутов.
func TestSTUNПрофильСтруктура(t *testing.T) {
	for i := 0; i < 100; i++ {
		s, err := GenerateSignatureFor(rand.Reader, MimicrySTUN)
		if err != nil {
			t.Fatalf("прогон %d: %v", i, err)
		}
		raw := decodeTags(t, s)
		if len(raw) <= 32 {
			t.Fatalf("прогон %d: пакет %d байт — не длиннее порога в 32 байта из статьи Amnezia про мимикрию", i, len(raw))
		}
		if binary.BigEndian.Uint16(raw[0:2]) != 0x0001 {
			t.Fatalf("прогон %d: тип не Binding Request", i)
		}
		// Поле длины сообщения обязано равняться числу байт ПОСЛЕ 20-байтового
		// заголовка (RFC 5389 §6) — то есть всему атрибуту SOFTWARE целиком,
		// включая паддинг. Та же проверка «varint/поле длины совпадает с
		// остатком», что у QUIC, только для STUN.
		msgLen := int(binary.BigEndian.Uint16(raw[2:4]))
		if msgLen != len(raw)-20 {
			t.Fatalf("прогон %d: поле длины сообщения = %d, реально после заголовка %d байт", i, msgLen, len(raw)-20)
		}
		if binary.BigEndian.Uint32(raw[4:8]) != 0x2112a442 {
			t.Fatalf("прогон %d: нет магического печенья 0x2112a442 — это не STUN", i)
		}
		// Атрибут SOFTWARE: тип 0x8022, длина значения БЕЗ паддинга, значение
		// дополнено нулями до кратности 4 (RFC 5389 §15).
		pos := 20
		if pos+4 > len(raw) {
			t.Fatalf("прогон %d: пакет длиной %d короче заголовка атрибута", i, len(raw))
		}
		if attrType := binary.BigEndian.Uint16(raw[pos : pos+2]); attrType != 0x8022 {
			t.Fatalf("прогон %d: тип атрибута %#x, ожидался SOFTWARE 0x8022", i, attrType)
		}
		attrLen := int(binary.BigEndian.Uint16(raw[pos+2 : pos+4]))
		pos += 4
		padded := attrLen
		if r := padded % 4; r != 0 {
			padded += 4 - r
		}
		if pos+padded != len(raw) {
			t.Fatalf("прогон %d: атрибут длиной %d (дополнено до %d) не сходится с концом пакета длиной %d на смещении %d",
				i, attrLen, padded, len(raw), pos)
		}
	}
}

// TestSTUNПрофильАтрибутМеняется — изменчивость: имя SOFTWARE выбирается из
// списка правдоподобных клиентов WebRTC случайно при каждой генерации.
func TestSTUNПрофильАтрибутМеняется(t *testing.T) {
	const n = 40
	values := map[string]bool{}
	for i := 0; i < n; i++ {
		s, err := GenerateSignatureFor(rand.Reader, MimicrySTUN)
		if err != nil {
			t.Fatalf("прогон %d: %v", i, err)
		}
		raw := decodeTags(t, s)
		attrLen := int(binary.BigEndian.Uint16(raw[22:24]))
		values[string(raw[24:24+attrLen])] = true
	}
	if len(values) < 2 {
		t.Errorf("за %d прогонов значение SOFTWARE ни разу не изменилось (%v) — генератор его не варьирует", n, values)
	}
}

// TestDNSПрофильЭтоЗапросАНеОтвет — клиент шлёт СЕРВЕРУ, а в эту сторону
// летят запросы. Ответ от клиента — сочетание, которого в настоящем трафике
// не бывает; часть промышленных межсетевых экранов сопоставляет
// идентификаторы транзакций (DNS Query Response Matching, "DNS guard") и
// отбрасывает непрошеные ответы.
//
// Флаги проверяются со смещения 2, а не 0: первые два байта настоящего
// DNS-пакета (RFC 1035 §4.1.1) — transaction ID, и он ОБЯЗАН идти первым на
// проводе, иначе пакет невалиден как DNS вообще, вне зависимости от
// содержимого остальных полей. decodeTags отдаёт для `<r 2>` два нулевых
// байта-заглушки (его случайное содержимое этим помощником не проверяется,
// см. её комментарий), поэтому raw[0:2] здесь не читается.
func TestDNSПрофильЭтоЗапросАНеОтвет(t *testing.T) {
	s, err := GenerateSignatureFor(rand.Reader, MimicryDNS)
	if err != nil {
		t.Fatal(err)
	}
	raw := decodeTags(t, s)
	if flags := binary.BigEndian.Uint16(raw[2:4]); flags != 0x0100 {
		t.Fatalf("флаги %#x, ожидались 0x0100 (стандартный запрос)", flags)
	}
	if an := binary.BigEndian.Uint16(raw[6:8]); an != 0 {
		t.Fatalf("ancount = %d, у запроса ответов быть не может", an)
	}
}

// TestDNSПрофильСтруктура разбирает запрос целиком ВПЕРЁД от первого байта:
// 12-байтовый заголовок (ID, флаги, четыре COUNT), затем QNAME по меткам
// до нулевого терминатора, затем QTYPE/QCLASS — и, главное, что после этого
// в пакете не остаётся ни одного лишнего байта (секции ответа быть не
// должно вовсе, а не просто ANCOUNT=0 при мусорном хвосте).
func TestDNSПрофильСтруктура(t *testing.T) {
	for i := 0; i < 100; i++ {
		s, err := GenerateSignatureFor(rand.Reader, MimicryDNS)
		if err != nil {
			t.Fatalf("прогон %d: %v", i, err)
		}
		raw := decodeTags(t, s)
		if len(raw) < 12 {
			t.Fatalf("прогон %d: пакет %d байт короче DNS-заголовка", i, len(raw))
		}
		if flags := binary.BigEndian.Uint16(raw[2:4]); flags != 0x0100 {
			t.Fatalf("прогон %d: флаги %#x, ожидались 0x0100", i, flags)
		}
		if qd := binary.BigEndian.Uint16(raw[4:6]); qd != 1 {
			t.Fatalf("прогон %d: qdcount = %d, ожидался 1", i, qd)
		}
		for _, off := range []int{6, 8, 10} { // ancount, nscount, arcount
			if v := binary.BigEndian.Uint16(raw[off : off+2]); v != 0 {
				t.Fatalf("прогон %d: счётчик на смещении %d = %d, ожидался 0 — у запроса секций ответа нет", i, off, v)
			}
		}
		pos := 12
		for {
			if pos >= len(raw) {
				t.Fatalf("прогон %d: QNAME вышло за пределы пакета длиной %d", i, len(raw))
			}
			n := int(raw[pos])
			pos++
			if n == 0 {
				break
			}
			if pos+n > len(raw) {
				t.Fatalf("прогон %d: метка длиной %d на смещении %d выходит за пределы пакета", i, n, pos)
			}
			pos += n
		}
		if pos+4 != len(raw) {
			t.Fatalf("прогон %d: после QNAME ожидалось ровно 4 байта QTYPE/QCLASS и конец пакета, "+
				"а реально %d байт (пакет длиной %d, QNAME кончается на %d)", i, len(raw)-pos, len(raw), pos)
		}
		if !bytes.Equal(raw[pos:pos+4], []byte{0x00, 0x01, 0x00, 0x01}) {
			t.Fatalf("прогон %d: QTYPE/QCLASS = % x, ожидалось 00 01 00 01 (A/IN)", i, raw[pos:pos+4])
		}
	}
}

// TestDNSПрофильИмяМеняется — изменчивость: доменное имя в QNAME выбирается
// случайно при каждой генерации из signatureDomains.
func TestDNSПрофильИмяМеняется(t *testing.T) {
	const n = 40
	names := map[string]bool{}
	for i := 0; i < n; i++ {
		s, err := GenerateSignatureFor(rand.Reader, MimicryDNS)
		if err != nil {
			t.Fatalf("прогон %d: %v", i, err)
		}
		raw := decodeTags(t, s)
		var labels []string
		pos := 12
		for {
			ln := int(raw[pos])
			pos++
			if ln == 0 {
				break
			}
			labels = append(labels, string(raw[pos:pos+ln]))
			pos += ln
		}
		names[strings.Join(labels, ".")] = true
	}
	if len(names) < 2 {
		t.Errorf("за %d прогонов доменное имя ни разу не изменилось (%v) — генератор его не варьирует", n, names)
	}
}

// Панель обязана принять собственный вывод: все три профиля уезжают в extra
// клиентского конфига.
func TestСигнатурныйПакетПроходитValidateExtra(t *testing.T) {
	for _, p := range []MimicryProfile{MimicryQUIC, MimicryDNS, MimicrySTUN} {
		s, err := GenerateSignatureFor(rand.Reader, p)
		if err != nil {
			t.Fatalf("профиль %q: %v", p, err)
		}
		if err := ValidateExtra(map[string]string{"I1": s}); err != nil {
			t.Fatalf("профиль %q: панель не принимает собственный сигнатурный пакет: %v", p, err)
		}
	}
}

func TestСигнатурныйПакетПустойИсточникЭтоОшибка(t *testing.T) {
	for _, p := range []MimicryProfile{MimicryQUIC, MimicryDNS, MimicrySTUN} {
		if _, err := GenerateSignatureFor(bytes.NewReader(nil), p); err == nil {
			t.Errorf("профиль %q: на исчерпанном источнике случайности ожидалась ошибка, её нет", p)
		}
	}
}

// rTagValues возвращает список чисел N из каждого тега `<r N>`, встреченного
// в строке I1, в порядке появления — не путать с decodeTags: тот
// разворачивает теги в байты, а этот читает сами значения N из текста.
func rTagValues(t *testing.T, s string) []int {
	t.Helper()
	var out []int
	for len(s) > 0 {
		if s[0] != '<' {
			t.Fatalf("ожидался тег: %q", s)
		}
		end := strings.IndexByte(s, '>')
		if end < 0 {
			t.Fatalf("незакрытый тег в %q", s)
		}
		tag := s[1:end]
		s = s[end+1:]
		if strings.HasPrefix(tag, "r ") {
			n, err := strconv.Atoi(strings.TrimSpace(tag[2:]))
			if err != nil {
				t.Fatalf("тег <r ...>: %q не число: %v", tag, err)
			}
			out = append(out, n)
		}
	}
	return out
}

// TestТегиСлучайностиПереносимыМеждуРеализациями проверяет ПЕРЕНОСИМОСТЬ, а
// не соблюдение протокольного предела — такого предела в протоколе нет.
// Проверено по эталонной amneziawg-go (тег v3.1.20260814, device/obf.go,
// device/obf_rand.go): её сборщик тега `<r N>` берёт длину из строки как
// есть и никак её не ограничивает, `<r 1177>` она разбирает без возражений.
// Ограничение в 1000 — самостоятельный выбор независимой реализации на Rust
// (AYastrebov/awgtun, N > AWG2_MAX_CPS_RANDOM_LEN отвергается при разборе
// конфига её разборщиком CPS), не требование спецификации. Мы держимся в её
// пределах ради переносимости: цена такого разбиения на проводе нулевая (те
// же случайные байты, только через несколько тегов подряд вместо одного), а
// конфиг с одним огромным тегом сторонние реализации с этим ограничением
// (в том числе Android-обвязка на основе awgtun) молча не разберут.
// Единственный профиль, где это реально имело значение, — QUIC: минимальная
// полезная нагрузка при датаграмме 1200 байт — 1174 байта одним тегом, если
// бы randTags не резала её на части. Проверка написана как общая для всех
// трёх профилей (а не только для QUIC), чтобы будущий профиль с длинной
// случайной частью не наступил на те же грабли незамеченным.
func TestТегиСлучайностиПереносимыМеждуРеализациями(t *testing.T) {
	for _, p := range []MimicryProfile{MimicryQUIC, MimicryDNS, MimicrySTUN} {
		for i := 0; i < 40; i++ {
			s, err := GenerateSignatureFor(rand.Reader, p)
			if err != nil {
				t.Fatalf("профиль %q, прогон %d: %v", p, i, err)
			}
			for _, n := range rTagValues(t, s) {
				if n > 1000 {
					t.Fatalf("профиль %q, прогон %d: тег <r %d> длиннее 1000 — часть реализаций (не эталонная) такой конфиг не разберёт", p, i, n)
				}
			}
		}
	}
}

// TestПрофильПоПорту проверяет прямое соответствие "порт → профиль" по
// таблице раздела 5.1 спеки 2026-08-25 и — отдельным циклом — что для
// произвольного порта соответствия нет и это НЕ ошибка (ok == false, а не
// паника или профиль по умолчанию).
func TestПрофильПоПорту(t *testing.T) {
	cases := map[int]MimicryProfile{443: MimicryQUIC, 53: MimicryDNS, 3478: MimicrySTUN}
	for port, want := range cases {
		got, ok := ProfileForPort(port)
		if !ok || got != want {
			t.Errorf("порт %d → (%q, %v), ожидалось (%q, true)", port, got, ok, want)
		}
	}
	// Произвольный порт — это НЕ ошибка, это «профиля нет».
	for _, port := range []int{51772, 52441, 0, 65535} {
		if _, ok := ProfileForPort(port); ok {
			t.Errorf("порту %d нашёлся профиль, а не должен", port)
		}
	}
}

// Таблица одна: обратное соответствие обязано быть согласовано с прямым,
// иначе подсказка порта в комплекте разойдётся с выбором по порту.
func TestТаблицаПрофилейСогласована(t *testing.T) {
	for _, p := range []MimicryProfile{MimicryQUIC, MimicryDNS, MimicrySTUN} {
		port, ok := PortForProfile(p)
		if !ok {
			t.Fatalf("профилю %q нет порта", p)
		}
		back, ok := ProfileForPort(port)
		if !ok || back != p {
			t.Errorf("профиль %q → порт %d → профиль %q: таблица разошлась", p, port, back)
		}
	}
}

// PortForProfile для неизвестного профиля — тоже "нет", а не паника: карта
// profilePort — единственный источник, и обращение к ней по строке, не
// входящей в набор трёх констант, обязано вести себя так же предсказуемо,
// как ProfileForPort для чужого порта.
func TestПортДляНеизвестногоПрофиля(t *testing.T) {
	if _, ok := PortForProfile(MimicryProfile("http")); ok {
		t.Error("неизвестному профилю нашёлся порт, а не должен")
	}
}

// ValidProfile — разбор строки из HTTP-запроса (тело generate/signature,
// query-параметр interface-params) в MimicryProfile. Он строже пустой
// строки: пустое значение — это "профиль не выбран явно, вывести из порта",
// и такое различение делает вызывающий код (задача 2+), а не эта функция —
// поэтому здесь пустая строка тоже "не распознано".
func TestValidProfileРаспознаётИзвестныеИОтвергаетЧужие(t *testing.T) {
	for _, s := range []string{"quic", "dns", "stun"} {
		got, ok := ValidProfile(s)
		if !ok || string(got) != s {
			t.Errorf("ValidProfile(%q) = (%q, %v), ожидалось (%q, true)", s, got, ok, s)
		}
	}
	for _, s := range []string{"", "QUIC", "http", "quic ", "не-профиль"} {
		if _, ok := ValidProfile(s); ok {
			t.Errorf("ValidProfile(%q) неожиданно распознала строку", s)
		}
	}
}

// --- Задача 4 (спека 2026-08-25, раздел 5.6): опознание профиля лежащего I1 ---

// TestDetectProfileУзнаётТриПрофиляПоБайтам — DetectProfile обязан узнавать
// КАЖДЫЙ из трёх сборщиков по их структурным байтам, не по отдельному полю
// (такого поля у I1 и нет — это просто строка). Прогоняем по 20 раз на
// профиль: случайные части (DCID/SCID, transaction ID, домен, имя SOFTWARE)
// не должны влиять на опознание — опознаётся ТОЛЬКО фиксированная часть.
func TestDetectProfileУзнаётТриПрофиляПоБайтам(t *testing.T) {
	for _, want := range []MimicryProfile{MimicryQUIC, MimicryDNS, MimicrySTUN} {
		for i := 0; i < 20; i++ {
			i1, err := GenerateSignatureFor(rand.Reader, want)
			if err != nil {
				t.Fatalf("%s, прогон %d: генерация: %v", want, i, err)
			}
			got, ok := DetectProfile(i1)
			if !ok || got != want {
				t.Fatalf("%s, прогон %d: DetectProfile(%q) = (%q, %v), ожидалось (%q, true)",
					want, i, i1, got, ok, want)
			}
		}
	}
}

// TestDetectProfileМусорДаётFalse — строка, не похожая ни на один из трёх
// профилей, НЕ ошибка: это explicitly допустимый исход (раздел 5.6 спеки —
// "и это НЕ ошибка"), например, defaults.json мог быть заполнен руками до
// того, как в панели появились профили мимикрии вообще.
func TestDetectProfileМусорДаётFalse(t *testing.T) {
	for _, s := range []string{
		"",
		"случайный текст, не CPS вовсе",
		"<r 16>",                 // только случайные байты, ни одного литерала
		"<b 0x0000000000000000>", // литерал есть, но не подходит ни под один профиль
	} {
		if p, ok := DetectProfile(s); ok {
			t.Errorf("DetectProfile(%q) = (%q, true), ожидалось (_, false)", s, p)
		}
	}
}

// TestProfilePortHintsПеречисляетВсеТриПрофиля — текст подсказки в ошибке
// маршрута ("порт не соответствует ничему — укажите профиль явно") обязан
// называть ВСЕ известные профили с портами, а не часть: единственная таблица
// profilePort — источник, и подсказка не должна отставать от неё при
// добавлении профиля.
func TestProfilePortHintsПеречисляетВсеТриПрофиля(t *testing.T) {
	hint := ProfilePortHints()
	for p := range profilePort {
		port, _ := PortForProfile(p)
		want := fmt.Sprintf("%s: %d", p, port)
		if !strings.Contains(hint, want) {
			t.Errorf("ProfilePortHints() = %q, не содержит %q", hint, want)
		}
	}
}

// TestGenerateInterfaceParamsРавныеS — замер 05.09.2026 на боевом awgref и
// разбор device/receive.go: при RandomTrailers = on классификатор читает
// поле типа по смещению S каждой ветки, и при S1 ≠ S4 транспортный пакет
// попадает в ветку рукопожатия с вероятностью ширина(H)/2³² — молча
// теряется. Равные S1..S4 делают кражу невозможной (ветка читает настоящий
// тип из H4, а H1..H3 с ним не пересекаются), это же рекомендует
// docs.amnezia.org. Генератор обязан выдавать равные S в коридоре 12..32:
// ≥ 12 — нонс ChaCha20 защиты заголовков, ≤ 32 — S4 падит каждый
// транспортный пакет.
func TestGenerateInterfaceParamsРавныеS(t *testing.T) {
	for i := 0; i < 300; i++ {
		p, err := GenerateInterfaceParams(rand.Reader, MimicryQUIC)
		if err != nil {
			t.Fatalf("прогон %d: %v", i, err)
		}
		if p.S1 != p.S2 || p.S2 != p.S3 || p.S3 != p.S4 {
			t.Fatalf("прогон %d: S1..S4 = %d/%d/%d/%d — обязаны быть равны", i, p.S1, p.S2, p.S3, p.S4)
		}
		if p.S1 < 12 || p.S1 > 32 {
			t.Fatalf("прогон %d: S = %d вне 12..32", i, p.S1)
		}
	}
}

// TestServerBlockНесётФлаги31 — комплект для нового интерфейса — это 3.1
// целиком: без RandomTrailers/DisableCookies оператор получил бы «эталон»
// уровня 3.0 и включал бы флаги руками (или забывал).
func TestServerBlockНесётФлаги31(t *testing.T) {
	p, err := GenerateInterfaceParams(rand.Reader, MimicryQUIC)
	if err != nil {
		t.Fatal(err)
	}
	block := p.ServerBlock()
	for _, want := range []string{"RandomTrailers = on\n", "DisableCookies = on\n"} {
		if !strings.Contains(block, want) {
			t.Errorf("в ServerBlock нет %q:\n%s", strings.TrimSpace(want), block)
		}
	}
	conf, err := wgconf.Parse("[Interface]\nPrivateKey = aaa=\n" + block)
	if err != nil {
		t.Fatalf("ServerBlock с флагами не разбирается: %v", err)
	}
	obf, err := ExtractObfuscation(conf.Interface)
	if err != nil {
		t.Fatal(err)
	}
	if !isOn(obf["RandomTrailers"]) || !isOn(obf["DisableCookies"]) {
		t.Fatalf("флаги 3.1 не доехали до клиентской карты: %v", obf)
	}
}
