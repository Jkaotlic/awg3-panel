package issuer

import (
	"testing"
	"time"

	"github.com/Jkaotlic/awg3-panel/internal/runtime"
)

func TestSummarizeСчитаетКатегории(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	ago := func(d time.Duration) int64 { return now.Add(-d).Unix() }

	peers := []PeerStat{
		{Name: "ноут", Enabled: true, LastHandshake: ago(30 * time.Second), TxBytes: 100, RxBytes: 10},
		{Name: "граница-онлайн", Enabled: true, LastHandshake: ago(180 * time.Second), TxBytes: 1, RxBytes: 1},
		{Name: "ждёт", Enabled: true, LastHandshake: ago(181 * time.Second), TxBytes: 1, RxBytes: 1},
		// Граница StaleAfter (24 ч) — по тому же принципу, что и 180 с выше:
		// сравнение в summarize строгое (p.LastHandshake < staleBefore), так
		// что ровно на границе пир ещё не «нет связи» — он просто выпадает
		// из всех трёх категорий (не онлайн, не никогда, не молчит), как и
		// "ждёт" выше. Секундой позже граница пересечена.
		{Name: "граница-24ч", Enabled: true, LastHandshake: ago(24 * time.Hour), TxBytes: 1, RxBytes: 1},
		{Name: "24ч-и-секунда", Enabled: true, LastHandshake: ago(24*time.Hour + time.Second), TxBytes: 1, RxBytes: 1},
		{Name: "молчит", Enabled: true, LastHandshake: ago(25 * time.Hour), TxBytes: 1, RxBytes: 1},
		{Name: "никогда", Enabled: true, LastHandshake: 0},
		{Name: "выключен", Enabled: false, LastHandshake: ago(10 * time.Second)},
	}
	dev := runtime.DumpDevice{PublicKey: "PUB=", ListenPort: 51772}

	got := summarize(now, "awg3", dev, "1280", peers)

	if got.PeersTotal != 8 {
		t.Errorf("PeersTotal = %d, ожидалось 8", got.PeersTotal)
	}
	if got.PeersOnline != 2 {
		t.Errorf("PeersOnline = %d, ожидалось 2 (граница 180 с включительно)", got.PeersOnline)
	}
	if got.PeersStale != 2 {
		t.Errorf("PeersStale = %d, ожидалось 2 (24ч-и-секунда и молчит; граница-24ч в эту категорию не входит)", got.PeersStale)
	}
	if got.PeersNever != 1 {
		t.Errorf("PeersNever = %d, ожидалось 1", got.PeersNever)
	}
	if got.LastHandshakePeer != "ноут" {
		t.Errorf("LastHandshakePeer = %q, ожидалось \"ноут\"", got.LastHandshakePeer)
	}
	if got.ListenPort != 51772 || got.PublicKey != "PUB=" || got.MTU != "1280" {
		t.Errorf("поля устройства не доехали: %+v", got)
	}
}

// Выключенный пир не считается ни онлайн, ни молчащим, ни «никогда»:
// он выключен, и это отдельное состояние, а не разновидность аварии.
func TestSummarizeВыключенныйНеПопадаетВКатегории(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	got := summarize(now, "awg3", runtime.DumpDevice{}, "", []PeerStat{
		{Name: "off-свежий", Enabled: false, LastHandshake: now.Unix()},
		{Name: "off-старый", Enabled: false, LastHandshake: now.Add(-72 * time.Hour).Unix()},
		{Name: "off-никогда", Enabled: false, LastHandshake: 0},
	})
	if got.PeersOnline+got.PeersStale+got.PeersNever != 0 {
		t.Fatalf("выключенные попали в категории: %+v", got)
	}
	if got.PeersTotal != 3 {
		t.Errorf("PeersTotal = %d, ожидалось 3", got.PeersTotal)
	}
}

func TestSummarizeПустойИнтерфейс(t *testing.T) {
	got := summarize(time.Unix(1_800_000_000, 0), "awg3", runtime.DumpDevice{}, "", nil)
	if got.PeersTotal != 0 || got.TxBytes != 0 || got.LastHandshake != 0 {
		t.Fatalf("пустой интерфейс дал не нули: %+v", got)
	}
	if got.LastHandshakePeer != "" {
		t.Errorf("LastHandshakePeer = %q, ожидалась пустая строка", got.LastHandshakePeer)
	}
}

func TestSummarizeСуммируетТрафикВключаяВыключенных(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	got := summarize(now, "awg3", runtime.DumpDevice{}, "", []PeerStat{
		{Name: "a", Enabled: true, LastHandshake: now.Unix(), TxBytes: 100, RxBytes: 7},
		{Name: "b", Enabled: false, LastHandshake: now.Unix(), TxBytes: 5, RxBytes: 3},
	})
	if got.TxBytes != 105 || got.RxBytes != 10 {
		t.Fatalf("tx=%d rx=%d, ожидалось 105/10: трафик выключенного пира уже прошёл через сервер", got.TxBytes, got.RxBytes)
	}
}
