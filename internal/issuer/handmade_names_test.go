package issuer_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/store"
)

// handConf — конфиг с пирами, заведёнными РУКАМИ до установки панели: имя у
// каждого записано обычным комментарием, без пометки авторства «awg3panel:».
// Ровно так выглядит боевой awg3, где из шести пиров пять именно такие.
const handConf = serverConf + `
[Peer]
# домашний роутер
PublicKey = bWUtcHVibGljLWtleS1mYWtlLTAwMDAwMDAwMDAwMDAwMD0=
PresharedKey = bWUtcHNrLWZha2UtMDAwMDAwMDAwMDAwMDAwMDAwMDAwMD0=
AllowedIPs = 10.11.0.2/32

[Peer]
; рабочий ПК
PublicKey = cGFwYS1wdWJsaWMta2V5LWZha2UtMDAwMDAwMDAwMDAwMD0=
PresharedKey = cGFwYS1wc2stZmFrZS0wMDAwMDAwMDAwMDAwMDAwMDAwPQ==
AllowedIPs = 10.11.0.3/32
`

// TestListAdoptsHandWrittenNames — пир, заведённый руками, обязан появиться в
// панели под тем именем, которым его назвал человек в комментарии конфига, а
// не под сгенерированным «peer-<12 hex>».
//
// Это не косметика. Удаление пира в консоли подтверждается ВВОДОМ ИМЕНИ
// символ в символ, поэтому имя, которого человек не выбирал и не может
// осмысленно набрать, делает пира фактически неудаляемым — что и произошло
// на боевом awg3 с пятью пирами из шести. Прежний разбор искал строго
// префикс «# awg3panel:», то есть узнавал ровно те имена, которые панель
// написала сама, и не узнавал ни одного чужого.
func TestListAdoptsHandWrittenNames(t *testing.T) {
	s, _, _ := serviceWithConf(t, handConf)
	peers, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, p := range peers {
		names[p.Name] = true
	}
	for _, want := range []string{"домашний роутер", "рабочий ПК"} {
		if !names[want] {
			t.Errorf("имя %q не подхвачено из комментария; получено: %v", want, names)
		}
	}
}

// TestListRenamesPreviouslyAutoNamedPeer — пир, УЖЕ подхваченный прежней
// версией панели и записанный в peers.json под именем «peer-<id>», обязан
// получить настоящее имя при первом же чтении новой версией.
//
// Без этого исправление не доходит до тех, ради кого делалось: на боевом
// хосте автоимена уже сохранены на диске, а Reconcile придумывает имя только
// НОВОМУ пиру и к записанному не возвращается. «peer-<id>» — имя, которое
// панель придумала сама и никогда не предлагала человеку, поэтому заменить
// его настоящим безопасно; имя, выбранное человеком, не трогается (см.
// TestListKeepsUserChosenName).
func TestListRenamesPreviouslyAutoNamedPeer(t *testing.T) {
	s, _, cfg := serviceWithConf(t, handConf)
	id := store.PeerID(meKey)
	seed(t, cfg.Interfaces[0].Storage.State, store.State{Version: 1, Peers: []store.Peer{
		{ID: id, Name: "peer-" + id, PublicKey: meKey, Address: "10.11.0.2/32", Enabled: true},
	}})

	peers, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range peers {
		if p.ID == id && p.Name != "домашний роутер" {
			t.Fatalf("имя = %q, ожидали «домашний роутер»", p.Name)
		}
	}
}

// TestListKeepsUserChosenName — имя, заданное человеком через панель,
// комментарий конфига не перебивает. Рубеж намеренный: пир, переименованный
// в консоли, обязан остаться под своим именем, даже если в конфиге рядом
// лежит чужой комментарий (например, тот, что был там до переименования, —
// rewritePeerBlock переносит чужие строки байт в байт и не удаляет их).
func TestListKeepsUserChosenName(t *testing.T) {
	s, _, cfg := serviceWithConf(t, handConf)
	id := store.PeerID(meKey)
	seed(t, cfg.Interfaces[0].Storage.State, store.State{Version: 1, Peers: []store.Peer{
		{ID: id, Name: "Кинетик дома", PublicKey: meKey, Address: "10.11.0.2/32", Enabled: true},
	}})

	peers, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range peers {
		if p.ID == id && p.Name != "Кинетик дома" {
			t.Fatalf("имя = %q, ожидали «Кинетик дома» — выбранное человеком имя затёрто", p.Name)
		}
	}
}

// seed кладёт готовое состояние в peers.json — так, как его оставила бы
// предыдущая версия панели.
func seed(t *testing.T, path string, st store.State) {
	t.Helper()
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(b, 0x0a), 0o600); err != nil {
		t.Fatal(err)
	}
}
