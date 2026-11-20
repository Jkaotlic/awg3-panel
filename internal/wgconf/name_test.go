package wgconf_test

import (
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/wgconf"
)

// TestPeerNameFromComment — имя пира, заведённого РУКАМИ, лежит в конфиге
// комментарием внутри блока [Peer], и это единственное место, где оно вообще
// есть: peers.json такого пира не знает, пока Reconcile его не подхватит.
// Без этой функции подхваченный пир получает имя "peer-<12 hex>", которое
// человек не выбирал и которое приходится вводить символ в символ при
// удалении, — ровно та причина, по которой пять боевых пиров awg3
// оказались фактически неудаляемыми из панели.
//
// Префикс "awg3panel: " снимается: его пишет RenderPeerBlock как пометку
// авторства, а не как часть имени, и показывать его в списке значило бы
// показывать разные имена одному и тому же пиру до и после переиздания.
func TestPeerNameFromComment(t *testing.T) {
	cases := []struct {
		title string
		block string
		want  string
	}{
		{
			title: "комментарий, написанный руками",
			block: "[Peer]\n# me — Keenetic (дом)\nPublicKey = " + mePub + "\nAllowedIPs = 10.11.0.2/32\n",
			want:  "me — Keenetic (дом)",
		},
		{
			title: "комментарий, написанный панелью",
			block: "[Peer]\n# awg3panel: Alyaba\nPublicKey = " + mePub + "\nAllowedIPs = 10.11.0.8/32\n",
			want:  "Alyaba",
		},
		{
			title: "точка с запятой — тоже комментарий",
			block: "[Peer]\n; work — рабочий ПК\nPublicKey = " + mePub + "\nAllowedIPs = 10.11.0.5/32\n",
			want:  "work — рабочий ПК",
		},
		{
			title: "комментария нет",
			block: "[Peer]\nPublicKey = " + mePub + "\nAllowedIPs = 10.11.0.4/32\n",
			want:  "",
		},
		{
			title: "берётся ПЕРВЫЙ комментарий, а не последний",
			block: "[Peer]\n# ru-entry Cloud.ru\nPublicKey = " + mePub + "\n# добавлен вручную\nAllowedIPs = 10.11.0.4/32\n",
			want:  "ru-entry Cloud.ru",
		},
		{
			title: "пустой комментарий именем не считается",
			block: "[Peer]\n#\nPublicKey = " + mePub + "\nAllowedIPs = 10.11.0.4/32\n",
			want:  "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			text := "[Interface]\nPrivateKey = " + papaPub + "\nListenPort = 51772\n\n" + tc.block
			c, err := wgconf.Parse(text)
			if err != nil {
				t.Fatalf("разбор: %v", err)
			}
			if len(c.Peers) != 1 {
				t.Fatalf("секций [Peer] = %d, ожидали 1", len(c.Peers))
			}
			if got := wgconf.PeerName(c.Peers[0], text); got != tc.want {
				t.Errorf("PeerName = %q, ожидали %q", got, tc.want)
			}
		})
	}
}

// TestPeerNameIgnoresLongComment — имя пира ограничено сорока символами
// (issuer.validateName), и комментарий, который в это не влезает, именем не
// является: это, скорее всего, пояснение, а не название. Возвращать его
// значило бы завести в peers.json имя, которое сама же панель отказывается
// принимать при правке.
func TestPeerNameIgnoresLongComment(t *testing.T) {
	long := "это очень длинное пояснение к пиру, которое именем быть не может"
	text := "[Interface]\nPrivateKey = " + papaPub + "\n\n[Peer]\n# " + long +
		"\nPublicKey = " + mePub + "\nAllowedIPs = 10.11.0.9/32\n"
	c, err := wgconf.Parse(text)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if got := wgconf.PeerName(c.Peers[0], text); got != "" {
		t.Errorf("PeerName = %q, ожидали пустую строку", got)
	}
}

// TestPeerNameRejectsSectionBrackets — имя уезжает обратно в конфиг
// комментарием (RenderPeerBlock), поэтому PeerSpec.validate отвергает в нём
// скобки заголовка секции. Подхватить такой комментарий как имя значило бы
// завести пира, которого панель показывает, но отказывается переименовать
// или отредактировать: ReplacePeerBlock упал бы на собственной проверке.
func TestPeerNameRejectsSectionBrackets(t *testing.T) {
	text := "[Interface]\nPrivateKey = " + papaPub + "\n\n[Peer]\n# узел [резерв]\nPublicKey = " +
		mePub + "\nAllowedIPs = 10.11.0.9/32\n"
	c, err := wgconf.Parse(text)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if got := wgconf.PeerName(c.Peers[0], text); got != "" {
		t.Errorf("PeerName = %q, ожидали пустую строку", got)
	}
}

// TestPeerNameTakesHeadOfLongComment — комментарий, не влезающий в
// PeerNameMaxLen, отдаёт СВОЮ ГОЛОВУ, если она отделена тире с пробелами.
//
// Привычка, из которой это следует, видна в боевом awg3: комментарии там
// устроены как «<название> — <пояснение>» («<название> — <пояснение с датой>»). Отвергать такой комментарий целиком
// значит оставить пиру имя «peer-<12 hex>» — то самое, из-за которого его
// нельзя подтвердить при удалении. Голова короче потолка, читаема и выбрана
// человеком, поэтому она лучше сгенерированной шестнадцатеричной строки.
//
// Правило срабатывает ТОЛЬКО когда целое не влезает: если комментарий
// помещается в потолок, он берётся целиком со всем пояснением — «me —
// Keenetic (дом)» информативнее, чем «me». Разделитель обязан быть с
// пробелами по краям, иначе «office-vpn» разрезало бы по собственному дефису.
func TestPeerNameTakesHeadOfLongComment(t *testing.T) {
	cases := []struct {
		title   string
		comment string
		want    string
	}{
		{
			title:   "длинный комментарий отдаёт голову до тире",
			comment: "office-vpn — выдан на второй ноутбук взамен утраченного, 2026",
			want:    "office-vpn",
		},
		{
			title:   "дефис с пробелами — тоже разделитель",
			comment: "papa2 - новый конфиг для папы, выдан взамен утерянного старого",
			want:    "papa2",
		},
		{
			title:   "короткий комментарий берётся ЦЕЛИКОМ, а не по голову",
			comment: "me — Keenetic (дом)",
			want:    "me — Keenetic (дом)",
		},
		{
			title:   "длинный без разделителя именем не становится",
			comment: "этот комментарий длинный и никакого разделителя в нём нет вовсе",
			want:    "",
		},
		{
			title:   "дефис внутри слова разделителем не считается",
			comment: "ru-entry-cloud-ru-очень-длинное-имя-без-единого-пробела-внутри",
			want:    "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			text := "[Interface]\nPrivateKey = " + papaPub + "\n\n[Peer]\n# " + tc.comment +
				"\nPublicKey = " + mePub + "\nAllowedIPs = 10.11.0.7/32\n"
			c, err := wgconf.Parse(text)
			if err != nil {
				t.Fatalf("разбор: %v", err)
			}
			if got := wgconf.PeerName(c.Peers[0], text); got != tc.want {
				t.Errorf("PeerName = %q, ожидали %q", got, tc.want)
			}
		})
	}
}
