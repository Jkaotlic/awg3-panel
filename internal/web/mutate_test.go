//go:build !readonly

package web_test

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/runtime"
	"github.com/Jkaotlic/awg3-panel/internal/store"
	"github.com/Jkaotlic/awg3-panel/internal/web"
	"golang.org/x/crypto/bcrypt"
)

type fakeMutator struct {
	added    string
	removed  string
	disabled string
	enabled  string
	err      error

	// Задача 10: правка пира, ротация, умолчания.
	lastPatch    issuer.PeerPatch
	rotated      string
	defaults     store.Defaults
	lastDefaults store.Defaults
}

func (m *fakeMutator) Add(name string) (*issuer.Issued, error) {
	if m.err != nil {
		return nil, m.err
	}
	m.added = name
	return &issuer.Issued{ID: "abc123", Name: name, Address: "10.11.0.4/32",
		Config: "[Interface]\n", QRPNG: []byte("\x89PNG\r\n\x1a\n")}, nil
}
func (m *fakeMutator) Remove(id string) error  { m.removed = id; return m.err }
func (m *fakeMutator) Disable(id string) error { m.disabled = id; return m.err }
func (m *fakeMutator) Enable(id string) error  { m.enabled = id; return m.err }
func (m *fakeMutator) ConfigFor(id string) (string, string, error) {
	return "peer.conf", "[Interface]\n", m.err
}
func (m *fakeMutator) ConfigWithoutCPSFor(id string) (string, string, error) {
	return "peer-no-cps.conf", "[Interface]\n", m.err
}
func (m *fakeMutator) PeerMimicryFor(id string) (issuer.PeerMimicry, error) {
	return issuer.PeerMimicry{
		Profile: issuer.MimicrySTUN, Source: "peer", EndpointPort: 3478, ProfilePort: 3478, HasCPS: true,
	}, m.err
}
func (m *fakeMutator) QRFor(id string) ([]byte, error) {
	return []byte("\x89PNG\r\n\x1a\n"), m.err
}
func (m *fakeMutator) VPNURIFor(id string) (string, error) {
	return "vpn://AAAA", m.err
}
func (m *fakeMutator) VPNQRFor(id string) ([]byte, error) {
	return []byte("\x89PNG\r\n\x1a\n"), m.err
}
func (m *fakeMutator) Update(id string, patch issuer.PeerPatch) error {
	m.lastPatch = patch
	return m.err
}
func (m *fakeMutator) Rotate(id string) (*issuer.Issued, error) {
	if m.err != nil {
		return nil, m.err
	}
	m.rotated = id
	return &issuer.Issued{ID: id, Name: "ротированный", Address: "10.11.0.4/32",
		Config: "[Interface]\n", QRPNG: []byte("\x89PNG\r\n\x1a\n")}, nil
}
func (m *fakeMutator) Defaults() store.Defaults { return m.defaults }
func (m *fakeMutator) SetDefaults(d store.Defaults) error {
	m.lastDefaults = d
	return m.err
}

// fakeMutatorRegistry — тестовая реализация web.MutatorRegistry: единственный
// интерфейс "awg3" отдаёт заданный мутатор. Методы на указательном ресивере
// намеренно — TestTypedNilMutatorRegistryIsTreatedAsReadOnly передаёт
// типизированный nil-указатель этого типа как web.MutatorRegistry.
type fakeMutatorRegistry struct{ byID map[string]web.PeerMutator }

func (r *fakeMutatorRegistry) Mutator(id string) (web.PeerMutator, bool) {
	m, ok := r.byID[id]
	return m, ok
}

// newTestServerWithMutator строит пишущий обработчик с единственным
// интерфейсом "awg3", чей мутатор — m. Замена прежнего mutServer(t, m)
// (задача 10 перевела Server с одиночного PeerMutator на MutatorRegistry).
func newTestServerWithMutator(t *testing.T, m web.PeerMutator) http.Handler {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte("секрет"), 4)
	cfg := config.Default()
	cfg.Auth.User, cfg.Auth.Bcrypt = "admin", string(hash)
	reg := &fakeRegistry{
		metas:   []issuer.IfaceMeta{{ID: "awg3", Title: "awg3", Interface: "awg3"}},
		listers: map[string]web.PeerLister{"awg3": &fakeLister{}},
	}
	mutators := &fakeMutatorRegistry{byID: map[string]web.PeerMutator{"awg3": m}}
	return web.NewServerWithMutator(cfg, reg, mutators).Handler()
}

func TestPostPeersCreates(t *testing.T) {
	m := &fakeMutator{}
	rec := doAuthed(t, newTestServerWithMutator(t, m), http.MethodPost, "/api/ifaces/awg3/peers",
		strings.NewReader(`{"name":"мой-ноут"}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("код = %d, ожидался 201, тело: %s", rec.Code, rec.Body)
	}
	if m.added != "мой-ноут" {
		t.Errorf("сервису передано имя %q", m.added)
	}
	var got struct {
		ID       string `json:"id"`
		Config   string `json:"config"`
		QRBase64 string `json:"qr_png_base64"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ID == "" || got.Config == "" || got.QRBase64 == "" {
		t.Errorf("неполный ответ: %+v", got)
	}
}

func TestPostPeersRejectsBadJSON(t *testing.T) {
	rec := doAuthed(t, newTestServerWithMutator(t, &fakeMutator{}), http.MethodPost, "/api/ifaces/awg3/peers",
		strings.NewReader(`не json`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("код = %d, ожидался 400", rec.Code)
	}
}

// TestPostPeersSurfacesValidationError — половина «разведения кодов» из ревью
// Task 11: ошибка ВВОДА обязана дойти до пользователя дословно. Иначе на
// пустое имя он получит «внутренняя ошибка» и не поймёт, что чинить.
func TestPostPeersSurfacesValidationError(t *testing.T) {
	m := &fakeMutator{err: fmt.Errorf("%w: имя пира не может быть пустым", issuer.ErrInvalidInput)}
	rec := doAuthed(t, newTestServerWithMutator(t, m), http.MethodPost, "/api/ifaces/awg3/peers",
		strings.NewReader(`{"name":"  "}`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("код = %d, ожидался 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "имя пира не может быть пустым") {
		t.Errorf("причина отказа не дошла до пользователя: %s", rec.Body)
	}
}

// TestPostPeersHidesInternalErrorText — вторая половина: ВНУТРЕННЯЯ ошибка
// наружу не уходит. Цепочка err на пути мутации проходит через wgconf,
// issuer и runtime, и однажды может снова понести в себе строку конфига с
// ключом (ровно это чинили в Task 11). Подробности — в лог администратора,
// клиенту — родовая формулировка.
func TestPostPeersHidesInternalErrorText(t *testing.T) {
	m := &fakeMutator{err: errors.New("пул адресов исчерпан")}
	rec := doAuthed(t, newTestServerWithMutator(t, m), http.MethodPost, "/api/ifaces/awg3/peers",
		strings.NewReader(`{"name":"x"}`))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("код = %d, ожидался 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "пул адресов исчерпан") {
		t.Errorf("текст внутренней ошибки ушёл клиенту: %s", rec.Body)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("ошибка отдана не в JSON: %v (%s)", err, rec.Body)
	}
	if body.Error == "" {
		t.Error("поле error пусто")
	}
}

func TestDeletePeer(t *testing.T) {
	m := &fakeMutator{}
	h := newTestServerWithMutator(t, m)
	if rec := doAuthed(t, h, http.MethodDelete, "/api/ifaces/awg3/peers/abc123", nil); rec.Code != http.StatusOK {
		t.Fatalf("код = %d", rec.Code)
	}
	if m.removed != "abc123" {
		t.Errorf("удалён %q", m.removed)
	}
}

// TestUnknownPeerIs404 — неизвестный id это ошибка запроса, а не сервера:
// 404 с внятной причиной, а не 500 «внутренняя ошибка».
func TestUnknownPeerIs404(t *testing.T) {
	m := &fakeMutator{err: fmt.Errorf("%w: abc123", issuer.ErrNotFound)}
	rec := doAuthed(t, newTestServerWithMutator(t, m), http.MethodPost, "/api/ifaces/awg3/peers/abc123/disable", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("код = %d, ожидался 404", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "abc123") {
		t.Errorf("ответ не называет ненайденного пира: %s", rec.Body)
	}
}

func TestDisableAndEnable(t *testing.T) {
	m := &fakeMutator{}
	h := newTestServerWithMutator(t, m)
	if rec := doAuthed(t, h, http.MethodPost, "/api/ifaces/awg3/peers/abc123/disable", nil); rec.Code != http.StatusOK {
		t.Fatalf("disable: код = %d", rec.Code)
	}
	if rec := doAuthed(t, h, http.MethodPost, "/api/ifaces/awg3/peers/abc123/enable", nil); rec.Code != http.StatusOK {
		t.Fatalf("enable: код = %d", rec.Code)
	}
	if m.disabled != "abc123" || m.enabled != "abc123" {
		t.Errorf("disabled=%q enabled=%q", m.disabled, m.enabled)
	}
}

func TestGetConfigHasAttachmentHeader(t *testing.T) {
	rec := doAuthed(t, newTestServerWithMutator(t, &fakeMutator{}), http.MethodGet, "/api/ifaces/awg3/peers/abc123/config", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("код = %d", rec.Code)
	}
	cd := rec.Header().Get("Content-Disposition")
	if !strings.Contains(cd, "attachment") || !strings.Contains(cd, "peer.conf") {
		t.Errorf("Content-Disposition = %q", cd)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q", ct)
	}
}

func TestGetQRReturnsPNG(t *testing.T) {
	rec := doAuthed(t, newTestServerWithMutator(t, &fakeMutator{}), http.MethodGet, "/api/ifaces/awg3/peers/abc123/qr", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("код = %d", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "image/png" {
		t.Errorf("Content-Type = %q", rec.Header().Get("Content-Type"))
	}
}

func TestMutationsRequireAuth(t *testing.T) {
	h := newTestServerWithMutator(t, &fakeMutator{})
	req := httptest.NewRequest(http.MethodPost, "/api/ifaces/awg3/peers", strings.NewReader(`{"name":"x"}`))
	req.RemoteAddr = "10.11.0.2:40000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("код = %d, ожидался 401", rec.Code)
	}
}

// TestCrossSitePostDoesNotReachMutator — та же защита, что и в
// TestCrossSiteWriteIsRejected, но с настоящим мутатором за маршрутом:
// важен не только код ответа, но и то, что сервисный метод не был вызван.
// 403 при уже выполненной мутации ничего бы не стоил.
func TestCrossSitePostDoesNotReachMutator(t *testing.T) {
	m := &fakeMutator{}
	h := newTestServerWithMutator(t, m)
	req := httptest.NewRequest(http.MethodPost, "/api/ifaces/awg3/peers", strings.NewReader(`{"name":"чужой"}`))
	req.RemoteAddr = "10.11.0.2:40000"
	req.SetBasicAuth("admin", "секрет")
	req.Header.Set("Origin", "http://evil.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("код = %d, ожидался 403", rec.Code)
	}
	if m.added != "" {
		t.Errorf("мутатор вызван кросс-сайтовым запросом: добавлено имя %q", m.added)
	}
}

// TestTypedNilMutatorRegistryIsTreatedAsReadOnly — та же находка ревью
// Task 11, перенесённая на новый уровень косвенности (задача 10): раньше
// типизированный nil мог прийти как сам PeerMutator, теперь — как
// MutatorRegistry (его отдаёт NewServerWithMutator реестру мутаторов, а не
// одному мутатору напрямую). Интерфейс с nil-указателем внутри сам по себе
// НЕ равен nil, поэтому наивная проверка `m == nil` на нём не срабатывает:
// страница объявила бы панель пишущей, маршруты мутаций зарегистрировались
// бы, и первый же вызов уронил бы обработчик. Панель обязана считать такой
// реестр отсутствующим — и в разметке, и в маршрутах.
func TestTypedNilMutatorRegistryIsTreatedAsReadOnly(t *testing.T) {
	var typedNil *fakeMutatorRegistry // nil-указатель конкретного типа
	hash, _ := bcrypt.GenerateFromPassword([]byte("секрет"), 4)
	cfg := config.Default()
	cfg.Auth.User, cfg.Auth.Bcrypt = "admin", string(hash)
	reg := &fakeRegistry{
		metas:   []issuer.IfaceMeta{{ID: "awg3", Title: "awg3", Interface: "awg3"}},
		listers: map[string]web.PeerLister{"awg3": &fakeLister{}},
	}
	h := web.NewServerWithMutator(cfg, reg, typedNil).Handler()

	rec := doAuthed(t, h, http.MethodGet, "/", nil)
	if !strings.Contains(rec.Body.String(), "только чтения") {
		t.Error("страница не сообщает о режиме только чтения, хотя реестр мутаторов фактически nil")
	}
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/api/ifaces/awg3/peers"},
		{http.MethodDelete, "/api/ifaces/awg3/peers/abc123"},
		{http.MethodPost, "/api/ifaces/awg3/peers/abc123/disable"},
		{http.MethodPost, "/api/ifaces/awg3/peers/abc123/enable"},
	} {
		rec := doAuthed(t, h, c.method, c.path, strings.NewReader(`{"name":"x"}`))
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: код = %d, ожидался 404/405 — маршрут не должен быть зарегистрирован",
				c.method, c.path, rec.Code)
		}
	}
}

// TestFullBuildIndexHasActionControls — обратная сторона
// TestReadOnlyIndexShowsBadge: в полной сборке кнопки действий обязаны быть в
// разметке, иначе панель read-only не по тегу сборки, а по недосмотру в
// шаблоне, и оба теста прошли бы одновременно.
func TestFullBuildIndexHasActionControls(t *testing.T) {
	if web.ReadOnlyBuild {
		t.Fatal("полная сборка помечена как read-only")
	}
	rec := doAuthed(t, newTestServerWithMutator(t, &fakeMutator{}), http.MethodGet, "/", nil)
	// "/peers/" (со слэшем) — задача 11 перевела JS на api()/apiURL(), собирающие
	// путь конкретного пира динамически ("/peers/" + id + "/..."), поэтому
	// прежний литерал "/api/peers/" в разметке больше не встречается нигде —
	// ни в мутирующей, ни в read-only сборке. Строка "/peers/" со слэшем
	// остаётся эквивалентным маркером: она входит в исходный JS-текст
	// rowActions/peerAction/editform, а те определены ТОЛЬКО внутри
	// {{if not .ReadOnly}} (см. TestReadOnlyIndexShowsBadge). refresh() же
	// (общий для обеих сборок) обращается к "/peers" без слэша.
	for _, want := range []string{"Добавить", "Действия", "/peers/"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("в разметке нет %q", want)
		}
	}
	if strings.Contains(rec.Body.String(), "только чтения") {
		t.Error("полная сборка показывает плашку режима только чтения")
	}
}

func TestFullBuildIndexAllowsOnlyScriptsWithPerResponseNonce(t *testing.T) {
	assertIndexAllowsOnlyScriptsWithPerResponseNonce(t, newTestServerWithMutator(t, &fakeMutator{}))
}

// --- Задача 10: PATCH пира, ротация ключей, умолчания интерфейса ---

// TestPatchPeerPassesThroughToMutator — путь PATCH БЕЗ завершающего слэша
// (поправка 1 контролёра к брифу задачи 10: DELETE и PATCH не конфликтуют
// как образцы net/http, слэш не нужен). Явно пустой DNS в overrides обязан
// дойти до Update как ЗАДАННЫЙ пустым (*string, указывающий на ""), а не
// как отсутствующее поле (nil) — раздел 8 спеки о наследовании умолчаний.
func TestPatchPeerPassesThroughToMutator(t *testing.T) {
	m := &fakeMutator{}
	srv := newTestServerWithMutator(t, m)
	body := `{"name":"новое","overrides":{"dns":""}}`
	rec := doAuthed(t, srv, http.MethodPatch, "/api/ifaces/awg3/peers/abc123", strings.NewReader(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	if m.lastPatch.Name == nil || *m.lastPatch.Name != "новое" {
		t.Fatal("имя не доехало до сервиса")
	}
	if m.lastPatch.Overrides == nil || m.lastPatch.Overrides.DNS == nil || *m.lastPatch.Overrides.DNS != "" {
		t.Fatal("явно пустой DNS обязан доехать как заданный, а не как отсутствующий")
	}
}

// TestPatchPeerOmittedFieldsStayNil — обратная сторона предыдущего теста:
// поле, которого нет в JSON вовсе, обязано остаться nil-указателем в
// PeerPatch (наследование/«не менять»), а не превратиться в пустое значение.
func TestPatchPeerOmittedFieldsStayNil(t *testing.T) {
	m := &fakeMutator{}
	srv := newTestServerWithMutator(t, m)
	rec := doAuthed(t, srv, http.MethodPatch, "/api/ifaces/awg3/peers/abc123", strings.NewReader(`{"name":"новое"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	if m.lastPatch.Address != nil {
		t.Errorf("address не присылался, а доехал как %v", *m.lastPatch.Address)
	}
	if m.lastPatch.Overrides != nil {
		t.Errorf("overrides не присылался, а доехал как %+v", m.lastPatch.Overrides)
	}
}

// TestMutationOnUnknownInterfaceIs404 — mutatorFor (общий для всех маршрутов
// мутаций) обязан отвечать 404 на неизвестный интерфейс, а не паниковать и
// не молча брать первый попавшийся мутатор (constraint 5 брифа задачи 10).
func TestMutationOnUnknownInterfaceIs404(t *testing.T) {
	h := newTestServerWithMutator(t, &fakeMutator{})
	rec := doAuthed(t, h, http.MethodPatch, "/api/ifaces/нет-такого/peers/abc123", strings.NewReader(`{}`))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("код = %d, ожидался 404 — интерфейс не существует", rec.Code)
	}
}

// TestRotateReturnsFreshConfigAndQR: старый конфиг у клиента уже не
// работает после ротации ключей, и оператору нужно чем-то заменить его
// немедленно — тем же откликом, что несёт выпуск нового пира.
func TestRotateReturnsFreshConfigAndQR(t *testing.T) {
	m := &fakeMutator{}
	srv := newTestServerWithMutator(t, m)
	rec := doAuthed(t, srv, http.MethodPost, "/api/ifaces/awg3/peers/abc123/rotate", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "qr_png_base64") {
		t.Fatal("ответ ротации обязан нести конфиг и QR: старый у клиента уже не работает")
	}
	if m.rotated != "abc123" {
		t.Errorf("ротирован %q, ожидался abc123", m.rotated)
	}
}

// TestRotateSurfacesStateConflictAs409 — находка финального ревью I4:
// checkRotateStateMatchesServer раньше заворачивала ошибку в
// issuer.ErrPostcondition, statusFor давала ей 500, а writeError на 5xx
// заменяет текст на «внутренняя ошибка» — причина уходила только в journal,
// оператор её не видел вовсе. issuer.ErrStateConflict — собственный класс
// именно для этого раннего (ДО применения к устройству) отказа, и статус
// 409 подходит по смыслу «состояние конфликтует», а не «сломалось что-то
// внутри».
func TestRotateSurfacesStateConflictAs409(t *testing.T) {
	m := &fakeMutator{err: fmt.Errorf("%w: пир %s числится включённым в peers.json, но его блока "+
		"нет в серверном конфиге", issuer.ErrStateConflict, "abc123")}
	rec := doAuthed(t, newTestServerWithMutator(t, m), http.MethodPost, "/api/ifaces/awg3/peers/abc123/rotate", nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("код = %d, ожидался 409: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "числится включённым в peers.json") {
		t.Errorf("причина расхождения не дошла до оператора (заменена на «внутренняя ошибка»?): %s", rec.Body)
	}
}

func TestGetDefaultsReturnsCurrentValues(t *testing.T) {
	m := &fakeMutator{defaults: store.Defaults{
		Endpoint: "1.2.3.4:51772", AllowedIPs: "0.0.0.0/0", Keepalive: "25",
	}}
	rec := doAuthed(t, newTestServerWithMutator(t, m), http.MethodGet, "/api/ifaces/awg3/defaults", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	var got store.Defaults
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Keepalive != "25" {
		t.Errorf("умолчания не доехали: %+v", got)
	}
}

func TestDefaultsGetPut(t *testing.T) {
	m := &fakeMutator{}
	srv := newTestServerWithMutator(t, m)
	rec := doAuthed(t, srv, http.MethodPut, "/api/ifaces/awg3/defaults",
		strings.NewReader(`{"endpoint":"1.2.3.4:51772","allowed_ips":"0.0.0.0/0","keepalive":"25","dns":""}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	if m.lastDefaults.Keepalive != "25" {
		t.Fatalf("умолчания не доехали: %+v", m.lastDefaults)
	}
}

// TestPutDefaultsSurfacesValidationError — умолчания проходят через
// ValidateDefaults (issuer.Service.SetDefaults); ошибка ввода обязана дойти
// до оператора дословно, тем же путём statusFor/writeError, что и у Add.
func TestPutDefaultsSurfacesValidationError(t *testing.T) {
	m := &fakeMutator{err: fmt.Errorf("%w: endpoint не задан", issuer.ErrInvalidInput)}
	rec := doAuthed(t, newTestServerWithMutator(t, m), http.MethodPut, "/api/ifaces/awg3/defaults",
		strings.NewReader(`{}`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("код = %d, ожидался 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "endpoint не задан") {
		t.Errorf("причина отказа не дошла до пользователя: %s", rec.Body)
	}
}

// --- Задача 8: генератор клиентского джиттера ---

// TestGenerateJitterМаршрут — маршрут ничего не пишет (fakeMutator не
// фиксирует вызов SetDefaults/Update), а только отдаёт готовую тройку;
// сохранение остаётся отдельным действием оператора (см. комментарий у
// handleGenerateJitter).
func TestGenerateJitterМаршрут(t *testing.T) {
	h := newTestServerWithMutator(t, &fakeMutator{}) // фейк, уже объявленный в этом файле
	rec := doAuthed(t, h, http.MethodPost, "/api/ifaces/awg3/generate/jitter", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d, тело %s", rec.Code, rec.Body.String())
	}
	var j issuer.Jitter
	if err := json.Unmarshal(rec.Body.Bytes(), &j); err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if j.Jc == 0 || j.Jmin >= j.Jmax {
		t.Fatalf("бессмысленная тройка: %+v", j)
	}
}

// TestGenerateJitterMissingOnUnknownInterface — mutatorFor, общий для всех
// мутирующих маршрутов, обязан отвечать 404 на неизвестный интерфейс и здесь
// тоже: генератор не должен молча выбрать первый попавшийся интерфейс.
func TestGenerateJitterMissingOnUnknownInterface(t *testing.T) {
	h := newTestServerWithMutator(t, &fakeMutator{})
	rec := doAuthed(t, h, http.MethodPost, "/api/ifaces/нет-такого/generate/jitter", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("код = %d, ожидался 404 — интерфейс не существует", rec.Code)
	}
}

// --- Задача 3 (спека 2026-08-24): маршрут генерации I1 ---

// TestGenerateSignatureMissingOnUnknownInterface — mutatorFor, общий для всех
// мутирующих маршрутов, обязан отвечать 404 на неизвестный интерфейс и здесь
// тоже.
func TestGenerateSignatureMissingOnUnknownInterface(t *testing.T) {
	h := newTestServerWithMutator(t, &fakeMutator{})
	rec := doAuthed(t, h, http.MethodPost, "/api/ifaces/нет-такого/generate/signature", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("код = %d, ожидался 404 — интерфейс не существует", rec.Code)
	}
}

// --- Задача 4 (спека 2026-08-25, раздел 5.5): выбор профиля мимикрии в маршруте ---

// newTestServerForMimicry строит сервер, где листер "awg3" отдаёт заданную
// сводку (в частности, ListenPort) НЕЗАВИСИМО от мутатора — в отличие от
// newTestServerWithMutator, который жёстко подставляет fakeLister{} с
// нулевым портом. Маршрутам generate/signature и generate/interface-params
// этой задачи нужен контроль над портом интерфейса, потому что именно из
// него выводится профиль мимикрии, когда оператор не указал его явно.
func newTestServerForMimicry(t *testing.T, m web.PeerMutator, summary issuer.IfaceSummary) http.Handler {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte("секрет"), 4)
	cfg := config.Default()
	cfg.Auth.User, cfg.Auth.Bcrypt = "admin", string(hash)
	reg := &fakeRegistry{
		metas:   []issuer.IfaceMeta{{ID: "awg3", Title: "awg3", Interface: "awg3"}},
		listers: map[string]web.PeerLister{"awg3": &fakeLister{summary: summary}},
	}
	mutators := &fakeMutatorRegistry{byID: map[string]web.PeerMutator{"awg3": m}}
	return web.NewServerWithMutator(cfg, reg, mutators).Handler()
}

// TestGenerateSignatureСЯвнымПрофилем — тело {"profile":"stun"} отдаёт STUN,
// вне зависимости от порта интерфейса: явное указание оператора обязано
// перебивать вывод по порту, а не просто дополнять его.
func TestGenerateSignatureСЯвнымПрофилем(t *testing.T) {
	// Порт нарочно НЕ 3478 (канонический для STUN) — явный выбор обязан
	// работать даже вопреки порту, иначе это не выбор, а подсказка.
	h := newTestServerForMimicry(t, &fakeMutator{}, issuer.IfaceSummary{ListenPort: 51772})
	rec := doAuthed(t, h, http.MethodPost, "/api/ifaces/awg3/generate/signature",
		strings.NewReader(`{"profile":"stun"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d, тело %s", rec.Code, rec.Body.String())
	}
	var got struct{ I1 string }
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if p, ok := issuer.DetectProfile(got.I1); !ok || p != issuer.MimicrySTUN {
		t.Fatalf("I1 = %q — DetectProfile дал (%q, %v), ожидался STUN", got.I1, p, ok)
	}
}

// TestGenerateSignatureРегистрПрофиляНормализуется — {"profile":"QUIC"} (капс)
// обязан сработать так же, как "quic": issuer.ValidProfile сознательно
// регистрозависима (см. её комментарий), а нормализация регистра — забота
// HTTP-границы, не типа.
func TestGenerateSignatureРегистрПрофиляНормализуется(t *testing.T) {
	h := newTestServerForMimicry(t, &fakeMutator{}, issuer.IfaceSummary{ListenPort: 51772})
	rec := doAuthed(t, h, http.MethodPost, "/api/ifaces/awg3/generate/signature",
		strings.NewReader(`{"profile":"QUIC"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d, тело %s", rec.Code, rec.Body.String())
	}
	var got struct{ I1 string }
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if p, ok := issuer.DetectProfile(got.I1); !ok || p != issuer.MimicryQUIC {
		t.Fatalf("I1 = %q — DetectProfile дал (%q, %v), ожидался QUIC", got.I1, p, ok)
	}
}

// TestGenerateSignatureБезТелаВыводитПрофильИзПорта — без тела и на порту
// 443 (канонический для QUIC) маршрут обязан сам вывести профиль, не
// заставляя оператора вводить очевидное.
func TestGenerateSignatureБезТелаВыводитПрофильИзПорта(t *testing.T) {
	h := newTestServerForMimicry(t, &fakeMutator{}, issuer.IfaceSummary{ListenPort: 443})
	rec := doAuthed(t, h, http.MethodPost, "/api/ifaces/awg3/generate/signature", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d, тело %s", rec.Code, rec.Body.String())
	}
	var got struct{ I1 string }
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if p, ok := issuer.DetectProfile(got.I1); !ok || p != issuer.MimicryQUIC {
		t.Fatalf("I1 = %q — DetectProfile дал (%q, %v), ожидался QUIC (порт 443)", got.I1, p, ok)
	}
}

// TestGenerateSignatureБезТелаНепонятныйПортДаётОшибку — без тела и на
// произвольном порту (никакому профилю не соответствует) маршрут обязан
// ответить внятной ошибкой, а НЕ выдумать профиль (раздел 5.5 спеки).
// Текст называет порт и перечисляет допустимые профили с портами.
func TestGenerateSignatureБезТелаНепонятныйПортДаётОшибку(t *testing.T) {
	h := newTestServerForMimicry(t, &fakeMutator{}, issuer.IfaceSummary{ListenPort: 52441})
	rec := doAuthed(t, h, http.MethodPost, "/api/ifaces/awg3/generate/signature", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("код %d, тело %s — ожидался 400", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"52441", "quic", "dns", "stun", "443", "53", "3478"} {
		if !strings.Contains(body, want) {
			t.Errorf("тело ошибки %q не содержит %q", body, want)
		}
	}
}

// TestGenerateSignatureНеизвестныйПрофиль400 — явно указанный, но
// неизвестный профиль — ошибка ввода, а не повод угадывать что-то другое.
func TestGenerateSignatureНеизвестныйПрофиль400(t *testing.T) {
	h := newTestServerForMimicry(t, &fakeMutator{}, issuer.IfaceSummary{ListenPort: 443})
	rec := doAuthed(t, h, http.MethodPost, "/api/ifaces/awg3/generate/signature",
		strings.NewReader(`{"profile":"http"}`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("код %d, тело %s — ожидался 400", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "http") {
		t.Errorf("тело ошибки %q не называет присланное значение", rec.Body.String())
	}
}

// --- Задача 9: генератор комплекта параметров для НОВОГО интерфейса ---

// serverConfForDiskTest — образец серверного файла для теста постусловия
// ниже. Содержимое неважно по существу (генератор его не открывает вовсе) —
// важно, что это настоящий файл на диске, чью контрольную сумму можно
// сверить до и после обращения к маршруту.
const serverConfForDiskTest = `[Interface]
PrivateKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
ListenPort = 51772
S1 = 39
S2 = 41
S3 = 62
S4 = 23
H1 = 1148223582
H2 = 1919088219
H3 = 1268881132
H4 = 1097565754
HeaderProtectionKey = ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=
ContentPaddingAddition = 0-64
`

// snapshotTree снимает состояние каталога: относительный путь → SHA-256
// содержимого. Хеш, а не время модификации: mtime имеет грубое разрешение и
// на Windows, и на многих файловых системах, поэтому запись, уложившаяся в
// один тик, осталась бы незаметной — а именно такую запись тест и обязан
// поймать. Новые и исчезнувшие файлы ловятся тем, что сравнивается вся карта
// целиком, а не значения по заранее известным ключам.
func snapshotTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			out[rel+"/"] = "<каталог>"
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		out[rel] = fmt.Sprintf("%x", sha256.Sum256(b))
		return nil
	})
	if err != nil {
		t.Fatalf("обход %s: %v", root, err)
	}
	return out
}

// realServiceEnv поднимает сервер с НАСТОЯЩИМ issuer.Service поверх
// временного каталога — не с fakeMutator. Для теста постусловия это
// принципиально: fakeMutator ничего не пишет на диск по построению, и тест
// на нём доказывал бы свойство фейка, а не свойство панели.
func realServiceEnv(t *testing.T) (http.Handler, string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "awg3")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	confPath := filepath.Join(dir, "awg3.conf")
	if err := os.WriteFile(confPath, []byte(serverConfForDiskTest), 0o600); err != nil {
		t.Fatal(err)
	}
	// peers.json и defaults.json кладутся руками: генератор не обязан их
	// создавать, но обязан не трогать уже существующие.
	if err := os.WriteFile(filepath.Join(dir, "peers.json"), []byte(`{"peers":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "defaults.json"),
		[]byte(`{"endpoint":"1.2.3.4:51772","allowed_ips":"0.0.0.0/0","jc":6,"jmin":70,"jmax":400}`), 0o600); err != nil {
		t.Fatal(err)
	}
	base := filepath.ToSlash(dir)
	hash, _ := bcrypt.GenerateFromPassword([]byte("секрет"), 4)
	cfg := config.Default()
	cfg.Auth.User, cfg.Auth.Bcrypt = "admin", string(hash)
	cfg.Interfaces = []config.Interface{{
		ID: "awg3", Title: "awg3", Interface: "awg3",
		Config: confPath, BinDir: dir,
		Client: config.Client{Endpoint: "1.2.3.4:51772", AllowedIPs: "0.0.0.0/0"},
		Storage: config.Storage{
			State:         base + "/peers.json",
			Backups:       base + "/backups",
			Keys:          base + "/keys",
			ClientConfigs: base + "/clients",
		},
	}}
	reg := issuer.NewRegistry(cfg, func(binDir string) runtime.Runner {
		return runtime.NewFake(serverConfForDiskTest)
	})
	return web.NewServerWithMutator(cfg, web.Adapt(reg), web.AdaptMutators(reg)).Handler(), root
}

// TestГенераторИнтерфейсаНичегоНеПишетНаДиск — постусловие правила 2
// репозитория в форме, исполнимой в CI. Ручной вариант из брифа (md5sum по
// боевым путям до и после нажатия кнопки) проверяет ровно то же самое, но
// только на живом хосте и только когда о нём кто-то вспомнит.
//
// Снимок берётся со ВСЕГО каталога состояния интерфейса — серверный конфиг,
// peers.json, defaults.json и всё, что появится рядом, — и сравнивается
// целиком. Поэтому тест падает не только на изменении известного файла, но и
// на появлении нового: если завтра обработчик начнёт, скажем, складывать
// сгенерированный комплект «на будущее» в pending-файл, это будет видно
// здесь, хотя ни одного заранее известного имени в проверке не названо.
func TestГенераторИнтерфейсаНичегоНеПишетНаДиск(t *testing.T) {
	h, root := realServiceEnv(t)
	before := snapshotTree(t, root)
	rec := doAuthed(t, h, http.MethodGet, "/api/ifaces/awg3/generate/interface-params", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d, тело %s", rec.Code, rec.Body.String())
	}
	after := snapshotTree(t, root)
	if reflect.DeepEqual(before, after) {
		return
	}
	for name, sum := range after {
		if old, ok := before[name]; !ok {
			t.Errorf("после генерации появился %s — генератор обязан только печатать текст", name)
		} else if old != sum {
			t.Errorf("после генерации изменился %s — генератор обязан только печатать текст", name)
		}
	}
	for name := range before {
		if _, ok := after[name]; !ok {
			t.Errorf("после генерации исчез %s", name)
		}
	}
	t.Fatal("состояние интерфейса на диске изменилось при обращении к генератору")
}

// TestGenerateInterfaceParamsМаршрут — ответ обязан нести и сам комплект, и
// готовый текст блока: браузер не собирает конфиг строками сам, иначе
// порядок и формат полей существовали бы в двух местах и однажды разошлись
// бы.
func TestGenerateInterfaceParamsМаршрут(t *testing.T) {
	h := newTestServerWithMutator(t, &fakeMutator{})
	rec := doAuthed(t, h, http.MethodGet, "/api/ifaces/awg3/generate/interface-params", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d, тело %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Params       issuer.InterfaceParams `json:"params"`
		ServerBlock  string                 `json:"server_block"`
		ClientJitter issuer.Jitter          `json:"client_jitter"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("разбор: %v (тело %s)", err, rec.Body.String())
	}
	if got.ServerBlock != got.Params.ServerBlock() {
		t.Errorf("текст блока в ответе не совпадает с комплектом:\n%s\n---\n%s",
			got.ServerBlock, got.Params.ServerBlock())
	}
	if got.Params.S1 == 0 || got.Params.H1 == (issuer.HRange{}) || got.Params.HeaderProtectionKey == "" {
		t.Errorf("комплект пуст: %+v", got.Params)
	}
	if got.ClientJitter != got.Params.Jitter {
		t.Errorf("client_jitter (%+v) разошёлся с джиттером комплекта (%+v)",
			got.ClientJitter, got.Params.Jitter)
	}
	// Джиттер — клиентский, серверу он неизвестен: в тексте для [Interface]
	// его быть не должно (см. TestServerBlockДетерминирован в issuer).
	for _, line := range strings.Split(got.ServerBlock, "\n") {
		key, _, _ := strings.Cut(line, "=")
		switch strings.TrimSpace(key) {
		case "Jc", "Jmin", "Jmax":
			t.Error("клиентский джиттер попал в блок серверного [Interface]")
		}
	}
}

// TestGenerateInterfaceParamsJSONПоляНижнегоРегистра — страж формы ответа по
// СЫРЫМ ключам JSON, а не через разбор в Go-структуру. encoding/json
// сопоставляет "H1"/"h1" одному и тому же полю без разбора регистра, поэтому
// TestGenerateInterfaceParamsМаршрут выше (разбор в issuer.InterfaceParams)
// не заметил бы регресс тегов HRange на заглавные — а любой клиент, кроме
// Go, сырые ключи различает, и "h1":{"Lo":...} вместо "h1":{"lo":...} для
// него уже другое поле. Находка ревью задачи 1: тегов lo/hi не было вовсе, и
// ответ уходил как {"Lo":..,"Hi":..} вразрез с остальным API (jc, jmin,
// header_protection_key и т.д. — все в нижнем регистре).
func TestGenerateInterfaceParamsJSONПоляНижнегоРегистра(t *testing.T) {
	h := newTestServerWithMutator(t, &fakeMutator{})
	rec := doAuthed(t, h, http.MethodGet, "/api/ifaces/awg3/generate/interface-params", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d, тело %s", rec.Code, rec.Body.String())
	}
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("тело не JSON: %v", err)
	}
	params, ok := raw["params"].(map[string]any)
	if !ok {
		t.Fatalf("params отсутствует или не объект: %#v", raw["params"])
	}
	for _, hName := range []string{"h1", "h2", "h3", "h4"} {
		hv, ok := params[hName].(map[string]any)
		if !ok {
			t.Fatalf("params.%s отсутствует или не объект — тег json на HRange не в нижнем регистре: %#v",
				hName, params[hName])
		}
		for _, key := range []string{"lo", "hi"} {
			if _, ok := hv[key]; !ok {
				t.Errorf("params.%s.%s отсутствует: %#v", hName, key, hv)
			}
		}
	}
	if _, ok := params["i1"]; !ok {
		t.Errorf("params.i1 отсутствует")
	}
}

// --- Задача 4 (спека 2026-08-25, раздел 7): выбор профиля в комплекте нового интерфейса ---

// TestGenerateInterfaceParamsСЯвнымПрофилем — ?profile=stun отдаёт в ответе
// профиль stun, его канонический порт 3478, и params.i1 — пакет ИМЕННО
// этого профиля (а не безусловный DNS, как до задачи 4).
func TestGenerateInterfaceParamsСЯвнымПрофилем(t *testing.T) {
	h := newTestServerWithMutator(t, &fakeMutator{})
	rec := doAuthed(t, h, http.MethodGet, "/api/ifaces/awg3/generate/interface-params?profile=stun", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d, тело %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Params         issuer.InterfaceParams `json:"params"`
		MimicryProfile string                 `json:"mimicry_profile"`
		MimicryPort    int                    `json:"mimicry_port"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("разбор: %v (тело %s)", err, rec.Body.String())
	}
	if got.MimicryProfile != "stun" || got.MimicryPort != 3478 {
		t.Fatalf("mimicry_profile/mimicry_port = %q/%d, ожидалось stun/3478", got.MimicryProfile, got.MimicryPort)
	}
	if p, ok := issuer.DetectProfile(got.Params.I1); !ok || p != issuer.MimicrySTUN {
		t.Fatalf("params.i1 = %q — DetectProfile дал (%q, %v), ожидался STUN", got.Params.I1, p, ok)
	}
}

// TestGenerateInterfaceParamsУмолчаниеПрофиля — находка ревью задачи 4:
// ни один тест не проверял, что умолчание профиля (без ?profile=) реально
// попадает в ответ. Реализация была верна, но регрессия, тихо выбросившая
// mimicry_profile/mimicry_port из ответа или саму строку умолчания в
// handleGenerateInterfaceParams, прошла бы весь набор незамеченной — точно
// так же, как раньше ловил TestGenerateInterfaceParamsСЯвнымПрофилем, но
// только для ЯВНОГО профиля.
//
// Ожидается QUIC/443 (задача 5, спека 2026-08-25, раздел 5.7 брифа) — не
// DNS/53, как было до этой задачи: у нового интерфейса живого порта ещё
// нет, выводить профиль неоткуда, а 443 — лучшая рекомендация из наших же
// (раздел 10.2 спеки), ровно так собран боевой эталон.
func TestGenerateInterfaceParamsУмолчаниеПрофиля(t *testing.T) {
	h := newTestServerWithMutator(t, &fakeMutator{})
	rec := doAuthed(t, h, http.MethodGet, "/api/ifaces/awg3/generate/interface-params", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d, тело %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Params         issuer.InterfaceParams `json:"params"`
		MimicryProfile string                 `json:"mimicry_profile"`
		MimicryPort    int                    `json:"mimicry_port"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("разбор: %v (тело %s)", err, rec.Body.String())
	}
	if got.MimicryProfile != "quic" || got.MimicryPort != 443 {
		t.Fatalf("mimicry_profile/mimicry_port = %q/%d, ожидалось quic/443 (умолчание без ?profile=)",
			got.MimicryProfile, got.MimicryPort)
	}
	if p, ok := issuer.DetectProfile(got.Params.I1); !ok || p != issuer.MimicryQUIC {
		t.Fatalf("params.i1 = %q — DetectProfile дал (%q, %v), ожидался QUIC", got.Params.I1, p, ok)
	}
	if got.Params.ListenPort != 443 {
		t.Errorf("params.listen_port = %d, ожидалось 443 — ServerBlock() печатает его первой строкой", got.Params.ListenPort)
	}
}

// TestGenerateInterfaceParamsНеизвестныйПрофиль400 — та же дисциплина
// разбора, что и у generate/signature: опечатка в query — 400 с текстом, а
// не тихая подстановка чего-то другого.
func TestGenerateInterfaceParamsНеизвестныйПрофиль400(t *testing.T) {
	h := newTestServerWithMutator(t, &fakeMutator{})
	rec := doAuthed(t, h, http.MethodGet, "/api/ifaces/awg3/generate/interface-params?profile=http", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("код %d, тело %s — ожидался 400", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "http") {
		t.Errorf("тело ошибки %q не называет присланное значение", rec.Body.String())
	}
}

// TestGenerateInterfaceParamsMissingOnUnknownInterface — mutatorFor
// используется в обработчике ТОЛЬКО ради этой проверки: генератор не зависит
// от интерфейса ни одним значением, но маршрут висит внутри
// /api/ifaces/{iface} и обязан отвечать 404 на несуществующий, а не делать
// вид, что всё в порядке.
func TestGenerateInterfaceParamsMissingOnUnknownInterface(t *testing.T) {
	h := newTestServerWithMutator(t, &fakeMutator{})
	rec := doAuthed(t, h, http.MethodGet, "/api/ifaces/нет-такого/generate/interface-params", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("код = %d, ожидался 404 — интерфейс не существует", rec.Code)
	}
}

// TestFullBuildIndexHasNewInterfaceTab — вкладка генератора и, главное,
// предупреждение о том, что ничего не применено. Текст предупреждения
// проверяется дословно: это не украшение интерфейса, а единственное, что
// отличает «заготовку для нового туннеля» от «кнопки, которая сейчас
// перенастроит работающий сервер», в глазах человека, который её нажимает.
func TestFullBuildIndexHasNewInterfaceTab(t *testing.T) {
	rec := doAuthed(t, newTestServerWithMutator(t, &fakeMutator{}), http.MethodGet, "/", nil)
	for _, want := range []string{
		`data-tab="newiface"`,
		"Новый интерфейс",
		"/generate/interface-params",
		"Ничего не применено.",
		"вставьте её в",
		"нового сервера руками",
		"Действующий интерфейс не затронут.",
	} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("в разметке нет %q", want)
		}
	}
}

// TestFullBuildIndexNewInterfaceTabPokazyvaetI1 — находка финального ревью
// (Important #3): InterfaceParams.I1 генерировался и уходил в ответ, но
// вкладка «Новый интерфейс» его нигде не показывала — оператор, читающий
// только страницу, не подозревал бы о его существовании. Проверка идёт
// отдельным тестом, а не строкой в TestFullBuildIndexHasNewInterfaceTab
// выше: там список — дословный текст предупреждения о неприменении, и
// смешивать с ним разметку третьего блока значило бы затемнить, за каким
// именно свойством следит каждая из двух проверок.
//
// Дословно проверяется и формулировка про «свой I1»: без неё блок читался
// бы как «вот I1 этого интерфейса», что для НОВОГО интерфейса неверно —
// issuer.Service.defaults() генерирует собственный, не связанный с этим,
// I1 при первом создании defaults.json (см. комментарий там же).
func TestFullBuildIndexNewInterfaceTabPokazyvaetI1(t *testing.T) {
	rec := doAuthed(t, newTestServerWithMutator(t, &fakeMutator{}), http.MethodGet, "/", nil)
	for _, want := range []string{
		`id="ifacei1"`,
		"Сигнатурный пакет I1",
		"defaults.json",
		"панель сеет туда свой, независимо сгенерированный",
	} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("в разметке вкладки «Новый интерфейс» нет %q — блок I1 не показан "+
				"или потерял пояснение про независимый сев умолчаний", want)
		}
	}
}

// TestFullBuildIndexHasMimicryProfileSelectors — задача 5 (спека 2026-08-25,
// раздел 5.6 брифа): рядом с обеими кнопками «Сгенерировать I1» (вкладка
// «Умолчания» и модалка правки пира) обязан быть селектор профиля из трёх
// значений — без него подсказка mimicrySeedFor «досейте I1 кнопкой в
// консоли, выбрав профиль вручную» (internal/issuer/service.go) обещала бы
// то, чего в разметке нет (см. её же комментарий, возвращающий этот оборот).
func TestFullBuildIndexHasMimicryProfileSelectors(t *testing.T) {
	rec := doAuthed(t, newTestServerWithMutator(t, &fakeMutator{}), http.MethodGet, "/", nil)
	for _, want := range []string{
		`id="editi1profile"`,
		`id="defaultsi1profile"`,
		`value="quic"`, `value="dns"`, `value="stun"`,
	} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("в разметке нет %q — селектор профиля мимикрии у кнопки «Сгенерировать I1» отсутствует", want)
		}
	}
}

// Спека 2026-10-29, раздел 7: в окне выдачи — минимальные версии клиентов,
// понимающих AWG 3.1, с датой сверки. Окно выдачи есть только в полной сборке.
func TestIndexПоказываетМатрицуКлиентов(t *testing.T) {
	h := newTestServerWithMutator(t, &fakeMutator{})
	body := doAuthed(t, h, http.MethodGet, "/", nil).Body.String()
	for _, want := range []string{`id="clientmatrix"`, "5.0.1.5", "Hiddify", "сверено 29.10.2026"} {
		if !strings.Contains(body, want) {
			t.Errorf("в разметке нет %q", want)
		}
	}
}

// Спека 2026-10-29, раздел 6: ссылка импорта AmneziaVPN и её QR.
func TestGetVPNURIИQR(t *testing.T) {
	h := newTestServerWithMutator(t, &fakeMutator{})
	rec := doAuthed(t, h, http.MethodGet, "/api/ifaces/awg3/peers/abc123/vpnuri", nil)
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Body.String(), "vpn://") {
		t.Fatalf("vpnuri: код %d, тело %q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("vpn:// несёт приватный ключ — Cache-Control: no-store обязателен")
	}
	rec = doAuthed(t, h, http.MethodGet, "/api/ifaces/awg3/peers/abc123/vpnqr", nil)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("vpnqr: код %d, Content-Type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	body := doAuthed(t, h, http.MethodGet, "/", nil).Body.String()
	if !strings.Contains(body, `id="qrvpn"`) {
		t.Error("в окне выдачи нет переключателя на QR для AmneziaVPN")
	}
}

func TestPeerMimicryAndControlRoutes(t *testing.T) {
	h := newTestServerWithMutator(t, &fakeMutator{})
	status := doAuthed(t, h, http.MethodGet, "/api/ifaces/awg3/peers/abc123/mimicry", nil)
	if status.Code != http.StatusOK || status.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d, caching=%q", status.Code, status.Header().Get("Cache-Control"))
	}
	var data map[string]any
	if err := json.Unmarshal(status.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	if len(data) != 6 || data["profile"] != "stun" || data["source"] != "peer" ||
		data["endpoint_port"] != float64(3478) || data["profile_port"] != float64(3478) ||
		data["port_mismatch"] != false || data["has_cps"] != true {
		t.Fatalf("unexpected metadata shape: %v", data)
	}
	control := doAuthed(t, h, http.MethodGet, "/api/ifaces/awg3/peers/abc123/config-no-cps", nil)
	if control.Code != http.StatusOK || control.Header().Get("Cache-Control") != "no-store" ||
		control.Header().Get("Content-Disposition") != `attachment; filename="peer-no-cps.conf"` {
		t.Fatalf("control response status=%d, headers=%v", control.Code, control.Header())
	}
}
