// Package keenetictune adapts AWG Manager v2.20.6 to junk-parameter trials.
package keenetictune

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/junktune"
)

const (
	requestTimeout  = 12 * time.Second
	probeTimeout    = 24 * time.Second
	probeSeparation = 350 * time.Millisecond
	probeCount      = 2
)

var (
	tunnelIDPattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,31}$`)
	wanPattern      = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,32}$`)
)

type Config struct {
	BaseURL          string
	MCPToken         string
	RESTToken        string
	TunnelID         string
	ExpectedName     string
	ExpectedEndpoint string
	ExpectedRoute    string
}

type Router struct {
	config Config
	base   url.URL
	client *http.Client

	mu       sync.Mutex
	protocol string
	session  string
	sequence uint64
	trial    *trialStart
}

type trialStart struct {
	startedAt         time.Time
	previousHandshake time.Time
	configuredRoute   string
	resolvedRoute     string
	wireFingerprint   [32]byte
	jitter            issuer.Jitter
}

type tunnelDetails struct {
	ID            string             `json:"id"`
	Name          string             `json:"name"`
	Backend       string             `json:"backend"`
	State         string             `json:"state"`
	Enabled       *bool              `json:"enabled"`
	DefaultRoute  *bool              `json:"defaultRoute"`
	ISPInterface  string             `json:"ispInterface"`
	InterfaceName string             `json:"interfaceName"`
	NDMSName      string             `json:"ndmsName"`
	Interface     *interfaceSettings `json:"interface"`
	Peer          *peerSettings      `json:"peer"`
	StateInfo     *struct {
		InterfaceUp *bool `json:"interfaceUp"`
	} `json:"stateInfo"`
	ConnectivityCheck *struct {
		Method string `json:"method"`
	} `json:"connectivityCheck"`
	Obfuscator *struct{} `json:"obfuscator"`
	PingCheck  *struct {
		Enabled bool `json:"enabled"`
	} `json:"pingCheck"`
}

type listedTunnel struct {
	ID                 string  `json:"id"`
	Name               string  `json:"name"`
	Backend            string  `json:"backend"`
	AWGVersion         string  `json:"awgVersion"`
	Status             string  `json:"status"`
	Enabled            *bool   `json:"enabled"`
	DefaultRoute       *bool   `json:"defaultRoute"`
	Endpoint           string  `json:"endpoint"`
	ISPInterface       string  `json:"ispInterface"`
	ResolvedInterface  string  `json:"resolvedIspInterface"`
	InterfaceName      string  `json:"interfaceName"`
	NDMSName           string  `json:"ndmsName"`
	HasAddressConflict bool    `json:"hasAddressConflict"`
	StartedAt          string  `json:"startedAt"`
	LastHandshake      string  `json:"lastHandshake"`
	Rx                 *uint64 `json:"rxBytes"`
	Tx                 *uint64 `json:"txBytes"`
}

type observedTunnel struct {
	snapshot junktune.Snapshot
	details  tunnelDetails
	listed   listedTunnel
	all      []listedTunnel
}

func New(cfg Config) (*Router, error) {
	base, err := url.Parse(cfg.BaseURL)
	if err != nil || base.Hostname() == "" || base.User != nil || base.Opaque != "" ||
		(base.Path != "" && base.Path != "/") || base.RawPath != "" || base.RawQuery != "" ||
		base.ForceQuery || base.Fragment != "" || strings.Contains(cfg.BaseURL, "#") {
		return nil, errors.New("задайте только схему и адрес AWG Manager")
	}
	if base.Scheme != "https" && (base.Scheme != "http" || !localHTTPHost(base.Hostname())) {
		return nil, errors.New("для AWG Manager требуется HTTPS или локальный HTTP-адрес")
	}
	if !validToken(cfg.MCPToken) || !validToken(cfg.RESTToken) || cfg.MCPToken == cfg.RESTToken {
		return nil, errors.New("задайте отдельные ключи MCP и REST AWG Manager")
	}
	if !tunnelIDPattern.MatchString(cfg.TunnelID) || strings.TrimSpace(cfg.ExpectedName) == "" ||
		strings.ContainsAny(cfg.ExpectedName, "\r\n") || !validEndpoint(cfg.ExpectedEndpoint) {
		return nil, errors.New("задайте ID, имя и endpoint тестового туннеля AWG Manager")
	}
	if !validExpectedRoute(cfg.ExpectedRoute) ||
		(cfg.ExpectedRoute == "tunnel:"+cfg.TunnelID) {
		return nil, errors.New("некорректный ожидаемый маршрут тестового туннеля")
	}
	transport := &http.Transport{}
	if defaults, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = defaults.Clone()
		transport.Proxy = nil
	}
	return &Router{config: cfg, base: *base, client: &http.Client{
		Timeout: requestTimeout, Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}, nil
}

func localHTTPHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast())
}

func validToken(token string) bool {
	return len(token) > 0 && len(token) <= 1024 &&
		strings.IndexFunc(token, func(r rune) bool { return r < 33 || r > 126 }) == -1
}

func validEndpoint(endpoint string) bool {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" || strings.ContainsAny(host, "/@?# \t\r\n") {
		return false
	}
	n, err := strconv.ParseUint(port, 10, 16)
	return err == nil && n != 0
}

func validExpectedRoute(route string) bool {
	switch {
	case route == "", route == "auto":
		return true
	case strings.HasPrefix(route, "tunnel:"):
		return tunnelIDPattern.MatchString(strings.TrimPrefix(route, "tunnel:"))
	default:
		return wanPattern.MatchString(strings.TrimPrefix(route, "wan:"))
	}
}

func (r *Router) Snapshot(ctx context.Context) (junktune.Snapshot, error) {
	current, err := r.inspect(ctx)
	return current.snapshot, err
}

func (r *Router) inspect(ctx context.Context) (observedTunnel, error) {
	current, err := r.observe(ctx)
	if err != nil {
		return observedTunnel{}, err
	}
	if err := r.checkIsolation(ctx, current); err != nil {
		return observedTunnel{}, err
	}
	return current, nil
}

func (r *Router) observe(ctx context.Context) (observedTunnel, error) {
	var detail tunnelDetails
	query := url.Values{"id": {r.config.TunnelID}}
	if err := r.rest(ctx, "/api/tunnels/get", query, &detail); err != nil {
		return observedTunnel{}, err
	}
	if detail.ID != r.config.TunnelID || detail.Name != r.config.ExpectedName ||
		detail.Peer == nil || detail.Peer.Endpoint != r.config.ExpectedEndpoint {
		return observedTunnel{}, errors.New("идентификация тестового туннеля AWG Manager изменилась")
	}
	if detail.Backend != "kernel" || detail.Obfuscator != nil || detail.Enabled == nil ||
		detail.DefaultRoute == nil || *detail.DefaultRoute {
		return observedTunnel{}, errors.New("требуется отдельный kernel-туннель без default route и внешнего обфускатора")
	}
	if !r.routeMatches(detail.ISPInterface) {
		return observedTunnel{}, errors.New("маршрут выхода тестового туннеля изменился")
	}
	if detail.ConnectivityCheck != nil && detail.ConnectivityCheck.Method != "" &&
		detail.ConnectivityCheck.Method != "http" {
		return observedTunnel{}, errors.New("для тестового туннеля требуется HTTP-проверка")
	}
	if detail.PingCheck != nil && detail.PingCheck.Enabled {
		return observedTunnel{}, errors.New("отключите мониторинг с авторестартом для тестового туннеля")
	}
	if detail.Interface == nil || detail.Interface.MTU < 576 || detail.StateInfo == nil ||
		detail.StateInfo.InterfaceUp == nil {
		return observedTunnel{}, errors.New("AWG Manager не вернул полное состояние тестового туннеля")
	}
	if _, err := netip.ParsePrefix(detail.Interface.Address); err != nil {
		return observedTunnel{}, errors.New("некорректный локальный адрес тестового туннеля")
	}
	if key, err := base64.StdEncoding.DecodeString(detail.Peer.PublicKey); err != nil || len(key) != 32 {
		return observedTunnel{}, errors.New("некорректный публичный ключ сервера тестового туннеля")
	}
	var list *[]listedTunnel
	if err := r.rest(ctx, "/api/tunnels/list", nil, &list); err != nil {
		return observedTunnel{}, err
	}
	if list == nil {
		return observedTunnel{}, errors.New("AWG Manager не вернул список туннелей")
	}
	for _, row := range *list {
		if row.ID != detail.ID {
			continue
		}
		if row.Name != detail.Name || row.Backend != "kernel" || row.AWGVersion != "awg3.1" ||
			row.Endpoint != detail.Peer.Endpoint || row.DefaultRoute == nil || *row.DefaultRoute ||
			row.HasAddressConflict || row.Enabled == nil || *row.Enabled != *detail.Enabled ||
			row.Rx == nil || row.Tx == nil || !r.routeMatches(row.ISPInterface) {
			return observedTunnel{}, errors.New("сводка AWG Manager не подтверждает изолированный AWG 3.1-туннель")
		}
		fingerprint, err := detail.wireFingerprint()
		if err != nil {
			return observedTunnel{}, err
		}
		return observedTunnel{snapshot: junktune.Snapshot{
			Jitter: detail.Interface.Jitter, MTU: detail.Interface.MTU,
			Running: *detail.StateInfo.InterfaceUp, Enabled: *detail.Enabled,
			Endpoint: detail.Peer.Endpoint, LocalAddress: detail.Interface.Address,
			ServerPublicKey: detail.Peer.PublicKey, WireFingerprint: fingerprint,
			Mimicry: [5]string{detail.Interface.I1, detail.Interface.I2, detail.Interface.I3, detail.Interface.I4, detail.Interface.I5},
			Headers: [4]string{detail.Interface.H1, detail.Interface.H2, detail.Interface.H3, detail.Interface.H4},
			Padding: [4]int{detail.Interface.S1, detail.Interface.S2, detail.Interface.S3, detail.Interface.S4},
		}, details: detail, listed: row, all: *list}, nil
	}
	return observedTunnel{}, errors.New("тестовый туннель отсутствует в списке AWG Manager")
}

func (r *Router) routeMatches(actual string) bool {
	expected := r.config.ExpectedRoute
	if actual == "" {
		actual = "auto"
	}
	if expected == "" {
		return wanPattern.MatchString(strings.TrimPrefix(actual, "wan:")) && actual != "none"
	}
	return strings.TrimPrefix(actual, "wan:") == strings.TrimPrefix(expected, "wan:")
}

func (r *Router) SetJitter(ctx context.Context, jitter issuer.Jitter) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	current, err := r.inspect(ctx)
	if err != nil {
		return err
	}
	if current.snapshot.Running || current.snapshot.Enabled || !inactiveState(current.details.State) {
		return errors.New("изменение джиттера допускается на остановленном тестовом туннеле")
	}
	if jitter != (issuer.Jitter{}) && (jitter.Jc < 1 || jitter.Jc > 122 ||
		jitter.Jmin < 1 || jitter.Jmax <= jitter.Jmin ||
		jitter.Jmax >= current.snapshot.MTU || jitter.Jmax > 1280) {
		return errors.New("тройка джиттера не входит в допустимый диапазон")
	}
	if current.snapshot.Jitter == jitter {
		return nil
	}
	if err := r.call(ctx, "update_tunnel_settings", map[string]any{
		"tunnelId": r.config.TunnelID, "awg": jitter,
	}, nil); err != nil {
		return err
	}
	after, err := r.observe(ctx)
	if err != nil {
		return err
	}
	expected := current.snapshot
	expected.Jitter = jitter
	if after.snapshot != expected {
		return errors.New("AWG Manager не подтвердил изменение только тройки джиттера")
	}
	return nil
}

func (r *Router) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	current, err := r.inspect(ctx)
	if err != nil {
		return err
	}
	if current.snapshot.Running || current.snapshot.Enabled || !inactiveState(current.details.State) {
		return errors.New("перед пробой тестовый туннель должен быть остановлен и отключён")
	}
	r.trial = nil
	if err := r.control(ctx, "start"); err != nil {
		return err
	}
	after, err := r.waitForState(ctx, true)
	if err != nil {
		return err
	}
	startedAt := parseTimestamp(after.listed.StartedAt)
	if startedAt.IsZero() {
		return errors.New("AWG Manager не вернул время запуска тестового туннеля")
	}
	r.trial = &trialStart{
		startedAt: startedAt, previousHandshake: parseTimestamp(current.listed.LastHandshake),
		configuredRoute: after.details.ISPInterface, resolvedRoute: after.listed.ResolvedInterface,
		wireFingerprint: current.snapshot.WireFingerprint, jitter: current.snapshot.Jitter,
	}
	return nil
}

func (r *Router) Stop(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.trial = nil
	current, err := r.inspect(ctx)
	if err != nil {
		return err
	}
	if !current.snapshot.Running && !current.snapshot.Enabled && inactiveState(current.details.State) {
		return nil
	}
	if err := r.control(ctx, "stop"); err != nil {
		return err
	}
	_, err = r.waitForState(ctx, false)
	return err
}

func (r *Router) waitForState(ctx context.Context, running bool) (observedTunnel, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	for {
		current, err := r.observe(ctx)
		if err != nil {
			return observedTunnel{}, err
		}
		statusMatches := current.snapshot.Running && current.snapshot.Enabled
		if !running {
			statusMatches = !current.snapshot.Running && !current.snapshot.Enabled && inactiveState(current.details.State)
		}
		if statusMatches {
			return current, nil
		}
		if err := wait(ctx, 200*time.Millisecond); err != nil {
			return observedTunnel{}, errors.New("AWG Manager не подтвердил смену состояния тестового туннеля")
		}
	}
}

func inactiveState(state string) bool {
	switch state {
	case "disabled", "disconnected", "stopped", "not_created", "error", "broken":
		return true
	default:
		return false
	}
}

func (r *Router) Probe(ctx context.Context) (junktune.Measurement, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.trial == nil {
		return junktune.Measurement{}, errors.New("сначала заново запустите тестовый туннель")
	}
	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	before, err := r.observe(probeCtx)
	if err != nil {
		return junktune.Measurement{}, err
	}
	if !r.trialRunning(before) {
		return junktune.Measurement{}, nil
	}
	var total time.Duration
	for i := 0; i < probeCount; i++ {
		var result struct {
			TunnelID  string `json:"tunnelId"`
			Connected *bool  `json:"connected"`
			LatencyMS int64  `json:"latencyMs"`
		}
		if err := r.call(probeCtx, "test_connectivity", map[string]string{"tunnelId": r.config.TunnelID}, &result); err != nil {
			return junktune.Measurement{}, err
		}
		if result.TunnelID != r.config.TunnelID || result.Connected == nil {
			return junktune.Measurement{}, errors.New("AWG Manager не подтвердил цель проверки HTTP")
		}
		if !*result.Connected || result.LatencyMS <= 0 || result.LatencyMS > probeTimeout.Milliseconds() {
			return junktune.Measurement{}, nil
		}
		after, err := r.observe(probeCtx)
		if err != nil {
			return junktune.Measurement{}, err
		}
		handshake := parseTimestamp(after.listed.LastHandshake)
		if !r.trialRunning(after) || handshake.Before(r.trial.startedAt) ||
			!handshake.After(r.trial.previousHandshake) ||
			*after.listed.Rx <= *before.listed.Rx || *after.listed.Tx <= *before.listed.Tx {
			return junktune.Measurement{}, nil
		}
		total += time.Duration(result.LatencyMS) * time.Millisecond
		before = after
		if i+1 < probeCount {
			if err := wait(probeCtx, probeSeparation); err != nil {
				return junktune.Measurement{}, err
			}
		}
	}
	return junktune.Measurement{Success: true, Latency: total / probeCount}, nil
}

func (r *Router) trialRunning(current observedTunnel) bool {
	return current.snapshot.Running && current.snapshot.Enabled &&
		parseTimestamp(current.listed.StartedAt).Equal(r.trial.startedAt) &&
		current.details.ISPInterface == r.trial.configuredRoute &&
		current.listed.ResolvedInterface == r.trial.resolvedRoute &&
		current.snapshot.WireFingerprint == r.trial.wireFingerprint &&
		current.snapshot.Jitter == r.trial.jitter
}

func parseTimestamp(raw string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, raw)
	return t
}

func wait(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
