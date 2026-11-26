package keenetictune

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/junktune"
)

const (
	testTunnelID        = "awg55"
	testName            = "AWG tuner test"
	testEndpoint        = "203.0.113.10:3478"
	testMCPToken        = "mcp-token-for-test"
	testRESTToken       = "rest-token-for-test"
	testServerPublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type fakeManager struct {
	t                    *testing.T
	id, name, backend    string
	endpoint, route      string
	checkMode            string
	defaultRoute         bool
	binding              string
	running, enabled     bool
	staleHandshake       bool
	noRx                 bool
	unsafeLog            bool
	redirect             bool
	startedAt, handshake time.Time
	rx, tx               uint64
	jitter               issuer.Jitter
	initPacket           string
	calls                []string
	httpProbes           int
}

func makeRouter(t *testing.T) (*Router, *fakeManager) {
	t.Helper()
	conf := Config{
		BaseURL: "http://127.0.0.1:2222", MCPToken: testMCPToken, RESTToken: testRESTToken,
		TunnelID: testTunnelID, ExpectedName: testName, ExpectedEndpoint: testEndpoint,
	}
	router, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeManager{
		t: t, id: testTunnelID, name: testName, backend: "kernel",
		endpoint: testEndpoint, checkMode: "http", jitter: issuer.Jitter{Jc: 4, Jmin: 64, Jmax: 400},
	}
	router.client.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		f.serveHTTP(rec, req)
		return rec.Result(), nil
	})
	return router, f
}

func (f *fakeManager) serveHTTP(w http.ResponseWriter, req *http.Request) {
	if req.URL.Host != "127.0.0.1:2222" {
		f.t.Errorf("unexpected request host %s", req.URL.Host)
	}
	token := testRESTToken
	method := http.MethodGet
	if req.URL.Path == "/mcp" {
		token = testMCPToken
		method = http.MethodPost
	}
	if req.Header.Get("Authorization") != "Bearer "+token || req.Method != method {
		f.t.Errorf("wrong authentication or HTTP method for %s", req.URL.Path)
	}
	if f.redirect {
		http.Redirect(w, req, "https://example.com/", http.StatusTemporaryRedirect)
		return
	}
	if f.unsafeLog {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, "private-key-and-router-token-must-not-be-logged")
		return
	}

	status := "disconnected"
	if f.running {
		status = "connected"
	}
	data := func(v any) { _ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": v}) }
	switch req.URL.Path {
	case "/api/tunnels/get":
		if req.URL.Query().Get("id") != testTunnelID {
			f.t.Errorf("wrong tunnel requested")
		}
		data(map[string]any{
			"id": f.id, "name": f.name, "backend": f.backend, "ispInterface": f.route,
			"state": status, "enabled": f.enabled, "defaultRoute": f.defaultRoute,
			"interfaceName": "opkgtun5", "ndmsName": "OpkgTun5",
			"interface": map[string]any{
				"address": "198.51.100.5/32", "mtu": 1280,
				"jc": f.jitter.Jc, "jmin": f.jitter.Jmin, "jmax": f.jitter.Jmax,
				"headerProtectionKey": "forbidden-in-errors", "i1": f.initPacket,
				"s1": 13, "s2": 14, "s3": 15, "s4": 16,
				"h1": "5-20", "h2": "21", "h3": "25-45", "h4": "46-60",
			},
			"peer": map[string]any{"endpoint": f.endpoint, "publicKey": testServerPublicKey, "allowedIPs": []string{"0.0.0.0/0"}},
			"stateInfo": map[string]any{
				"interfaceUp": f.running, "lastHandshake": f.handshake, "rxBytes": f.rx, "txBytes": f.tx,
			},
			"connectivityCheck": map[string]any{"method": f.checkMode},
		})
	case "/api/tunnels/list":
		data([]any{map[string]any{
			"id": f.id, "name": f.name, "status": status, "enabled": f.enabled,
			"defaultRoute": f.defaultRoute, "backend": f.backend, "endpoint": f.endpoint,
			"lastHandshake": f.handshake, "startedAt": f.startedAt, "rxBytes": f.rx, "txBytes": f.tx,
			"interfaceName": "opkgtun5", "ndmsName": "OpkgTun5", "awgVersion": "awg3.1",
			"ispInterface": f.route,
		}})
	case "/api/dns-routes/list", "/api/static-routes/list", "/api/client-routes", "/api/access-policies":
		if f.binding == req.URL.Path {
			data([]any{map[string]any{
				"tunnelId": testTunnelID, "routes": []any{map[string]any{"tunnelId": testTunnelID}},
				"interfaces": []any{map[string]any{"name": "OpkgTun5"}},
			}})
		} else {
			data([]any{})
		}
	case "/mcp":
		f.serveMCP(w, req)
	default:
		f.t.Errorf("unexpected request path %s", req.URL.Path)
		http.NotFound(w, req)
	}
}

func (f *fakeManager) serveMCP(w http.ResponseWriter, req *http.Request) {
	var message struct {
		ID     json.RawMessage
		Method string
		Params struct {
			Name      string
			Arguments map[string]json.RawMessage
		}
	}
	if req.Header.Get("Content-Type") != "application/json" {
		f.t.Errorf("missing MCP content type")
	}
	if err := json.NewDecoder(req.Body).Decode(&message); err != nil {
		f.t.Error(err)
	}
	result := func(v any) {
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": message.ID, "result": v})
	}
	switch message.Method {
	case "initialize":
		result(map[string]any{"protocolVersion": "2025-06-18"})
		return
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
		return
	case "tools/call":
	default:
		f.t.Errorf("unexpected MCP request %s", message.Method)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.calls = append(f.calls, message.Params.Name)
	var target string
	_ = json.Unmarshal(message.Params.Arguments["tunnelId"], &target)
	if target != testTunnelID {
		f.t.Errorf("MCP call hit wrong tunnel")
	}
	switch message.Params.Name {
	case "update_tunnel_settings":
		var patch map[string]int
		_ = json.Unmarshal(message.Params.Arguments["awg"], &patch)
		if len(message.Params.Arguments) != 2 || len(patch) != 3 || f.running {
			f.t.Errorf("unexpected patch fields or tunnel was running")
		}
		f.jitter = issuer.Jitter{Jc: patch["jc"], Jmin: patch["jmin"], Jmax: patch["jmax"]}
	case "control_tunnel":
		var action string
		_ = json.Unmarshal(message.Params.Arguments["action"], &action)
		switch action {
		case "start":
			f.running, f.enabled = true, true
			if f.startedAt.IsZero() {
				f.startedAt = time.Now().UTC().Truncate(time.Second)
			} else {
				f.startedAt = f.startedAt.Add(2 * time.Second)
			}
			f.rx, f.tx = 0, 0
			if !f.staleHandshake {
				f.handshake = time.Time{}
			}
		case "stop":
			f.running, f.enabled = false, false
		default:
			f.t.Errorf("unexpected operation %q", action)
		}
		result(map[string]any{"structuredContent": map[string]any{"tunnelId": testTunnelID, "action": action, "stateKnown": true}})
		return
	case "test_connectivity":
		f.httpProbes++
		if !f.staleHandshake {
			f.handshake = f.startedAt.Add(time.Second)
		}
		if !f.noRx {
			f.rx += 512
		}
		f.tx += 512
		result(map[string]any{"structuredContent": map[string]any{"tunnelId": testTunnelID, "connected": true, "latencyMs": 23}})
		return
	default:
		f.t.Errorf("unexpected MCP tool %s", message.Params.Name)
	}
	result(map[string]any{"structuredContent": map[string]any{"id": testTunnelID}})
}

func TestRouterRunsIsolatedCandidate(t *testing.T) {
	r, f := makeRouter(t)
	ctx := context.Background()
	initial, err := r.Snapshot(ctx)
	if err != nil || initial.Running || initial.Enabled || initial.Jitter != f.jitter ||
		initial.MTU != 1280 || initial.Endpoint != testEndpoint || initial.LocalAddress != "198.51.100.5/32" ||
		initial.ServerPublicKey != testServerPublicKey {
		t.Fatalf("bad initial snapshot: %+v, %v", initial, err)
	}
	candidate := issuer.Jitter{Jc: 7, Jmin: 80, Jmax: 500}
	if err = r.SetJitter(ctx, candidate); err != nil {
		t.Fatal(err)
	}
	if err = r.Start(ctx); err != nil {
		t.Fatal(err)
	}
	result, err := r.Probe(ctx)
	if err != nil || !result.Success || result.Latency != 23*time.Millisecond || f.httpProbes < 2 {
		t.Fatalf("bad measurement: %+v, %v, HTTP probes=%d", result, err, f.httpProbes)
	}
	if err = r.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err = r.SetJitter(ctx, initial.Jitter); err != nil {
		t.Fatal(err)
	}
	final, err := r.Snapshot(ctx)
	if err != nil || final != initial {
		t.Fatalf("rollback differs: %+v, %v", final, err)
	}
	if want := []string{"update_tunnel_settings", "control_tunnel", "test_connectivity", "test_connectivity", "control_tunnel", "update_tunnel_settings"}; !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("wrong tools/order: %v", f.calls)
	}
}

func TestRouterRefusesUnsafeOrMismatchedTunnelBeforeMutation(t *testing.T) {
	for name, edit := range map[string]func(*fakeManager){
		"default route":            func(f *fakeManager) { f.defaultRoute = true },
		"native backend":           func(f *fakeManager) { f.backend = "nativewg" },
		"wrong endpoint":           func(f *fakeManager) { f.endpoint = "203.0.113.11:3478" },
		"wrong name":               func(f *fakeManager) { f.name = "Another tunnel" },
		"wrong id":                 func(f *fakeManager) { f.id = "awg56" },
		"chained route by default": func(f *fakeManager) { f.route = "tunnel:awg57" },
		"handshake health check":   func(f *fakeManager) { f.checkMode = "handshake" },
		"client route":             func(f *fakeManager) { f.binding = "/api/client-routes" },
		"DNS route":                func(f *fakeManager) { f.binding = "/api/dns-routes/list" },
		"static route":             func(f *fakeManager) { f.binding = "/api/static-routes/list" },
		"access policy":            func(f *fakeManager) { f.binding = "/api/access-policies" },
	} {
		t.Run(name, func(t *testing.T) {
			r, f := makeRouter(t)
			edit(f)
			if err := r.Start(context.Background()); err == nil || len(f.calls) != 0 {
				t.Fatalf("unsafe start not refused before MCP mutation: %v, %v", err, f.calls)
			}
		})
	}
}

func TestEngineWithManagerAdapterRestoresEveryTrial(t *testing.T) {
	router, manager := makeRouter(t)
	ctx := context.Background()
	initial, err := router.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	engine := junktune.New(router, filepath.Join(t.TempDir(), "pending.json"))
	result, err := engine.Run(ctx, nil)
	if err != nil || len(result.Attempts) != 4 || result.Best == nil || *result.Best != 0 {
		t.Fatalf("bad result: %+v, %v", result, err)
	}
	for _, attempt := range result.Attempts {
		if attempt.Runs != 3 || attempt.Successes != 3 {
			t.Fatalf("trial was not confirmed: %+v", attempt)
		}
	}
	after, err := router.Snapshot(ctx)
	if err != nil || after != initial || manager.httpProbes != 24 {
		t.Fatalf("unfinished trial or restoration: probes=%d, %v", manager.httpProbes, err)
	}
}

func TestRouterProbeRefusesStaleHandshakeOrOneWayTraffic(t *testing.T) {
	for _, mode := range []string{"stale", "one-way"} {
		t.Run(mode, func(t *testing.T) {
			r, f := makeRouter(t)
			f.staleHandshake, f.noRx = mode == "stale", mode == "one-way"
			f.handshake = time.Now().Add(-time.Minute)
			ctx := context.Background()
			if err := r.Start(ctx); err != nil {
				t.Fatal(err)
			}
			result, err := r.Probe(ctx)
			if err != nil || result.Success {
				t.Fatalf("invalid measurement accepted: %+v, %v", result, err)
			}
		})
	}
}

func TestRouterDoesNotFollowRedirectsOrLogResponseBodies(t *testing.T) {
	r, f := makeRouter(t)
	for _, redirect := range []bool{true, false} {
		f.redirect, f.unsafeLog = redirect, !redirect
		_, err := r.Snapshot(context.Background())
		if err == nil || strings.Contains(err.Error(), "private-key") || strings.Contains(err.Error(), "example.com") ||
			strings.Contains(err.Error(), testMCPToken) || strings.Contains(err.Error(), testRESTToken) {
			t.Fatalf("unexpected diagnostic: %v", err)
		}
	}
}

func TestWireFingerprintIgnoresJunkAndRuntimeButSeesCPS(t *testing.T) {
	r, f := makeRouter(t)
	ctx := context.Background()
	f.initPacket = "<r 48>"
	first, err := r.Snapshot(ctx)
	if err != nil || first.WireFingerprint == ([32]byte{}) {
		t.Fatalf("missing wire fingerprint: %v", err)
	}
	if want := ([5]string{"<r 48>"}); first.Mimicry != want {
		t.Fatalf("CPS projection = %q, want %q", first.Mimicry, want)
	}
	if want := ([4]string{"5-20", "21", "25-45", "46-60"}); first.Headers != want {
		t.Fatalf("header projection = %q, want %q", first.Headers, want)
	}
	if want := ([4]int{13, 14, 15, 16}); first.Padding != want {
		t.Fatalf("padding projection = %v, want %v", first.Padding, want)
	}
	f.jitter = issuer.Jitter{Jc: 6, Jmin: 70, Jmax: 500}
	f.rx, f.tx = 15, 22
	f.handshake = time.Now()
	next, err := r.Snapshot(ctx)
	if err != nil || first.WireFingerprint != next.WireFingerprint {
		t.Fatalf("runtime or junk changed the wire fingerprint: %v", err)
	}
	f.initPacket = "<r 64>"
	next, err = r.Snapshot(ctx)
	if err != nil || first.WireFingerprint == next.WireFingerprint {
		t.Fatalf("CPS change did not alter the wire fingerprint: %v", err)
	}
}
