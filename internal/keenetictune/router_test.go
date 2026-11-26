package keenetictune

import (
	"context"
	"encoding/hex"
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
	handshakeDuringStart bool
	counterLagReads      int
	pendingCounterReads  int
	resolvedRoute        string
	resolveOnProbe       bool
	probeStartSkew       time.Duration
	noRx                 bool
	unsafeLog            bool
	redirect             bool
	startedAt, handshake time.Time
	rx, tx               uint64
	jitter               issuer.Jitter
	cps                  [5]string
	interfaceField       string
	headerProtectionKey  string
	mutatePadding        bool
	restWrites           int
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
		headerProtectionKey: testServerPublicKey,
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
	if req.URL.Path == "/api/tunnels/update" || req.URL.Path == "/panel/tune/obfuscation" {
		method = http.MethodPost
		if req.Header.Get("Content-Type") != "application/json" || req.Header.Get("Mcp-Session-Id") != "" ||
			req.Header.Get("MCP-Protocol-Version") != "" || req.Header.Get("Accept") != "application/json" {
			f.t.Error("unexpected headers on REST write")
		}
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
			"interface": f.interfaceResponse(),
			"peer":      map[string]any{"endpoint": f.endpoint, "publicKey": testServerPublicKey, "allowedIPs": []string{"0.0.0.0/0"}},
			"stateInfo": map[string]any{
				"interfaceUp": f.running, "lastHandshake": f.handshake, "rxBytes": f.rx, "txBytes": f.tx,
			},
			"connectivityCheck": map[string]any{"method": f.checkMode},
		})
	case "/api/tunnels/update", "/panel/tune/obfuscation":
		f.updateObfuscation(req)
		data(map[string]string{"id": f.id})
	case "/api/tunnels/list":
		if f.pendingCounterReads > 0 {
			f.pendingCounterReads--
			if f.pendingCounterReads == 0 {
				f.advanceCounters()
			}
		}
		reportedStart := f.startedAt
		if f.httpProbes > 0 {
			reportedStart = reportedStart.Add(f.probeStartSkew)
		}
		data([]any{map[string]any{
			"id": f.id, "name": f.name, "status": status, "enabled": f.enabled,
			"defaultRoute": f.defaultRoute, "backend": f.backend, "endpoint": f.endpoint,
			"lastHandshake": f.handshake, "startedAt": reportedStart, "rxBytes": f.rx, "txBytes": f.tx,
			"interfaceName": "opkgtun5", "ndmsName": "OpkgTun5", "awgVersion": "awg3.1",
			"ispInterface": f.route, "resolvedIspInterface": f.resolvedRoute,
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
		if f.resolveOnProbe {
			f.resolvedRoute = "WAN"
		}
		if !f.staleHandshake {
			f.handshake = f.startedAt.Add(time.Second)
			if f.handshakeDuringStart {
				f.handshake = f.startedAt.Add(-time.Second)
			}
		}
		if f.counterLagReads > 0 {
			f.pendingCounterReads = f.counterLagReads
		} else {
			f.advanceCounters()
		}
		result(map[string]any{"structuredContent": map[string]any{"tunnelId": testTunnelID, "connected": true, "latencyMs": 23}})
		return
	default:
		f.t.Errorf("unexpected MCP tool %s", message.Params.Name)
	}
	result(map[string]any{"structuredContent": map[string]any{"id": testTunnelID}})
}

func (f *fakeManager) interfaceConfig() map[string]any {
	s4 := 16
	if f.mutatePadding && f.restWrites != 0 {
		s4++
	}
	return map[string]any{
		"privateKey": "", "address": "198.51.100.5/32", "mtu": 1280,
		"dns": "203.0.113.53", "qlen": 512,
		"jc": f.jitter.Jc, "jmin": f.jitter.Jmin, "jmax": f.jitter.Jmax,
		"s1": 13, "s2": 14, "s3": 15, "s4": s4,
		"h1": "5-20", "h2": "21", "h3": "25-45", "h4": "46-60",
		"i1": f.cps[0], "i2": f.cps[1], "i3": f.cps[2], "i4": f.cps[3], "i5": f.cps[4],
		"headerProtectionKey": f.headerProtectionKey, "contentPaddingAddition": "0-90",
		"rekeyAfterTime": "90-100", "rekeyTimeout": "5", "rejectAfterTime": "180",
		"keepaliveTimeout": "25", "maxHandshakeAttempts": "4", "randomTrailers": true, "disableCookies": true,
	}
}

func (f *fakeManager) interfaceResponse() json.RawMessage {
	body, err := json.Marshal(f.interfaceConfig())
	if err != nil {
		f.t.Fatal(err)
	}
	if f.interfaceField != "" {
		body = append(body[:len(body)-1], f.interfaceField...)
	}
	return body
}

func (f *fakeManager) updateObfuscation(req *http.Request) {
	f.t.Helper()
	if req.URL.RawQuery != "id="+testTunnelID {
		f.t.Errorf("wrong REST mutation target")
	}
	var received map[string]any
	if err := json.NewDecoder(req.Body).Decode(&received); err != nil {
		f.t.Fatal(err)
	}
	fields := [...]string{"jc", "jmin", "jmax", "i1", "i2", "i3", "i4", "i5"}
	values := received
	if req.URL.Path == "/api/tunnels/update" {
		var ok bool
		if values, ok = received["interface"].(map[string]any); !ok || len(received) != 1 {
			f.t.Fatal("direct mutation must contain only the interface block")
		}
		original := f.interfaceConfig()
		delete(original, "privateKey")
		for _, key := range fields {
			original[key] = values[key]
		}
		body, _ := json.Marshal(original)
		var comparable map[string]any
		_ = json.Unmarshal(body, &comparable)
		if !reflect.DeepEqual(comparable, values) {
			f.t.Fatal("direct mutation changed non-junk interface values or discarded stable fields")
		}
	} else if len(values) != len(fields) {
		f.t.Fatal("bridge mutation must contain precisely the eight tuning fields")
	}
	for _, key := range fields {
		if _, ok := values[key]; !ok {
			f.t.Fatalf("missing mutable field %s", key)
		}
	}
	f.jitter = issuer.Jitter{Jc: int(values["jc"].(float64)), Jmin: int(values["jmin"].(float64)), Jmax: int(values["jmax"].(float64))}
	for i, key := range fields[3:] {
		f.cps[i] = values[key].(string)
	}
	f.restWrites++
}

func (f *fakeManager) advanceCounters() {
	if !f.noRx {
		f.rx += 512
	}
	f.tx += 512
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

func TestFindJunkRunsAndRestoresCPSOverScopedBridge(t *testing.T) {
	router, manager := makeRouter(t)
	router.config.CPSBridge = true
	manager.headerProtectionKey = strings.Repeat("a", 64)
	manager.cps = [5]string{"<r 25>", "<r 30>"}
	ctx := context.Background()
	initial, err := router.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	result, err := junktune.New(router, filepath.Join(t.TempDir(), "pending.json")).FindJunk(ctx,
		junktune.Options{Profile: "dns", HostPreset: "custom", Domains: "example.com", MaxAttempts: 3}, nil)
	if err != nil || len(result.Attempts) != 2 || result.Attempts[1].Successes != 3 ||
		result.Attempts[1].Domain != "example.com" || result.Attempts[1].CPS[0] == "" {
		t.Fatalf("expected the control and one working DNS candidate: %+v, %v", result, err)
	}
	after, err := router.Snapshot(ctx)
	if err != nil || after != initial || manager.restWrites != 2 || manager.httpProbes != 12 {
		t.Fatalf("both J and CPS should be restored after threshold reached: %v, writes %d, probes %d",
			err, manager.restWrites, manager.httpProbes)
	}
}

func TestRouterAcceptsHandshakeBeforeManagerFinishesStarting(t *testing.T) {
	router, manager := makeRouter(t)
	manager.handshakeDuringStart = true
	manager.handshake = time.Now().Add(-time.Minute)
	ctx := context.Background()
	if err := router.Start(ctx); err != nil {
		t.Fatal(err)
	}
	result, err := router.Probe(ctx)
	if err != nil || !result.Success {
		t.Fatalf("manager's start timestamp hid a fresh handshake: %+v, %v", result, err)
	}
}

func TestRouterWaitsForCountersAndWANResolution(t *testing.T) {
	for _, name := range []string{"cached counters", "WAN resolves after start"} {
		t.Run(name, func(t *testing.T) {
			router, manager := makeRouter(t)
			if name == "cached counters" {
				manager.counterLagReads = 2
			} else {
				manager.resolveOnProbe = true
			}
			ctx := context.Background()
			if err := router.Start(ctx); err != nil {
				t.Fatal(err)
			}
			result, err := router.Probe(ctx)
			if err != nil || !result.Success || manager.httpProbes != 2 {
				t.Fatalf("fresh traffic not confirmed: %+v, %v, probes=%d", result, err, manager.httpProbes)
			}
		})
	}
}

func TestRouterDistinguishesUptimeRoundingFromNewStart(t *testing.T) {
	for _, tc := range []struct {
		name string
		skew time.Duration
		want bool
	}{
		{"one second of rounding", time.Second, true},
		{"different start", 10 * time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			router, manager := makeRouter(t)
			manager.probeStartSkew = tc.skew
			ctx := context.Background()
			if err := router.Start(ctx); err != nil {
				t.Fatal(err)
			}
			result, err := router.Probe(ctx)
			if err != nil || result.Success != tc.want {
				t.Fatalf("unexpected verdict with start time difference %v: %+v, %v", tc.skew, result, err)
			}
		})
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

func TestWireFingerprintIgnoresTunableFieldsButLegacySeesCPS(t *testing.T) {
	r, f := makeRouter(t)
	ctx := context.Background()
	f.cps[0] = "<r 48>"
	first, err := r.Snapshot(ctx)
	if err != nil || first.WireFingerprint == ([32]byte{}) || first.LegacyWireFingerprint == ([32]byte{}) {
		t.Fatalf("missing wire fingerprint: %v", err)
	}
	const legacy = "528582e6977ebdb1888dd5d979a2979b76aab5bf891563d5ba6ebfebade5c28b"
	if hex.EncodeToString(first.LegacyWireFingerprint[:]) != legacy {
		t.Fatal("legacy fingerprint must match the installed journal format")
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
	if err != nil || first.WireFingerprint != next.WireFingerprint || first.LegacyWireFingerprint != next.LegacyWireFingerprint {
		t.Fatalf("runtime or junk changed the wire fingerprint: %v", err)
	}
	f.cps[0] = "<r 64>"
	next, err = r.Snapshot(ctx)
	if err != nil || first.WireFingerprint != next.WireFingerprint || first.LegacyWireFingerprint == next.LegacyWireFingerprint {
		t.Fatalf("CPS change must affect only the legacy fingerprint: %v", err)
	}
}

func TestSetObfuscationPostsOnlyExpectedChangesAndClearsCPS(t *testing.T) {
	for _, bridge := range []bool{false, true} {
		name := "direct"
		if bridge {
			name = "bridge"
		}
		t.Run(name, func(t *testing.T) {
			r, f := makeRouter(t)
			r.config.CPSBridge = bridge
			r.protocol, r.session = "2025-06-18", "active-mcp-session"
			if bridge {
				f.headerProtectionKey = strings.Repeat("a", 64)
			}
			f.cps = [5]string{"<r 48>", "<r 32>", "<r 24>"}
			f.route = "wan:ppp0"
			want := junktune.Parameters{
				Jitter: issuer.Jitter{Jc: 7, Jmin: 90, Jmax: 700},
				CPS:    [5]string{"<r 64>", "", "<r 30>", "<r 45>", "<r 60>"},
			}
			if err := r.SetObfuscation(context.Background(), want); err != nil {
				t.Fatal(err)
			}
			if f.restWrites != 1 || len(f.calls) != 0 || f.jitter != want.Jitter || f.cps != want.CPS ||
				f.route != "wan:ppp0" || f.defaultRoute || f.running || f.enabled {
				t.Fatal("unexpected adapter side effects or missing CPS clear")
			}
			if err := r.SetObfuscation(context.Background(), want); err != nil || f.restWrites != 1 {
				t.Fatalf("identical state should be a no-op: %v", err)
			}
			want.CPS = [5]string{}
			if err := r.SetObfuscation(context.Background(), want); err != nil || f.cps != want.CPS || f.restWrites != 2 {
				t.Fatalf("all CPS slots must be cleared explicitly: %v", err)
			}
		})
	}
}

func TestSetObfuscationRefusesUnsafeReplayAndVerifiesPostcondition(t *testing.T) {
	want := junktune.Parameters{Jitter: issuer.Jitter{Jc: 7, Jmin: 90, Jmax: 700}, CPS: [5]string{"<r 64>"}}
	for _, test := range []struct {
		name  string
		setup func(*fakeManager)
		wrote int
	}{
		{"duplicate-key", func(f *fakeManager) { f.interfaceField = `,"h1":"5-20"}` }, 0},
		{"noncanonical-key", func(f *fakeManager) { f.interfaceField = `,"H1":"5-20"}` }, 0},
		{"unknown-key", func(f *fakeManager) { f.interfaceField = `,"newAwgField":1}` }, 0},
		{"redacted-hpk", func(f *fakeManager) { f.headerProtectionKey = strings.Repeat("a", 64) }, 0},
		{"active", func(f *fakeManager) { f.running, f.enabled = true, true }, 0},
		{"other-interface-field-changed", func(f *fakeManager) { f.mutatePadding = true }, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			r, f := makeRouter(t)
			test.setup(f)
			err := r.SetObfuscation(context.Background(), want)
			if err == nil || f.restWrites != test.wrote || strings.Contains(err.Error(), f.headerProtectionKey) {
				t.Fatalf("should refuse unsafe mutation without reflecting profile details: %v, writes %d", err, f.restWrites)
			}
		})
	}
}

func TestProbeRefusesCPSChangeDuringTrial(t *testing.T) {
	r, f := makeRouter(t)
	if err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.cps[0] = "<r 42>"
	got, err := r.Probe(context.Background())
	if err != nil || got.Success || f.httpProbes != 0 {
		t.Fatalf("probe accepted changed CPS: %+v %v", got, err)
	}
}
