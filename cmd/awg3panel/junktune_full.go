//go:build !readonly

package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/junktune"
	"github.com/Jkaotlic/awg3-panel/internal/keenetictune"
	"github.com/Jkaotlic/awg3-panel/internal/web"
	"github.com/Jkaotlic/awg3-panel/internal/wgconf"
)

func configureJunkTune(server *web.Server, cfg *config.Config, reg *issuer.Registry) error {
	baseURL := os.Getenv("AWG3PANEL_TUNE_URL")
	if baseURL == "" {
		return nil
	}
	ifaceID := os.Getenv("AWG3PANEL_TUNE_IFACE")
	peerID := os.Getenv("AWG3PANEL_TUNE_PEER")
	if peerID == "" {
		return fmt.Errorf("укажите AWG3PANEL_TUNE_PEER")
	}
	var stateDir string
	for _, iface := range cfg.Interfaces {
		if iface.ID == ifaceID {
			stateDir = iface.StateDir()
			break
		}
	}
	if stateDir == "" {
		return fmt.Errorf("AWG3PANEL_TUNE_IFACE не соответствует интерфейсу панели")
	}
	svc, ok := reg.Mutator(ifaceID)
	if !ok {
		return fmt.Errorf("тестовый интерфейс панели недоступен")
	}
	restToken, err := readTuneToken("AWG3PANEL_TUNE_REST_TOKEN_FILE")
	if err != nil {
		return err
	}
	mcpToken, err := readTuneToken("AWG3PANEL_TUNE_MCP_TOKEN_FILE")
	if err != nil {
		return err
	}
	router, err := keenetictune.New(keenetictune.Config{
		BaseURL:          baseURL,
		RESTToken:        restToken,
		MCPToken:         mcpToken,
		TunnelID:         os.Getenv("AWG3PANEL_TUNE_TUNNEL"),
		ExpectedName:     os.Getenv("AWG3PANEL_TUNE_TUNNEL_NAME"),
		ExpectedEndpoint: os.Getenv("AWG3PANEL_TUNE_ENDPOINT"),
		ExpectedRoute:    os.Getenv("AWG3PANEL_TUNE_ROUTE"),
		CPSBridge:        os.Getenv("AWG3PANEL_TUNE_CPS_BRIDGE") == "1",
	})
	if err != nil {
		return fmt.Errorf("проверьте параметры AWG3PANEL_TUNE_URL, _TUNNEL, _TUNNEL_NAME, _ENDPOINT и _ROUTE")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("не удалось открыть каталог журнала автоподбора")
	}
	engine := junktune.New(router, filepath.Join(stateDir, "keenetic-junktune.json"))
	checkSelected := func(ctx context.Context, full bool, expected web.JunkTuneProfile) (func(string) error, error) {
		actual, err := router.Snapshot(ctx)
		if err != nil || actual.Running || actual.Enabled {
			return nil, fmt.Errorf("%w: AWG Manager не подтвердил исходное состояние тестового туннеля", issuer.ErrStateConflict)
		}
		return func(profile string) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			got, err := tuneProfileVersion(profile, actual, full)
			if err != nil || got != expected {
				return fmt.Errorf("%w: конфигурация тестового пира изменилась. Запустите подбор заново", issuer.ErrStateConflict)
			}
			return nil
		}, nil
	}
	server.EnableJunkTune(ifaceID, peerID, engine, func(ctx context.Context, full bool) (web.JunkTuneProfile, error) {
		peers, err := svc.List()
		if err != nil {
			return web.JunkTuneProfile{}, err
		}
		for _, peer := range peers {
			if peer.ID == peerID && peer.Enabled {
				_, profile, err := svc.ConfigFor(peerID)
				if err != nil {
					return web.JunkTuneProfile{}, err
				}
				actual, err := router.Snapshot(ctx)
				if err != nil {
					return web.JunkTuneProfile{}, err
				}
				return tuneProfileVersion(profile, actual, full)
			}
		}
		return web.JunkTuneProfile{}, issuer.ErrNotFound
	}, func(ctx context.Context, parameters junktune.Parameters, full bool, expected web.JunkTuneProfile) error {
		check, err := checkSelected(ctx, full, expected)
		if err != nil {
			return err
		}
		if full {
			return svc.UpdateObfuscationIfProfile(peerID, parameters.Jitter, parameters.CPS, check)
		}
		return svc.UpdateJitterIfProfile(peerID, parameters.Jitter, check)
	}, func(ctx context.Context, parameters junktune.Parameters, full bool, expected web.JunkTuneProfile) (string, string, error) {
		check, err := checkSelected(ctx, full, expected)
		if err != nil {
			return "", "", err
		}
		var cps *[5]string
		if full {
			cps = &parameters.CPS
		}
		return svc.PreviewMeasuredObfuscation(peerID, parameters.Jitter, cps, check)
	})
	return nil
}

func readTuneToken(variable string) (string, error) {
	f, err := os.Open(os.Getenv(variable))
	if err != nil {
		return "", fmt.Errorf("не удалось открыть %s", variable)
	}
	defer f.Close()
	value, err := io.ReadAll(io.LimitReader(f, 4097))
	token := strings.TrimSpace(string(value))
	if err != nil || len(value) > 4096 || token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", fmt.Errorf("некорректный ключ в %s", variable)
	}
	return token, nil
}

// For a full search, the measured CPS comes from the fixed test tunnel, and
// saving a measurement may replace the stored peer's CPS independently.
func tuneProfileVersion(profile string, actual junktune.Snapshot, changesCPS bool) (web.JunkTuneProfile, error) {
	c, err := wgconf.Parse(profile)
	if err != nil || len(c.Peers) != 1 {
		return web.JunkTuneProfile{}, fmt.Errorf("некорректный тестовый профиль панели")
	}
	peer := c.Peers[0]
	if !sameTuneEndpoint(peer.Get("Endpoint"), actual.Endpoint) ||
		peer.Get("PublicKey") != actual.ServerPublicKey ||
		!sameTuneAddress(c.Interface.Get("Address"), actual.LocalAddress) {
		return web.JunkTuneProfile{}, fmt.Errorf("тестовый туннель не соответствует пиру панели")
	}
	if mtu, err := strconv.Atoi(c.Interface.Get("MTU")); err == nil && mtu != actual.MTU {
		return web.JunkTuneProfile{}, fmt.Errorf("MTU тестового туннеля отличается от профиля пира")
	}
	var values junktune.Parameters
	jitterFields := [...]struct {
		key   string
		value *int
	}{
		{"Jc", &values.Jitter.Jc}, {"Jmin", &values.Jitter.Jmin}, {"Jmax", &values.Jitter.Jmax},
	}
	for _, field := range jitterFields {
		if value := c.Interface.Get(field.key); value != "" {
			number, err := strconv.Atoi(value)
			if err != nil {
				return web.JunkTuneProfile{}, fmt.Errorf("некорректный параметр %s тестового пира", field.key)
			}
			*field.value = number
		}
	}
	for i, key := range [...]string{"I1", "I2", "I3", "I4", "I5"} {
		values.CPS[i] = strings.TrimSpace(c.Interface.Get(key))
		if !changesCPS && values.CPS[i] != strings.TrimSpace(actual.Mimicry[i]) {
			return web.JunkTuneProfile{}, fmt.Errorf("мимикрия тестового туннеля отличается от профиля пира")
		}
	}
	for i, keys := range [...][2]string{{"H1", "S1"}, {"H2", "S2"}, {"H3", "S3"}, {"H4", "S4"}} {
		padding, err := strconv.Atoi(c.Interface.Get(keys[1]))
		if err != nil || actual.Padding[i] != padding || actual.Headers[i] != c.Interface.Get(keys[0]) {
			return web.JunkTuneProfile{}, fmt.Errorf("поля H/S тестового туннеля отличаются от профиля пира")
		}
	}

	var body strings.Builder
	for _, line := range strings.Split(profile, "\n") {
		key, _, _ := strings.Cut(line, "=")
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "jc", "jmin", "jmax":
			continue
		case "i1", "i2", "i3", "i4", "i5":
			if changesCPS {
				continue
			}
		}
		body.WriteString(line)
		body.WriteByte('\n')
	}
	profileHash := sha256.Sum256([]byte(body.String()))
	return web.JunkTuneProfile{
		Fingerprint: sha256.Sum256(append(profileHash[:], actual.WireFingerprint[:]...)),
		Parameters:  values,
	}, nil
}

func sameTuneEndpoint(left, right string) bool {
	lh, lp, err := net.SplitHostPort(left)
	rh, rp, otherErr := net.SplitHostPort(right)
	return err == nil && otherErr == nil && lp == rp && strings.EqualFold(lh, rh)
}

func sameTuneAddress(left, right string) bool {
	l, err := netip.ParsePrefix(strings.TrimSpace(left))
	r, otherErr := netip.ParsePrefix(strings.TrimSpace(right))
	return err == nil && otherErr == nil && l.Addr() == r.Addr()
}
