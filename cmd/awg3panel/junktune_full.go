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
	})
	if err != nil {
		return fmt.Errorf("проверьте параметры AWG3PANEL_TUNE_URL, _TUNNEL, _TUNNEL_NAME, _ENDPOINT и _ROUTE")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("не удалось открыть каталог журнала автоподбора")
	}
	engine := junktune.New(router, filepath.Join(stateDir, "keenetic-junktune.json"))
	server.EnableJunkTune(ifaceID, peerID, engine, func(ctx context.Context) ([32]byte, error) {
		peers, err := svc.List()
		if err != nil {
			return [32]byte{}, err
		}
		for _, peer := range peers {
			if peer.ID == peerID && peer.Enabled {
				_, profile, err := svc.ConfigFor(peerID)
				if err != nil {
					return [32]byte{}, err
				}
				actual, err := router.Snapshot(ctx)
				if err != nil {
					return [32]byte{}, err
				}
				return tuneFingerprint(profile, actual)
			}
		}
		return [32]byte{}, issuer.ErrNotFound
	}, func(ctx context.Context, jitter issuer.Jitter, expected [32]byte) error {
		actual, err := router.Snapshot(ctx)
		if err != nil || actual.Running || actual.Enabled {
			return fmt.Errorf("%w: AWG Manager не подтвердил исходное состояние тестового туннеля", issuer.ErrStateConflict)
		}
		return svc.UpdateJitterIfProfile(peerID, jitter, func(profile string) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			got, err := tuneFingerprint(profile, actual)
			if err != nil || got != expected {
				return fmt.Errorf("%w: конфигурация тестового пира изменилась. Запустите подбор заново", issuer.ErrStateConflict)
			}
			return nil
		})
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

func tuneFingerprint(profile string, actual junktune.Snapshot) ([32]byte, error) {
	c, err := wgconf.Parse(profile)
	if err != nil || len(c.Peers) != 1 {
		return [32]byte{}, fmt.Errorf("некорректный тестовый профиль панели")
	}
	peer := c.Peers[0]
	if !sameTuneEndpoint(peer.Get("Endpoint"), actual.Endpoint) ||
		peer.Get("PublicKey") != actual.ServerPublicKey ||
		!sameTuneAddress(c.Interface.Get("Address"), actual.LocalAddress) {
		return [32]byte{}, fmt.Errorf("тестовый туннель не соответствует пиру панели")
	}
	if mtu, err := strconv.Atoi(c.Interface.Get("MTU")); err == nil && mtu != actual.MTU {
		return [32]byte{}, fmt.Errorf("MTU тестового туннеля отличается от профиля пира")
	}
	for i, key := range [...]string{"I1", "I2", "I3", "I4", "I5"} {
		if strings.TrimSpace(c.Interface.Get(key)) != strings.TrimSpace(actual.Mimicry[i]) {
			return [32]byte{}, fmt.Errorf("мимикрия тестового туннеля отличается от профиля пира")
		}
	}
	for i, keys := range [...][2]string{{"H1", "S1"}, {"H2", "S2"}, {"H3", "S3"}, {"H4", "S4"}} {
		padding, err := strconv.Atoi(c.Interface.Get(keys[1]))
		if err != nil || actual.Padding[i] != padding || actual.Headers[i] != c.Interface.Get(keys[0]) {
			return [32]byte{}, fmt.Errorf("поля H/S тестового туннеля отличаются от профиля пира")
		}
	}

	var body strings.Builder
	for _, line := range strings.Split(profile, "\n") {
		key, _, _ := strings.Cut(line, "=")
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "jc", "jmin", "jmax":
			continue
		}
		body.WriteString(line)
		body.WriteByte('\n')
	}
	profileHash := sha256.Sum256([]byte(body.String()))
	return sha256.Sum256(append(profileHash[:], actual.WireFingerprint[:]...)), nil
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
