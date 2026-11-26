package keenetictune

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/junktune"
)

func (r *Router) SetObfuscation(ctx context.Context, params junktune.Parameters) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	current, err := r.inspect(ctx)
	if err != nil {
		return err
	}
	if current.snapshot.Running || current.snapshot.Enabled || !inactiveState(current.details.State) {
		return errors.New("изменение обфускации допускается на остановленном тестовом туннеле")
	}
	if current.snapshot.Jitter == params.Jitter && current.snapshot.Mimicry == params.CPS {
		return nil
	}
	if !validJitter(params.Jitter, current.snapshot.MTU) || !validJitter(current.snapshot.Jitter, current.snapshot.MTU) ||
		!validCPS(params.CPS) || !validCPS(current.snapshot.Mimicry) {
		return errors.New("исходные или запрошенные параметры обфускации не прошли проверку")
	}

	wire := current.details.Interface.wireInterface.withCPS(params.CPS)
	legacyFingerprint, err := current.details.wireFingerprint(wire)
	if err != nil {
		return err
	}
	if err := r.updateObfuscation(ctx, params, current.details.Interface.replaySafe, wire); err != nil {
		return err
	}
	after, err := r.observe(ctx)
	if err != nil {
		return err
	}
	expected := current.snapshot
	expected.Jitter, expected.Mimicry, expected.LegacyWireFingerprint = params.Jitter, params.CPS, legacyFingerprint
	if after.snapshot != expected || !inactiveState(after.details.State) {
		return errors.New("AWG Manager не подтвердил изменение только параметров обфускации")
	}
	return nil
}

func (r *Router) updateObfuscation(ctx context.Context, params junktune.Parameters, replaySafe bool, wire wireInterface) error {
	path := "/api/tunnels/update"
	var payload any
	if r.config.CPSBridge {
		path = "/panel/tune/obfuscation"
		payload = struct {
			issuer.Jitter
			I1 string `json:"i1"`
			I2 string `json:"i2"`
			I3 string `json:"i3"`
			I4 string `json:"i4"`
			I5 string `json:"i5"`
		}{Jitter: params.Jitter, I1: wire.I1, I2: wire.I2, I3: wire.I3, I4: wire.I4, I5: wire.I5}
	} else {
		if !replaySafe {
			return errors.New("ответ AWG Manager не позволяет безопасно сохранить исходные поля интерфейса")
		}
		payload = struct {
			Interface interfaceSettings `json:"interface"`
		}{Interface: interfaceSettings{Jitter: params.Jitter, wireInterface: wire}}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return errors.New("не удалось подготовить параметры обфускации для AWG Manager")
	}
	var updated struct {
		ID string `json:"id"`
	}
	query := url.Values{"id": {r.config.TunnelID}}
	if err := r.restRequest(ctx, http.MethodPost, path, query, body, &updated); err != nil {
		return err
	}
	if updated.ID != r.config.TunnelID {
		return errors.New("AWG Manager не подтвердил цель изменения обфускации")
	}
	return nil
}

func validCPS(cps [5]string) bool {
	keys := [...]string{"I1", "I2", "I3", "I4", "I5"}
	fields := make(map[string]string, len(keys))
	for index, packet := range cps {
		if packet != "" {
			fields[keys[index]] = packet
		}
	}
	return issuer.ValidateExtra(fields) == nil
}
