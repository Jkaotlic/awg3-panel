package issuer

import (
	"context"
	"errors"
	"fmt"
	"maps"

	"github.com/Jkaotlic/awg3-panel/internal/store"
)

// PreviewMeasuredObfuscation exports the checked peer with the measured
// client parameters. A nil CPS keeps the existing packets. The check receives
// the current rendered profile under the service mutex.
func (s *Service) PreviewMeasuredObfuscation(id string, jitter Jitter, cps *[5]string, check func(string) error) (string, string, error) {
	if check == nil {
		return "", "", fmt.Errorf("%w: требуется проверка измеренного профиля", ErrInvalidInput)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	peer, current, err := s.clientParamsFor(id)
	if err != nil {
		return "", "", err
	}
	if !peer.Enabled {
		return "", "", fmt.Errorf("%w: тестовый пир выключен", ErrStateConflict)
	}
	if err := validateEffectiveJitter(jitter.Jc, jitter.Jmin, jitter.Jmax, current.MTU); err != nil {
		return "", "", err
	}
	if err := validateCPSOverride(cps); err != nil {
		return "", "", fmt.Errorf("%w: некорректные параметры мимикрии", ErrInvalidInput)
	}
	baseline, err := RenderClientConfig(current)
	if err != nil {
		return "", "", fmt.Errorf("%w: текущий профиль пира не прошёл проверку", ErrStateConflict)
	}
	if err := check(baseline); err != nil {
		switch {
		case errors.Is(err, context.Canceled):
			return "", "", context.Canceled
		case errors.Is(err, context.DeadlineExceeded):
			return "", "", context.DeadlineExceeded
		default:
			return "", "", fmt.Errorf("%w: не удалось подтвердить измеренный профиль. Запустите подбор заново", ErrStateConflict)
		}
	}
	candidate := current
	candidate.Jc, candidate.Jmin, candidate.Jmax = jitter.Jc, jitter.Jmin, jitter.Jmax
	if cps != nil {
		candidate.Extra = maps.Clone(current.Extra)
		replaceCPS(candidate.Extra, *cps)
	}
	body, err := RenderClientConfig(candidate)
	if err != nil {
		return "", "", fmt.Errorf("%w: конфиг с измеренными параметрами не прошёл проверку", ErrInvalidInput)
	}
	return store.Slug(peer.Name) + "-measured.conf", body, nil
}
