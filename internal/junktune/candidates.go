package junktune

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"

	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/warpsignature"
)

const (
	defaultFindJunkAttempts  = 10
	maxFindJunkAttempts      = 30
	defaultFindJunkThreshold = 95
	minFindJunkThreshold     = 50
	maxFindJunkThreshold     = 100

	// AWG Manager v2.20.6, internal/warpscout/findjunk.go.
	junkCountMin = 4
	junkCountMax = 6
	junkSizeMin  = 10
	junkSizeMax  = 50
	junkSpanMin  = 20
	junkSpanMax  = 100

	// Allow for a UDP header and up to a full IPv6 base header. Use the same
	// conservative bound for DNS endpoints because they can resolve to either IP family.
	udpIPOverhead     = 8 + 40
	maxCandidateDraws = 64
)

var errCPSExceedsMTU = errors.New("пакет CPS не помещается в MTU")

type Parameters struct {
	Jitter issuer.Jitter `json:"jitter"`
	CPS    [5]string     `json:"cps"`
}

type Candidate struct {
	Parameters
	Profile string `json:"profile,omitempty"`
	Domain  string `json:"domain,omitempty"`
}

type Options struct {
	Profile      string `json:"profile"`
	HostPreset   string `json:"host_preset,omitempty"`
	Domains      string `json:"domains,omitempty"`
	MaxAttempts  int    `json:"max_attempts,omitempty"`
	ThresholdPct int    `json:"threshold_pct,omitempty"`
	AutoApply    bool   `json:"auto_apply,omitempty"`
}

// NormalizeOptions validates protocol and domain input and supplies bounded
// defaults for the number of generated candidates and the success threshold.
func NormalizeOptions(opts Options) (Options, error) {
	profile, host, err := warpsignature.Normalize(opts.Profile, warpsignature.GenerateOptions{
		Domain: opts.Domains, HostPreset: opts.HostPreset,
	})
	if err != nil {
		return Options{}, fmt.Errorf("%w: параметры мимикрии: %w", issuer.ErrInvalidInput, err)
	}
	opts.Profile, opts.HostPreset = profile, host.HostPreset
	opts.Domains = strings.Join(host.Domains, ", ")
	if opts.MaxAttempts <= 0 {
		opts.MaxAttempts = defaultFindJunkAttempts
	}
	opts.MaxAttempts = min(opts.MaxAttempts, maxFindJunkAttempts)
	if opts.ThresholdPct <= 0 {
		opts.ThresholdPct = defaultFindJunkThreshold
	}
	opts.ThresholdPct = min(max(opts.ThresholdPct, minFindJunkThreshold), maxFindJunkThreshold)
	return opts, nil
}

func generateFindJunkCandidates(opts Options, initial Snapshot) ([]Candidate, error) {
	opts, err := NormalizeOptions(opts)
	if err != nil {
		return nil, err
	}
	candidates := make([]Candidate, 1, opts.MaxAttempts+1)
	candidates[0] = Candidate{
		Parameters: Parameters{Jitter: initial.Jitter, CPS: initial.Mimicry},
		Profile:    "current",
	}
	seen := map[Parameters]bool{candidates[0].Parameters: true}
	pool := candidateDomains(opts)
	for range opts.MaxAttempts {
		var domain string
		if len(pool) > 0 {
			domain = pool[(len(candidates)-1)%len(pool)]
		}
		var added bool
		for range maxCandidateDraws {
			candidate, err := generateFindJunkCandidate(opts.Profile, domain, initial.MTU)
			if errors.Is(err, errCPSExceedsMTU) && opts.Profile == warpsignature.ProfileRandom {
				continue
			}
			if err != nil {
				return nil, err
			}
			if seen[candidate.Parameters] {
				continue
			}
			candidates = append(candidates, candidate)
			seen[candidate.Parameters] = true
			added = true
			break
		}
		if !added {
			return nil, fmt.Errorf("%w: не удалось получить разные варианты для данного MTU", issuer.ErrInvalidInput)
		}
	}
	return candidates, nil
}

func candidateDomains(opts Options) []string {
	if opts.Domains != "" {
		return strings.Split(opts.Domains, ", ")
	}
	if opts.HostPreset == warpsignature.HostPresetRU || opts.HostPreset == warpsignature.HostPresetCDN {
		pool, _ := warpsignature.PresetDomains(opts.HostPreset)
		rand.Shuffle(len(pool), func(i, j int) { pool[i], pool[j] = pool[j], pool[i] })
		return pool
	}
	return nil
}

func generateFindJunkCandidate(profile, domain string, mtu int) (Candidate, error) {
	size := junkSizeMin + rand.IntN(junkSizeMax-junkSizeMin+1)
	jitter := issuer.Jitter{
		Jc:   junkCountMin + rand.IntN(junkCountMax-junkCountMin+1),
		Jmin: size,
		Jmax: size + junkSpanMin + rand.IntN(junkSpanMax-junkSpanMin+1),
	}
	if err := validateJitter(jitter, mtu); err != nil {
		return Candidate{}, err
	}
	signature, err := warpsignature.GenerateWithOptions(profile, warpsignature.GenerateOptions{Domain: domain})
	if err != nil {
		return Candidate{}, err
	}
	packets := signature.Packets
	candidate := Candidate{
		Parameters: Parameters{Jitter: jitter, CPS: [5]string{packets.I1, packets.I2, packets.I3, packets.I4, packets.I5}},
		Profile:    signature.Profile,
		Domain:     signature.Domain,
	}
	if err := validateCandidateCPS(candidate.CPS, mtu); err != nil {
		return Candidate{}, err
	}
	return candidate, nil
}

func validateCandidateCPS(cps [5]string, mtu int) error {
	extra := make(map[string]string, len(cps))
	for index, packet := range cps {
		if packet != "" {
			extra[fmt.Sprintf("I%d", index+1)] = packet
		}
	}
	if err := issuer.ValidateExtra(extra); err != nil {
		return err
	}
	for index, packet := range cps {
		if packet != "" && warpsignature.ByteSize(packet)+udpIPOverhead > mtu {
			return fmt.Errorf("%w: I%d: %w (%d)", issuer.ErrInvalidInput, index+1, errCPSExceedsMTU, mtu)
		}
	}
	return nil
}
